/**
 * sbobctl verify — consumer-side registry-entry verification (offline
 * byte-binding + optional cosign keyless identity pin).
 *
 * The guarantee under test is the fail-closed contract that would have
 * caught SBOB-Forge v1.5.39 defect A in production: a Rekor bundle whose
 * hash does not equal the sha256 of the shipped entry bytes must never
 * pass, whatever the signature itself says. Also pinned here: the
 * production encoding gotcha (publish lane emits UTF-16LE bundles) and
 * the cosign-unavailable fail-loud behavior.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  GITHUB_ACTIONS_OIDC_ISSUER,
  extractRekorSha256,
  normalizeVerifyOptions,
  readTextAnyEncoding,
  verifyEntry,
} from "../src/verify.ts";
import { SbobError } from "../src/errors.ts";

const ROOT = new URL("..", import.meta.url).pathname;
const REDIS = join(ROOT, "sbobs", "redis.yaml");
const CLI = join(ROOT, "src", "cli.ts");

function hasCosign(): boolean {
  return spawnSync("cosign", ["version"]).status === 0;
}

function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Builds a well-formed cosign-style Rekor bundle for the given artifact
 *  bytes: the hashedrekord body commits sha256(bytes) exactly like the
 *  real publish lane does after the convert-before-sign fix (v1.5.40+). */
function makeBundleJson(bytes: Buffer): string {
  const body = {
    apiVersion: "v0.0.1",
    kind: "hashedrekord",
    body: {
      hashedrekord: {
        data: { hash: { algorithm: "sha256", value: sha256(bytes) } },
        signature: { content: Buffer.from("fakesig").toString("base64") },
      },
    },
  };
  return JSON.stringify({
    base64Signature: Buffer.from("fakesig").toString("base64"),
    rekorBundle: {
      SignedEntryTimestamp: Buffer.from("tset").toString("base64"),
      Payload: {
        body: Buffer.from(JSON.stringify(body)).toString("base64"),
        integratedTime: 1730000000,
        logID: "cf9798328dfba7fd9d33b75e3739e1b75e2ba46f9371d3fea3b7f37c53f2a377",
        logIndex: 1,
      },
    },
  });
}

interface Fixture {
  dir: string;
  entry: string;
  setBundle(bytes: Buffer, encoding?: "utf8" | "utf16le"): void;
  cleanup(): void;
}

function makeFixture(): Fixture {
  const dir = mkdtempSync(join(tmpdir(), "sbob-verify-"));
  const entry = join(dir, "redis.yaml");
  copyFileSync(REDIS, entry);
  const fix: Fixture = {
    dir,
    entry,
    setBundle(bytes: Buffer, encoding: "utf8" | "utf16le" = "utf8") {
      const json = makeBundleJson(bytes);
      if (encoding === "utf16le") {
        // UTF-16LE with BOM — what the publish lane emitted on windows runners.
        writeFileSync(entry + ".bundle", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(json, "utf16le")]));
      } else {
        writeFileSync(entry + ".bundle", json, "utf8");
      }
    },
    cleanup() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
  // a detached signature file must exist for the fixture to be complete
  writeFileSync(entry + ".sig", Buffer.from("fakesig").toString("base64"));
  fix.setBundle(readFileSync(entry));
  return fix;
}

// ---------------------------------------------------------------------------
// offline byte-binding (stage 1)
// ---------------------------------------------------------------------------

test("verifyEntry passes when the bundle commits the shipped bytes (utf8 bundle)", async () => {
  const fix = makeFixture();
  try {
    const report = await verifyEntry(fix.entry, {});
    assert.equal(report.ok, true);
    assert.equal(report.byteBindingVerified, true);
    assert.equal(report.identityVerified, false);
    assert.equal(report.entrySha256, sha256(readFileSync(fix.entry)));
    assert.equal(report.rekorSha256, report.entrySha256);
  } finally {
    fix.cleanup();
  }
});

test("verifyEntry parses UTF-16LE bundles (publish-lane encoding, production 2026-11-05)", async () => {
  const fix = makeFixture();
  try {
    fix.setBundle(readFileSync(fix.entry), "utf16le");
    const report = await verifyEntry(fix.entry, {});
    assert.equal(report.ok, true);
    assert.equal(report.rekorSha256, report.entrySha256);
  } finally {
    fix.cleanup();
  }
});

test("readTextAnyEncoding decodes UTF-16LE BOM and strips UTF-8 BOM", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbob-enc-"));
  try {
    const p16 = join(dir, "b16.json");
    writeFileSync(p16, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"a":"æ"}', "utf16le")]));
    assert.equal(readTextAnyEncoding(p16), '{"a":"æ"}');
    const p8 = join(dir, "b8.json");
    writeFileSync(p8, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":"b"}')]));
    assert.equal(readTextAnyEncoding(p8), '{"a":"b"}');
    const plain = join(dir, "plain.json");
    writeFileSync(plain, '{"a":"b"}');
    assert.equal(readTextAnyEncoding(plain), '{"a":"b"}');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verifyEntry fails closed when the shipped bytes were tampered with (hash mismatch)", async () => {
  const fix = makeFixture();
  try {
    writeFileSync(fix.entry, readFileSync(fix.entry) + "\n# tampered\n");
    await assert.rejects(
      verifyEntry(fix.entry, {}),
      (e: unknown) => {
        assert.ok(e instanceof SbobError);
        assert.equal((e as SbobError).code, "ERR_VERIFY_HASH_MISMATCH");
        assert.match((e as SbobError).message, /signed bytes are not the shipped bytes/);
        return true;
      },
    );
  } finally {
    fix.cleanup();
  }
});

test("verifyEntry fails closed when the signature binds pre-convert bytes (v1.5.39 defect A regression)", async () => {
  const fix = makeFixture();
  try {
    // bundle commits OTHER bytes (e.g. the pre-convert kubescape dialect)
    fix.setBundle(Buffer.from("different-bytes-signed-not-shipped"));
    await assert.rejects(
      verifyEntry(fix.entry, {}),
      (e: unknown) => {
        assert.ok(e instanceof SbobError);
        assert.equal((e as SbobError).code, "ERR_VERIFY_HASH_MISMATCH");
        assert.match((e as SbobError).message, /does not bind to this file/);
        return true;
      },
    );
  } finally {
    fix.cleanup();
  }
});

test("verifyEntry requires the sig and bundle sidecars and the entry itself", async () => {
  const fix = makeFixture();
  try {
    rmSync(fix.entry + ".bundle");
    await assert.rejects(verifyEntry(fix.entry, {}), (e: unknown) => {
      assert.ok(e instanceof SbobError);
      assert.equal((e as SbobError).code, "ERR_VERIFY_BUNDLE_MISSING");
      assert.match((e as SbobError).message, /\.bundle/);
      return true;
    });
    fix.setBundle(readFileSync(fix.entry));
    rmSync(fix.entry + ".sig");
    await assert.rejects(verifyEntry(fix.entry, {}), (e: unknown) => {
      assert.ok(e instanceof SbobError);
      assert.equal((e as SbobError).code, "ERR_VERIFY_SIG_MISSING");
      return true;
    });
    const missing = join(fix.dir, "nope.yaml");
    await assert.rejects(verifyEntry(missing, {}), (e: unknown) => {
      assert.ok(e instanceof SbobError);
      assert.equal((e as SbobError).code, "ERR_VERIFY_ENTRY_MISSING");
      return true;
    });
  } finally {
    fix.cleanup();
  }
});

test("verifyEntry rejects malformed bundles loudly (JSON, layout, hash shape)", async () => {
  const fix = makeFixture();
  try {
    writeFileSync(fix.entry + ".bundle", "{not json");
    await assert.rejects(verifyEntry(fix.entry, {}), (e: unknown) => {
      assert.ok(e instanceof SbobError);
      assert.equal((e as SbobError).code, "ERR_VERIFY_BUNDLE_MALFORMED");
      return true;
    });

    writeFileSync(fix.entry + ".bundle", JSON.stringify({ base64Signature: "eA==" }));
    await assert.rejects(verifyEntry(fix.entry, {}), (e: unknown) => {
      assert.ok(e instanceof SbobError);
      assert.equal((e as SbobError).code, "ERR_VERIFY_BUNDLE_MALFORMED");
      assert.match((e as SbobError).message, /\.rekorBundle\.Payload\.body/);
      return true;
    });

    // hashedrekord with a non-sha256 algorithm is not a contract this
    // verifier upholds — refuse rather than degrade
    const body = {
      apiVersion: "v0.0.1",
      kind: "hashedrekord",
      body: { hashedrekord: { data: { hash: { algorithm: "sha1", value: "00" } } } },
    };
    writeFileSync(fix.entry + ".bundle", JSON.stringify({
      rekorBundle: { Payload: { body: Buffer.from(JSON.stringify(body)).toString("base64") } },
    }));
    await assert.rejects(verifyEntry(fix.entry, {}), (e: unknown) => {
      assert.ok(e instanceof SbobError);
      assert.equal((e as SbobError).code, "ERR_VERIFY_BUNDLE_MALFORMED");
      return true;
    });
  } finally {
    fix.cleanup();
  }
});

test("extractRekorSha256 accepts the legacy .bundle.Payload layout too", () => {
  const entry = "legacy-bytes";
  const body = {
    apiVersion: "v0.0.1",
    kind: "hashedrekord",
    body: { hashedrekord: { data: { hash: { algorithm: "sha256", value: sha256(entry) } } } },
  };
  const legacy = JSON.stringify({
    base64Signature: "eA==",
    bundle: { Payload: { body: Buffer.from(JSON.stringify(body)).toString("base64") } },
  });
  assert.equal(extractRekorSha256(legacy).hashValue, sha256(entry));
});

// ---------------------------------------------------------------------------
// identity pin normalization (stage 2 gating)
// ---------------------------------------------------------------------------

test("normalizeVerifyOptions defaults the issuer to GitHub Actions OIDC when only an identity is given", () => {
  const opts = normalizeVerifyOptions({ certificateIdentity: "https://github.com/acme/app/.github/workflows/publish.yml@refs/heads/main" });
  assert.equal(opts.certificateOidcIssuer, GITHUB_ACTIONS_OIDC_ISSUER);
});

test("normalizeVerifyOptions keeps an explicit issuer and rejects an issuer without an identity", () => {
  const opts = normalizeVerifyOptions({
    certificateIdentity: "acme-id",
    certificateOidcIssuer: "https://idp.example.com",
  });
  assert.equal(opts.certificateOidcIssuer, "https://idp.example.com");
  assert.throws(
    () => normalizeVerifyOptions({ certificateOidcIssuer: "https://idp.example.com" }),
    (e: unknown) => {
      assert.ok(e instanceof SbobError);
      assert.equal((e as SbobError).code, "ERR_VERIFY_COSIGN_FAILED");
      assert.match((e as SbobError).message, /requires --certificate-identity/);
      return true;
    },
  );
});

// ---------------------------------------------------------------------------
// cosign stage 2 — fail-loud when the binary is missing
// ---------------------------------------------------------------------------

test("verifyEntry fails loud with ERR_VERIFY_COSIGN_UNAVAILABLE when an identity pin is requested and no cosign is on PATH", async (t) => {
  if (hasCosign()) {
    t.skip("cosign binary present on this machine — the unavailable-path cannot be asserted here");
    return;
  }
  const fix = makeFixture();
  try {
    await assert.rejects(
      verifyEntry(fix.entry, { certificateIdentity: "https://github.com/acme/app/.github/workflows/publish.yml@refs/heads/main" }),
      (e: unknown) => {
        assert.ok(e instanceof SbobError);
        assert.equal((e as SbobError).code, "ERR_VERIFY_COSIGN_UNAVAILABLE");
        assert.match((e as SbobError).message, /no cosign binary on PATH/);
        return true;
      },
    );
  } finally {
    fix.cleanup();
  }
});

// ---------------------------------------------------------------------------
// CLI subprocess contract (exit 0 ok / 1 SbobError / 2 usage)
// ---------------------------------------------------------------------------

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], cwd?: string): RunResult {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: cwd ?? ROOT, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

test("cli verify: ok on a byte-bound entry, notes offline-only without an identity pin", () => {
  const fix = makeFixture();
  try {
    const r = runCli(["verify", "--sbob", fix.entry], fix.dir);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /OK: redis/);
    assert.match(r.stdout, /bundle byte-binding: sha256/);
    assert.match(r.stdout, /offline byte-binding only/);
  } finally {
    fix.cleanup();
  }
});

test("cli verify: exit 1 + ERR_VERIFY_HASH_MISMATCH on a defect-A entry", () => {
  const fix = makeFixture();
  try {
    fix.setBundle(Buffer.from("pre-convert-bytes"));
    const r = runCli(["verify", "--sbob", fix.entry], fix.dir);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /ERR_VERIFY_HASH_MISMATCH/);
  } finally {
    fix.cleanup();
  }
});

test("cli verify: usage (exit 2) without --sbob and on unknown options", () => {
  assert.equal(runCli(["verify"]).status, 2);
  assert.equal(runCli(["verify", "--certificate-oidc-issuer", "https://x", "--sbob", REDIS]).status, 1);
  const r = runCli(["verify", "--frobnicate"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /usage: sbobctl/);
});

test("cli verify: exit 1 on a schema-invalid entry before any bundle check", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbob-verify-cli-"));
  try {
    const entry = join(dir, "broken.yaml");
    writeFileSync(entry, "metadata:\n  name: [unclosed\n");
    const r = runCli(["verify", "--sbob", entry], dir);
    assert.equal(r.status, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli verify: cosign-unavailable exits 1 with the operator guidance (skipped when cosign present)", (t) => {
  if (hasCosign()) {
    t.skip("cosign binary present on this machine");
    return;
  }
  const fix = makeFixture();
  try {
    const r = runCli(
      ["verify", "--sbob", fix.entry, "--certificate-identity", "https://github.com/acme/app/.github/workflows/publish.yml@refs/heads/main"],
      fix.dir,
    );
    assert.equal(r.status, 1);
    assert.match(r.stderr, /ERR_VERIFY_COSIGN_UNAVAILABLE/);
    assert.match(r.stderr, /sigstore\/cosign installer/);
  } finally {
    fix.cleanup();
  }
});

// fixtures never leak
test("fixture cleanup leaves nothing behind", () => {
  const fix = makeFixture();
  const dir = fix.dir;
  fix.cleanup();
  assert.equal(existsSync(dir), false);
});

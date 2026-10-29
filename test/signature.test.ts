/**
 * Signature verification interface (TDS 7.1 / spec section 8) — SkipVerifier,
 * CosignVerifier and makeVerifier wiring.
 *
 * The upstream SBoB signature envelope (spec section 8) is still in
 * development, so the guarantee under test is the fail-loud contract:
 * unsigned development profiles must pass --skip-signature-verify explicitly,
 * and a missing cosign binary must never silently skip verification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { CosignVerifier, makeVerifier, SkipVerifier } from "../src/signature.ts";
import { SbobError } from "../src/errors.ts";

/** Whether a cosign binary is usable on PATH (CI runners do not ship one). */
function hasCosign(): boolean {
  return spawnSync("cosign", ["version"]).status === 0;
}

test("SkipVerifier reports method=skipped and marks the profile unverified", async () => {
  const result = await new SkipVerifier().verify("sbobs/redis.yaml");
  assert.equal(result.ok, true);
  assert.ok(result.method === "skipped");
  if (result.method === "skipped") {
    assert.match(result.note, /--skip-signature-verify/);
    assert.match(result.note, /unverified/);
  }
});

test("SkipVerifier is path-independent and repeatable", async () => {
  const v = new SkipVerifier();
  const a = await v.verify("a.yaml");
  const b = await v.verify("some/other/path.yaml");
  assert.deepEqual(a, b);
});

test("makeVerifier wires the skip flag to the right implementation", () => {
  assert.ok(makeVerifier(true) instanceof SkipVerifier);
  assert.ok(makeVerifier(false) instanceof CosignVerifier);
});

test("CosignVerifier fails loud with ERR_SIGNATURE_UNAVAILABLE when no cosign binary is on PATH", async (t) => {
  if (hasCosign()) {
    t.skip("cosign binary present on this machine — the unavailable-path cannot be asserted here");
    return;
  }
  await assert.rejects(
    new CosignVerifier().verify("sbobs/redis.yaml"),
    (e: unknown) => {
      assert.ok(e instanceof SbobError, "SbobError, not a raw exec error");
      assert.equal((e as SbobError).code, "ERR_SIGNATURE_UNAVAILABLE");
      // the operator must be told which file and which flag fix it
      assert.match((e as SbobError).message, /sbobs\/redis\.yaml/);
      assert.match((e as SbobError).message, /--skip-signature-verify/);
      return true;
    },
  );
});

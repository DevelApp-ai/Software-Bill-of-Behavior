/**
 * CLI integration tests — sbobctl as a subprocess: usage/exit-code contract
 * (exit 2 usage, exit 1 SbobError, exit 0 success) for every command,
 * the fail-on verdict semantics of `diff`, and the multi-workload registry
 * evolution path of `transpile`.
 *
 * The unit suites cover the engines; these tests pin the operator-facing
 * behavior: what an operator sees in stdout/stderr and what CI can branch on.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const CLI = join(ROOT, "src", "cli.ts");
const REDIS = join(ROOT, "sbobs", "redis.yaml");
const REGISTRY = join(ROOT, "docs", "sbob-registry.yaml");

/** Next slot the committed registry will allocate (max slot + 1, TDS 6.1) —
 *  derived instead of hardcoded so registry evolution (new committed
 *  workloads) does not break this contract. */
function nextSlot(): number {
  const slots = [...readFileSync(REGISTRY, "utf8").matchAll(/\{slot: (\d+)\}/g)].map((m) => Number(m[1]));
  return Math.max(...slots, -1) + 1;
}

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): RunResult {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function hasCosign(): boolean {
  return spawnSync("cosign", ["version"]).status === 0;
}

// ---------------------------------------------------------------------------
// usage contract — every malformed invocation must exit 2 with usage on stderr
// ---------------------------------------------------------------------------

test("no arguments prints usage and exits 2", () => {
  const r = runCli([]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /usage: sbobctl/);
  assert.equal(r.stdout, "");
});

test("unknown option is rejected with usage (exit 2)", () => {
  const r = runCli(["validate", "--sbob", REDIS, "--frobnicate"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown option: --frobnicate/);
});

test("unknown command prints usage and exits 2", () => {
  const r = runCli(["frobnicate", "--sbob", REDIS]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /usage: sbobctl/);
});

test("transpile without --sbob is a usage error (exit 2)", () => {
  const r = runCli(["transpile"]);
  assert.equal(r.status, 2);
});

test("validate with two --sbob files is a usage error (exit 2)", () => {
  const r = runCli(["validate", "--sbob", REDIS, "--sbob", REDIS]);
  assert.equal(r.status, 2);
});

test("diff without --old/--new is a usage error (exit 2)", () => {
  const r = runCli(["diff", "--new", REDIS]);
  assert.equal(r.status, 2);
});

test("enforce without --state is a usage error (exit 2)", () => {
  const r = runCli(["enforce", "--sbob", REDIS, "--skip-signature-verify"]);
  assert.equal(r.status, 2);
});

test("profile without --workload/--image is a usage error (exit 2)", () => {
  const r = runCli([
    "profile", "--events", join(ROOT, "test", "profiler-fixtures", "events.jsonl"),
  ]);
  assert.equal(r.status, 2);
});

test("profile rejects a zero window (--window-days 0, exit 2)", () => {
  const r = runCli([
    "profile", "--events", join(ROOT, "test", "profiler-fixtures", "events.jsonl"),
    "--workload", "legacy-cache", "--image", "docker.io/legacy/cache@sha256:aa",
    "--window-days", "0",
  ]);
  assert.equal(r.status, 2);
});

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

test("validate prints the workload identity and exits 0", () => {
  const r = runCli(["validate", "--sbob", REDIS]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^OK: redis \(cache-tier\)/);
});

test("validate on a schema-invalid SBoB exits 1 with ERR_SCHEMA_INVALID on stderr", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbob-cli-"));
  try {
    const broken = join(dir, "broken.yaml");
    writeFileSync(
      broken,
      "apiVersion: sbob.k8sstormcenter.io/v1\nkind: SoftwareBillOfBehavior\nmetadata:\n  name: broken\n  namespace: ns\nspec:\n  architectures: [amd64]\n",
    );
    const r = runCli(["validate", "--sbob", broken]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /ERR_SCHEMA_INVALID/);
    assert.match(r.stderr, /imageID/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// transpile
// ---------------------------------------------------------------------------

test("transpile with an unknown target exits 2 and lists the valid targets", () => {
  const r = runCli(["transpile", "--sbob", REDIS, "--target", "vmware", "--skip-signature-verify"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /target "vmware" is not available/);
  assert.match(r.stderr, /linux, windows, k8s-node/);
});

test("transpile without --skip-signature-verify fails loud when no cosign binary exists", async (t) => {
  if (hasCosign()) {
    t.skip("cosign binary present on this machine — cannot assert the unavailable path");
    return;
  }
  const r = runCli(["transpile", "--sbob", REDIS]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /ERR_SIGNATURE_UNAVAILABLE/);
});

test("transpile writes the bundle, reports the slot, and does not touch the registry for a known workload", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbob-cli-"));
  try {
    const reg = join(dir, "registry.yaml");
    const out = join(dir, "bundle");
    copyFileSync(REGISTRY, reg);
    const r = runCli([
      "transpile", "--sbob", REDIS, "--registry", reg, "--out", out,
      "--target", "linux", "--skip-signature-verify",
    ]);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /workload redis \(slot 0\)/);
    assert.ok(existsSync(join(out, "redis.manifest.json")));
    assert.ok(existsSync(join(out, "wazuh", "rules", "sbob", "100000_redis_linux.xml")));
    // redis is already allocated: no registry evolution, no update hint
    assert.doesNotMatch(r.stdout, /registry updated/);
    assert.equal(readFileSync(reg, "utf8"), readFileSync(REGISTRY, "utf8"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("transpile allocates the next slot for a new workload and prints the evolved registry (the file is never mutated)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbob-cli-"));
  try {
    const reg = join(dir, "registry.yaml");
    const out = join(dir, "bundle");
    const web = join(dir, "web.yaml");
    copyFileSync(REGISTRY, reg);
    // a second workload: same shape, different name
    writeFileSync(web, readFileSync(REDIS, "utf8").replace("name: redis", "name: web"));
    const r = runCli([
      "transpile", "--sbob", REDIS, "--sbob", web,
      "--registry", reg, "--out", out,
      "--target", "linux", "--skip-signature-verify",
    ]);
    assert.equal(r.status, 0);
    const slot = nextSlot();
    assert.match(r.stdout, /workload redis \(slot 0\)/);
    assert.match(r.stdout, new RegExp(`workload web \\(slot ${slot}\\)`));
    assert.match(r.stdout, /registry updated/);
    // the new slot lands in its own 100xxx band, not the redis band (TDS 6.1)
    assert.ok(existsSync(join(out, "redis.manifest.json")));
    assert.ok(existsSync(join(out, "web.manifest.json")));
    assert.ok(existsSync(join(out, "wazuh", "rules", "sbob", `${100000 + slot * 100}_web_linux.xml`)));
    // the GitOps contract: the committed registry file is never mutated in place —
    // the evolved registry is printed for the operator to review and commit
    assert.equal(readFileSync(reg, "utf8"), readFileSync(REGISTRY, "utf8"));
    assert.match(r.stdout, new RegExp(`web: \\{slot: ${slot}\\}`));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// diff — verdict/exit-code contract (the M8 release gate)
// ---------------------------------------------------------------------------

const DIFF_BASE = join(ROOT, "test", "diffgate-fixtures", "base.yaml");
const DIFF_DRIFTED = join(ROOT, "test", "diffgate-fixtures", "drifted.yaml");

test("diff on a drifted pair exits 1 (default --fail-on mandatory) and prints the verdict", () => {
  const r = runCli(["diff", "--old", DIFF_BASE, "--new", DIFF_DRIFTED]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /MANDATORY/);
});

test("diff --fail-on none exits 0 even on a mandatory verdict", () => {
  const r = runCli(["diff", "--old", DIFF_BASE, "--new", DIFF_DRIFTED, "--fail-on", "none"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /MANDATORY/);
});

test("diff --fail-on advisory still blocks a mandatory verdict (exit 1)", () => {
  const r = runCli(["diff", "--old", DIFF_BASE, "--new", DIFF_DRIFTED, "--fail-on", "advisory"]);
  assert.equal(r.status, 1);
});

test("diff on an identical pair exits 0 and reports no scored changes", () => {
  const r = runCli(["diff", "--old", DIFF_BASE, "--new", DIFF_BASE]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /No scored behavior changes/);
});

test("diff rejects an invalid --fail-on level with usage (exit 2)", () => {
  const r = runCli(["diff", "--old", DIFF_BASE, "--new", DIFF_DRIFTED, "--fail-on", "bogus"]);
  assert.equal(r.status, 2);
});

test("diff --report writes the machine-readable JSON delta report", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbob-cli-"));
  try {
    const report = join(dir, "report.json");
    const r = runCli(["diff", "--old", DIFF_BASE, "--new", DIFF_DRIFTED, "--report", report]);
    assert.equal(r.status, 1);
    const parsed = JSON.parse(readFileSync(report, "utf8")) as { verdict: string; score: number };
    assert.equal(parsed.verdict, "mandatory");
    assert.ok(parsed.score >= 25);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// enforce — the Monitor->Audit->Enforce gates as the operator meets them
// ---------------------------------------------------------------------------

const ENFORCE_STATE = join(ROOT, "test", "enforce-fixtures", "redis-enforce.state.yaml");
const ENFORCE_BAD = join(ROOT, "test", "enforce-fixtures", "redis-bad-enforce.state.yaml");

test("enforce on an enforce state without an audit record exits 1 with ERR_ENFORCE_NOT_AUDITED", () => {
  const r = runCli([
    "enforce", "--sbob", REDIS, "--state", ENFORCE_BAD,
    "--target", "linux", "--skip-signature-verify",
  ]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /ERR_ENFORCE_NOT_AUDITED/);
});

test("enforce on a graduated state exits 0 and lists the enforcing sections", () => {
  const dir = mkdtempSync(join(tmpdir(), "sbob-cli-"));
  try {
    const r = runCli([
      "enforce", "--sbob", REDIS, "--state", ENFORCE_STATE, "--out", join(dir, "bundle"),
      "--target", "linux", "--skip-signature-verify",
    ]);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /enforcing sections: execs, egress, ingress/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("enforce with a k8s-only target name is rejected on linux (exit 2)", () => {
  const r = runCli([
    "enforce", "--sbob", REDIS, "--state", ENFORCE_STATE,
    "--target", "sigma", "--skip-signature-verify",
  ]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /enforce targets: linux, windows, k8s-node/);
});

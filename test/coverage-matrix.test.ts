/**
 * Machine-generated coverage matrix (TDS 8, M4 / issue #5) — completeness
 * gate, reason-code validity, suppression cells.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import type { IR } from "../src/types.ts";
import { makeAllocator } from "../src/ruleids.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { generateWindowsBundle } from "../src/codegen/windows.ts";
import { generateK8sNodeBundle } from "../src/codegen/k8s.ts";
import {
  COVERAGE_SECTIONS,
  REASON_CODES,
  assertCoverageComplete,
  buildCoverageMatrix,
} from "../src/coverage.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;

function redisIR(): IR {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  return buildIR(validateSbob(parsed), parsed);
}

function manifestFor(ir: IR, target: "linux" | "windows" | "k8s"): any {
  const files =
    target === "linux"
      ? generateLinuxBundle(ir, makeAllocator("redis", 0))
      : target === "windows"
        ? generateWindowsBundle(ir, makeAllocator("redis", 0))
        : generateK8sNodeBundle(ir, makeAllocator("redis", 0));
  return JSON.parse(files.find((f) => f.path === "redis.manifest.json")!.content);
}

// ---------------------------------------------------------------------------

test("matrix has 18 canonical rows (10 sections + 8 rulePolicies) x 3 targets", () => {
  const matrix = buildCoverageMatrix(redisIR());
  assert.equal(matrix.workload, "redis");
  assert.deepEqual(matrix.rows.map((r) => r.section), COVERAGE_SECTIONS);
  assert.equal(matrix.rows.length, 18);
  for (const row of matrix.rows) {
    for (const t of ["linux", "windows", "k8s"] as const) {
      assert.ok(row.cells[t], `${row.section}/${t} present`);
    }
  }
});

test("redis matrix: known cells land on the documented statuses", () => {
  const m = buildCoverageMatrix(redisIR());
  const cell = (section: string, t: "linux" | "windows" | "k8s") =>
    m.rows.find((r) => r.section === section)!.cells[t];
  assert.equal(cell("execs.path", "linux").status, "covered");
  assert.equal(cell("execs.args", "windows").status, "partial");
  assert.ok(cell("execs.args", "windows").reasons.includes("ARGS_WIN_CMDLINE"));
  assert.equal(cell("opens.flags", "linux").status, "partial");
  assert.ok(cell("opens.flags", "linux").reasons.includes("FLAGS_DEFERRED"));
  assert.equal(cell("egress.dnsNames", "linux").status, "partial");
  assert.ok(cell("egress.dnsNames", "linux").reasons.includes("DNS_NODE_BLIND"));
  assert.equal(cell("capabilities", "linux").status, "absent");
  assert.ok(cell("capabilities", "linux").reasons.includes("SECTION_ABSENT"));
  // rulePolicies defaults (section absent): audit-keyed covered on linux/k8s
  assert.equal(cell("rulePolicies.module-load", "linux").status, "covered");
  assert.equal(cell("rulePolicies.module-load", "windows").status, "partial");
  assert.ok(cell("rulePolicies.module-load", "windows").reasons.includes("SIG_WIN_DEFERRED"));
  assert.equal(cell("rulePolicies.namespace-change", "windows").status, "not-applicable");
  assert.equal(cell("rulePolicies.sensitive-file-access", "linux").status, "covered");
  assert.equal(cell("rulePolicies.kubernetes-api-access", "k8s").status, "covered");
  assert.ok(cell("rulePolicies.kubernetes-api-access", "k8s").reasons.includes("SIG_MANAGER_JSON"));
  assert.equal(cell("rulePolicies.binary-not-in-container-image", "k8s").status, "partial");
  assert.ok(cell("rulePolicies.binary-not-in-container-image", "k8s").reasons.includes("SIG_CORRELATE"));
});

test("containerAllowed flips the policy row to not-applicable/SIG_EXEMPT_SUPPRESSED", () => {
  const ir = redisIR();
  ir.rulePolicies = { "module-load": { containerAllowed: true } };
  const m = buildCoverageMatrix(ir);
  const c = m.rows.find((r) => r.section === "rulePolicies.module-load")!.cells.linux;
  assert.equal(c.status, "not-applicable");
  assert.ok(c.reasons.includes("SIG_EXEMPT_SUPPRESSED"));
  // and the build actually suppresses the rule
  const files = generateLinuxBundle(ir, makeAllocator("redis", 0));
  const rulesXml = files.find((f) => f.path.endsWith("_linux.xml"))!.content;
  assert.ok(!rulesXml.includes('id="100060"'), "module-load rule suppressed in emission");
});

test("completeness gate passes for redis and fails on a broken matrix", () => {
  const good = buildCoverageMatrix(redisIR());
  assert.deepEqual(assertCoverageComplete(good), []);

  const missingRow = { ...good, rows: good.rows.filter((r) => r.section !== "endpoints") };
  assert.ok(assertCoverageComplete(missingRow).some((p) => p.includes("missing coverage row: endpoints")));

  const badReason = JSON.parse(JSON.stringify(good)) as typeof good;
  badReason.rows[0].cells.linux.reasons.push("SIG_MADE_UP");
  assert.ok(assertCoverageComplete(badReason).some((p) => p.includes("SIG_MADE_UP")));

  const noReason = JSON.parse(JSON.stringify(good)) as typeof good;
  const egress = noReason.rows.find((r) => r.section === "egress.dnsNames")!;
  egress.cells.linux = { status: "partial", reasons: [] };
  assert.ok(assertCoverageComplete(noReason).some((p) => p.includes("without a reason code")));
});

test("every REASON_CODE value is a stable identifier key (documented, not silent)", () => {
  const expected = [
    "SECTION_ABSENT", "ARGS_WIN_CMDLINE", "OPEN_CREATE_ONLY_WIN", "FLAGS_DEFERRED",
    "DNS_NODE_BLIND", "K8SPEER_PHASE3", "INGRESS_ACCEPT_WEAK", "ENDPOINTS_L7",
    "CAPS_PENDING", "SIG_WIN_DEFERRED", "SIG_CORRELATE", "SIG_PARENT_REQUIRED",
    "SIG_MANAGER_JSON", "SIG_SADDR_PENDING", "SIG_EXEMPT_SUPPRESSED", "SIG_NODE_SCOPED",
  ];
  assert.deepEqual(Object.keys(REASON_CODES), expected);
  for (const v of Object.values(REASON_CODES)) assert.ok(v.length > 10);
});

test("all three target manifests embed the coverage matrix and pass the build gate", () => {
  const ir = redisIR();
  for (const target of ["linux", "windows", "k8s"] as const) {
    const manifest = manifestFor(ir, target);
    assert.ok(manifest.coverage, `${target} manifest has coverage`);
    assert.equal(manifest.coverage.rows.length, 18);
    assert.deepEqual(assertCoverageComplete(manifest.coverage), []);
    assert.ok(
      manifest.coverageNotes.some((n: string) => n.includes("signatures: audit keys are node-scoped")),
      `${target} manifest carries the signature pack note`,
    );
  }
});

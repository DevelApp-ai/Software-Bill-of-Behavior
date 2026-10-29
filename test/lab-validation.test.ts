/**
 * Lab-validation evidence flip (M1-M4 exit criteria, docs/lab-validation.yaml).
 *
 * A committed evidence record (workload x targets x manager x date x run URL)
 * stamps the generated bundle for the listed targets: the XML header banner
 * reads LAB VALIDATED with the evidence, the manifest carries
 * labValidation: "validated" plus the evidence record. Workload x target pairs
 * without a record keep the LAB VALIDATION PENDING banner and
 * labValidation: "pending" — the default stays pending.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { labForTarget, makeAllocator, parseLabValidations } from "../src/ruleids.ts";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { generateWindowsBundle } from "../src/codegen/windows.ts";
import { generateK8sNodeBundle } from "../src/codegen/k8s.ts";

const LAB_YAML = `
validations:
  - workload: redis
    targets: [linux, k8s-node]
    manager: wazuh/wazuh-manager:4.14.6
    date: "2026-10-29"
    evidence: https://example.invalid/actions/runs/1
`;

function redisIR() {
  const raw = readFileSync(new URL("../sbobs/redis.yaml", import.meta.url), "utf8");
  const parsed = parseYaml(raw);
  return buildIR(validateSbob(parsed), parsed);
}

function manifestOf(files: Array<{ path: string; content: string }>, name: string) {
  return JSON.parse(files.find((f) => f.path === name)!.content);
}

test("parseLabValidations reads workload evidence records", () => {
  const map = parseLabValidations(LAB_YAML);
  const rec = map.get("redis");
  assert.ok(rec, "record present");
  assert.deepEqual(rec!.targets, ["linux", "k8s-node"]);
  assert.equal(rec!.manager, "wazuh/wazuh-manager:4.14.6");
  assert.equal(rec!.date, "2026-10-29");
  assert.equal(rec!.evidence, "https://example.invalid/actions/runs/1");
});

test("parseLabValidations fails loudly on malformed records", () => {
  assert.throws(() => parseLabValidations("not-a-mapping:\n"));
  assert.throws(() => parseLabValidations("validations:\n  - workload: redis\n"));
  assert.throws(() =>
    parseLabValidations(
      'validations:\n  - {workload: redis, targets: [linux], manager: m, date: "2026-10-29", evidence: "https://x.invalid/1"}\n' +
        '  - {workload: redis, targets: [windows], manager: m, date: "2026-10-29", evidence: "https://x.invalid/1"}\n',
    ),
  );
  assert.throws(() =>
    parseLabValidations(
      'validations:\n  - {workload: redis, targets: [linux], manager: m, date: "29-10-2026", evidence: "https://x.invalid/1"}\n',
    ),
  );
  assert.throws(() =>
    parseLabValidations(
      'validations:\n  - {workload: redis, targets: [linux], manager: m, date: "2026-10-29", evidence: "not-a-url"}\n',
    ),
  );
  assert.throws(() =>
    parseLabValidations('validations:\n  - {workload: redis, targets: [], manager: m, date: "2026-10-29", evidence: "https://x.invalid/1"}\n'),
  );
});

test("with-lab allocator stamps validated banner + manifest evidence (linux)", () => {
  const lab = parseLabValidations(LAB_YAML).get("redis")!;
  const files = generateLinuxBundle(redisIR(), makeAllocator("redis", 0, lab));
  const banner = "LAB VALIDATED (2026-10-29, wazuh/wazuh-manager:4.14.6): evidence https://example.invalid/actions/runs/1";
  assert.ok(files.find((f) => f.path === "wazuh/decoders/sbob/redis.xml")!.content.includes(banner));
  assert.ok(files.find((f) => f.path.endsWith("_redis_linux.xml"))!.content.includes(banner));
  const manifest = manifestOf(files, "redis.manifest.json");
  assert.equal(manifest.labValidation, "validated");
  assert.equal(manifest.labValidationEvidence.evidence, "https://example.invalid/actions/runs/1");
  assert.equal(manifest.labValidationEvidence.manager, "wazuh/wazuh-manager:4.14.6");
  assert.equal(manifest.labValidationEvidence.date, "2026-10-29");
  assert.deepEqual(manifest.labValidationEvidence.targets, ["linux", "k8s-node"]);
});

test("target filter: an evidence record without this target keeps the bundle pending (windows)", () => {
  const map = parseLabValidations(LAB_YAML); // redis record targets: [linux, k8s-node] — no windows
  const filtered = labForTarget(map, "redis", "windows");
  assert.equal(filtered, undefined, "labForTarget filters the record out for unlisted targets");
  const files = generateWindowsBundle(redisIR(), makeAllocator("redis", 0, filtered));
  const xml = files.find((f) => f.path.endsWith("_redis_windows.xml"))!.content;
  assert.ok(xml.includes("LAB VALIDATION PENDING (M2 exit criteria)"));
  assert.ok(!xml.includes("LAB VALIDATED"));
  const manifest = manifestOf(files, "redis.manifest.json");
  assert.equal(manifest.labValidation, "pending");
  assert.equal(manifest.labValidationEvidence, undefined);
});

test("labForTarget passes the record through for listed targets", () => {
  const map = parseLabValidations(LAB_YAML);
  assert.equal(labForTarget(map, "redis", "linux"), map.get("redis"));
  assert.equal(labForTarget(map, "redis", "k8s-node"), map.get("redis"));
  assert.equal(labForTarget(map, "php-fpm", "linux"), undefined, "unrecorded workload");
});

test("with-lab allocator stamps the k8s-node bundle too (attribution target)", () => {
  const lab = parseLabValidations(LAB_YAML).get("redis")!;
  const files = generateK8sNodeBundle(redisIR(), makeAllocator("redis", 0, lab));
  const banner = "LAB VALIDATED (2026-10-29, wazuh/wazuh-manager:4.14.6): evidence https://example.invalid/actions/runs/1";
  assert.ok(files.find((f) => f.path === "wazuh/decoders/sbob/redis-k8s.xml")!.content.includes(banner));
  assert.ok(files.find((f) => f.path.endsWith("_redis_k8s-node.xml"))!.content.includes(banner));
  assert.equal(manifestOf(files, "redis.manifest.json").labValidation, "validated");
});

test("no-lab allocator keeps the pending default (all three targets)", () => {
  const linux = generateLinuxBundle(redisIR(), makeAllocator("redis", 0));
  const windows = generateWindowsBundle(redisIR(), makeAllocator("redis", 0));
  const k8s = generateK8sNodeBundle(redisIR(), makeAllocator("redis", 0));
  assert.equal(manifestOf(linux, "redis.manifest.json").labValidation, "pending");
  assert.equal(manifestOf(windows, "redis.manifest.json").labValidation, "pending");
  assert.equal(manifestOf(k8s, "redis.manifest.json").labValidation, "pending");
  for (const files of [linux, windows, k8s]) {
    for (const f of files) {
      if (f.path.endsWith(".xml")) assert.ok(!f.content.includes("LAB VALIDATED"), f.path);
    }
  }
});

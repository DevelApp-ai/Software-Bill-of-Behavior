/**
 * M5 ops rules + deploy flow (TDS 10) — config-check, cadence, digest
 * determinism, bundle version and agent-conf wiring.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { lintIR } from "../src/lint.ts";
import { makeAllocator } from "../src/ruleids.ts";
import type { IR } from "../src/types.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { generateK8sNodeBundle } from "../src/codegen/k8s.ts";
import { generateWindowsBundle } from "../src/codegen/windows.ts";
import {
  auditFragmentKeys,
  auditKeySetDigest,
  cadenceNote,
  pinnedImageDigest,
  bundleVersion,
} from "../src/codegen/opshealth.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;

function redisIR(): IR {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  return buildIR(validateSbob(parsed), parsed);
}

function linuxBundle(ir = redisIR()) {
  const alloc = makeAllocator("redis", 0);
  lintIR(ir, { confirmNone: [], requireScope: true });
  return generateLinuxBundle(ir, alloc);
}

function k8sBundle(ir = redisIR()) {
  const alloc = makeAllocator("redis", 0);
  lintIR(ir, { confirmNone: [], requireScope: true });
  return generateK8sNodeBundle(ir, alloc);
}

function fileText(files: { path: string; content: string }[], path: string): string {
  const f = files.find((x) => x.path === path);
  assert.ok(f, `missing bundle file ${path}`);
  return f.content;
}

// ---------------------------------------------------------------------------

test("audit key-set digest is deterministic and matches a manual sha256", () => {
  const bundle = linuxBundle();
  const rules = fileText(bundle, "wazuh/audit/sbob/redis.rules");
  const digest = auditKeySetDigest(rules.split("\n"));
  // manual re-derivation from the same fragment
  const keys = auditFragmentKeys(rules.split("\n"));
  const manual = createHash("sha256")
    .update([...keys].sort().join("\n") + "\n")
    .digest("hex");
  assert.equal(digest, manual);
  // stable across runs
  assert.equal(digest, auditKeySetDigest(fileText(linuxBundle(), "wazuh/audit/sbob/redis.rules").split("\n")));
  assert.match(digest, /^[0-9a-f]{64}$/);
});

test("linux bundle ships the config-check agent-conf wodle + digest script", () => {
  const bundle = linuxBundle();
  const frag = fileText(bundle, "wazuh/agent-conf/sbob/redis.xml");
  assert.match(frag, /<wodle name="command">/);
  assert.match(frag, /<tag>sbob-config-check<\/tag>/);
  assert.match(frag, /bash \/var\/ossec\/etc\/shared\/sbob-redis\/sbob-audit-digest\.sh/);
  assert.match(frag, /<interval>30m<\/interval>/);
  const script = fileText(bundle, "wazuh/agent-conf/sbob/redis-audit-digest.sh");
  assert.match(script, /auditctl -l/);
  assert.match(script, /sbob-audit-digest: /);
});

test("linux bundle emits config-check decoder + rule 100083 with the expected digest", () => {
  const bundle = linuxBundle();
  const decoders = fileText(bundle, "wazuh/decoders/sbob/redis.xml");
  assert.match(decoders, /<decoder name="sbob-redis-config-check">/);
  assert.match(decoders, /<prematch>\^sbob-audit-digest: \[0-9a-f\]\{64\}<\/prematch>/);
  const rules = fileText(bundle, "wazuh/rules/sbob/100000_redis_linux.xml");
  const digest = auditKeySetDigest(fileText(bundle, "wazuh/audit/sbob/redis.rules").split("\n"));
  assert.match(rules, new RegExp(`<rule id="100083" level="5">`));
  assert.ok(
    rules.includes(`^(?!${digest}$)`),
    "config-check rule anchors the negative lookahead to the bundle digest",
  );
  // no cadence rule on linux (docker events are k8s-node only)
  assert.ok(!rules.includes('id="100081"'));
});

test("k8s bundle emits cadence rule 100081 chained off 87900 and the config-check pair", () => {
  const bundle = k8sBundle();
  const rules = fileText(bundle, "wazuh/rules/sbob/100000_redis_k8s-node.xml");
  const cadenceIdx = rules.indexOf('<rule id="100081" level="9">');
  assert.ok(cadenceIdx > 0, "cadence rule present");
  const block = rules.slice(cadenceIdx, rules.indexOf("</rule>", cadenceIdx));
  assert.ok(block.includes("<if_sid>87900</if_sid>"));
  assert.match(block, /<field name="docker.status" type="pcre2">\^start\$<\/field>/);
  const pinned = pinnedImageDigest(redisIR().workload.imageID);
  assert.ok(pinned);
  assert.ok(
    block.includes(`(?:^|/)redis@sha256:(?!${pinned}$)`),
    "cadence regex is repo-anchored with a negative lookahead on the pinned digest",
  );
  // config-check rule + decoder present on k8s too
  assert.ok(rules.includes('<rule id="100083" level="5">'));
  assert.match(fileText(bundle, "wazuh/decoders/sbob/redis-k8s.xml"), /sbob-redis-config-check/);
  // wodle merged into the -k8s.xml fragment next to docker-listener
  const frag = fileText(bundle, "wazuh/agent-conf/sbob/redis-k8s.xml");
  assert.match(frag, /<wodle name="docker-listener">/);
  assert.match(frag, /<tag>sbob-config-check<\/tag>/);
  assert.ok(fileText(bundle, "wazuh/agent-conf/sbob/redis-audit-digest.sh").length > 0);
});

test("windows bundle: no ops rules, but manifest carries sbobVersion/imageID/bundleVersion", () => {
  const ir = redisIR();
  const alloc = makeAllocator("redis", 0);
  lintIR(ir, { confirmNone: [], requireScope: true });
  const bundle = generateWindowsBundle(ir, alloc);
  const paths = bundle.map((f) => f.path);
  assert.ok(
    !paths.some((p) => p.endsWith("-audit-digest.sh")),
    "windows ships no audit-digest script (no auditd)",
  );
  assert.ok(
    !paths.some((p) => p.endsWith("-config-check")),
    "windows ships no config-check decoder",
  );
  for (const f of bundle) {
    assert.ok(!f.content.includes('id="100081"'));
    assert.ok(!f.content.includes('id="100083"'));
  }
  const manifest = JSON.parse(fileText(bundle, "redis.manifest.json"));
  assert.equal(manifest.target, "windows");
  assert.equal(manifest.sbobVersion, ir.workload.sbobVersion);
  assert.equal(manifest.imageID, ir.workload.imageID);
  assert.equal(manifest.bundleVersion, bundleVersion(ir));
});

test("bundleVersion is digest-derived, falls back to -untagged for tag-only pins", () => {
  const ir = redisIR();
  const digest = pinnedImageDigest(ir.workload.imageID);
  assert.ok(digest);
  assert.equal(bundleVersion(ir), `sbob-v${ir.workload.sbobVersion}-${digest.slice(0, 12)}`);
  const tagged: IR = { ...ir, workload: { ...ir.workload, imageID: "docker.io/library/redis:7.2" } };
  assert.equal(bundleVersion(tagged), `sbob-v${ir.workload.sbobVersion}-untagged`);
});

test("cadenceNote fires for tag-pinned imageIDs only", () => {
  assert.equal(cadenceNote(redisIR()), undefined, "redis is digest-pinned — cadence rule emitted instead");
  const ir = redisIR();
  const tagged: IR = { ...ir, workload: { ...ir.workload, imageID: "docker.io/library/redis:7.2" } };
  const note = cadenceNote(tagged);
  assert.ok(note);
  assert.match(note, /TDS 10\.3/);
});

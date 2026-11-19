/**
 * M4 signature rules (rulePolicies, TDS 7.4) — rule emission, exemptions,
 * suppression and audit-fragment coverage.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { lintIR } from "../src/lint.ts";
import { makeAllocator } from "../src/ruleids.ts";
import type { IR } from "../src/types.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { generateK8sNodeBundle } from "../src/codegen/k8s.ts";
import {
  AUDIT_KEYED_POLICIES,
  SA_TOKEN_PATH_REGEX,
  SENSITIVE_PATH_REGEX,
  signatureAuditLines,
  signatureCoverageNotes,
  signatureRulesK8s,
  signatureRulesShared,
} from "../src/codegen/signatures.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;

function redisIR(): IR {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  return buildIR(validateSbob(parsed), parsed);
}

/** IR with rulePolicies injected (redis SBoB has none — section-absent path). */
function irWithPolicies(policies: Record<string, { processAllowed?: string[]; containerAllowed?: boolean }>): IR {
  const ir = redisIR();
  ir.rulePolicies = policies;
  return ir;
}

function linuxRules(ir: IR) {
  const alloc = makeAllocator("redis", 0);
  const files = generateLinuxBundle(ir, alloc);
  const xml = files.find((f) => f.path.endsWith("_linux.xml"))!.content;
  return { alloc, files, xml };
}

function k8sRules(ir: IR) {
  const alloc = makeAllocator("redis", 0);
  const files = generateK8sNodeBundle(ir, alloc);
  const xml = files.find((f) => f.path.endsWith("_k8s-node.xml"))!.content;
  return { alloc, files, xml };
}

function ruleBlock(xml: string, ruleId: number): string {
  const m = new RegExp(`<rule\\s+id="${ruleId}"[^>]*>([\\s\\S]*?)</rule>`, "m").exec(xml);
  assert.ok(m, `rule ${ruleId} present`);
  return m[1];
}

// ---------------------------------------------------------------------------

test("default signature pack: four audit-keyed rules emitted with M4 id layout", () => {
  const ir = redisIR(); // redis.yaml has no rulePolicies -> defaults
  const alloc = makeAllocator("redis", 0);
  const base = generateLinuxBundle(ir, alloc).length; // forces full allocation order
  assert.ok(base > 0);
  const alloc2 = makeAllocator("redis", 0);
  const rules = signatureRulesShared(ir, alloc2, []);
  const ids = rules.map((r) => r.id);
  // (6,0)-(6,3) audit-keyed policies, slot 0
  assert.deepEqual(ids, [100060, 100061, 100062, 100063]);
  assert.equal(rules[0].level, 12); // module-load
  assert.equal(rules[1].level, 10); // namespace-change
  assert.equal(rules[2].level, 10); // process-tracing
  assert.equal(rules[3].level, 10); // execution-from-memory
  assert.match(ruleBlock(linuxRules(ir).xml, 100060), /sbob-module-load/);
  assert.match(ruleBlock(linuxRules(ir).xml, 100060), /T1547\.006/);
});

test("overlays emitted only when the parent drift rule exists (redis: opens+egress present)", () => {
  const ir = redisIR();
  const { xml } = linuxRules(ir);
  // (0,1) sensitive-file overlay, (0,2) SA-token overlay, (0,3) k8s API connect overlay
  assert.match(ruleBlock(xml, 100001), /if_sid>100021/);
  assert.match(ruleBlock(xml, 100001), /shadow\|gshadow\|sudoers/);
  assert.match(ruleBlock(xml, 100002), /if_sid>100021/);
  assert.match(ruleBlock(xml, 100002), /serviceaccount/);
  // (0,9) overlay-sustained child (winner-context finding, issue #42): the
  // level-12 sensitive-file overlay steals the winner slot from the level-9
  // drift parent, so repeated sensitive access escalates via the overlay
  assert.match(ruleBlock(xml, 100009), /if_matched_sid>100001</);
  // (0,3) kubernetes-api connect overlay DELETED on wazuh 4.14: analysisd
  // rejects PCRE2 conditions on the STATIC srcip field; the policy rides the
  // manager-side k8s audit-log JSON rule (6,4) instead
  assert.ok(!xml.includes('id="100003"'), "(0,3) overlay not emitted");
  // no (0,4) on linux (k8s-only correlate)
  assert.ok(!xml.includes('id="100004"'));
});

test("overlay watchlist regexes are quote-anchored (audit.directory.name carries quotes)", () => {
  const sensitive = new RegExp(SENSITIVE_PATH_REGEX);
  const q = (x: string) => JSON.stringify(x); // the field decodes WITH quotes
  assert.ok(sensitive.test(q("/etc/shadow")));
  assert.ok(sensitive.test(q("/root/.ssh/authorized_keys")));
  assert.ok(sensitive.test(q("/home/redis/.ssh/id_rsa")));
  assert.ok(!sensitive.test(q("/etc/passwd")), "passwd is not on the watchlist");
  assert.ok(!sensitive.test(q("/data/dump.rdb")), "workload data is not sensitive");
  assert.ok(!sensitive.test("/etc/shadow"), "unquoted spelling must NOT match (quote-anchored)");
  const sa = new RegExp(SA_TOKEN_PATH_REGEX);
  assert.ok(sa.test(q("/var/run/secrets/kubernetes.io/serviceaccount/token")));
  assert.ok(sa.test(q("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")));
  assert.ok(!sa.test(q("/var/run/secrets/kubernetes.io/serviceaccount/other")));
});

test("(0,3) kubernetes-api overlay deletion is documented (srcip is a static field)", () => {
  const notes = signatureCoverageNotes(redisIR()).join("\n");
  assert.match(notes, /kubernetes-api-access/);
  assert.match(notes, /srcip is a static field|static/, "the static-field constraint is stated");
  assert.match(notes, /\(6,4\)|manager-side/, "manager-side rule carries the policy");
});

test("explicit rulePolicies requires lint confirmation when empty", () => {
  const ir = irWithPolicies({});
  assert.throws(
    () => lintIR(ir, { confirmNone: [], requireScope: true }),
    /ERR_NONE_UNCONFIRMED[\s\S]*rulePolicies/,
  );
  lintIR(ir, { confirmNone: ["rulePolicies"], requireScope: true }); // confirmed = ok
});

test("absent rulePolicies emits defaults and the section-absent coverage note", () => {
  const ir = redisIR();
  assert.equal(ir.rulePolicies, undefined);
  const manifest = JSON.parse(linuxRules(ir).files.find((f) => f.path === "redis.manifest.json")!.content);
  assert.ok(
    manifest.coverageNotes.some((n: string) => n.includes("rulePolicies: section-absent")),
    "ir pushes the section-absent note",
  );
  assert.equal(AUDIT_KEYED_POLICIES.length, 4);
});

test("k8s bundle carries the manager-side (6,4) JSON rule and the (0,4) correlate", () => {
  const ir = redisIR();
  const { xml } = k8sRules(ir);
  const mgr = ruleBlock(xml, 100064);
  assert.match(mgr, /object\.user\.username/);
  assert.match(mgr, /\^system:serviceaccount:cache-tier:redis\$/);
  assert.match(mgr, /secrets\|configmaps/);
  const correlate = ruleBlock(xml, 100004);
  assert.match(correlate, /if_sid>100074/); // child of the lifecycle rule
  assert.equal(xml.includes('id="100064"'), true);
});

test("kubernetes-api-access suppression kills the manager rule ((0,3) no longer exists)", () => {
  const ir = irWithPolicies({ "kubernetes-api-access": { containerAllowed: true } });
  const { xml } = k8sRules(ir);
  assert.ok(!xml.includes('id="100064"'), "manager-side (6,4) rule suppressed");
  // the node-side (0,3) overlay was deleted outright on wazuh 4.14 (srcip is
  // static; PCRE2 on static fields is rejected by analysisd) — suppression
  // only needs to silence the manager rule now
  assert.ok(!xml.includes('id="100003"'));
});

test("audit fragment carries node-scoped signature keys for all four policies", () => {
  const lines = signatureAuditLines(redisIR());
  const joined = lines.join("\n");
  for (const p of AUDIT_KEYED_POLICIES) {
    assert.ok(joined.includes(`-k ${p.auditKey}`), `${p.auditKey} b64 line`);
    assert.ok(joined.includes("-F arch=b32"), "b32 mirror emitted");
  }
});

test("signatureRulesK8s allocates (6,4)+(0,4) only; shared allocates section 6 + overlays", () => {
  const ir = redisIR();
  const alloc = makeAllocator("redis", 0);
  const k8sOnly = signatureRulesK8s(ir, alloc, 100074);
  assert.deepEqual(k8sOnly.map((r) => r.id), [100064, 100004]);
  // lifecycle id null -> no (0,4)
  const alloc2 = makeAllocator("redis", 0);
  assert.deepEqual(signatureRulesK8s(ir, alloc2, null).map((r) => r.id), [100064]);
});

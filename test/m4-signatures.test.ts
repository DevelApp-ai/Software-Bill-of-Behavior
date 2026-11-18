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
  signatureRulesK8s,
  signatureRulesShared,
} from "../src/codegen/signatures.ts";
import { saddrAllowedFragment } from "../src/codegen/sockaddr.ts";

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
  const m = new RegExp(`<rule id="${ruleId}"[^>]*>([\\s\\S]*?)</rule>`, "m").exec(xml);
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
  assert.match(ruleBlock(xml, 100003), /if_sid>100031/);
  // no (0,4) on linux (k8s-only correlate)
  assert.ok(!xml.includes('id="100004"'));
});

test("overlay watchlist regexes match the intended path classes", () => {
  const sensitive = new RegExp(SENSITIVE_PATH_REGEX);
  assert.ok(sensitive.test("/etc/shadow"));
  assert.ok(sensitive.test("/root/.ssh/authorized_keys"));
  assert.ok(sensitive.test("/home/redis/.ssh/id_rsa"));
  assert.ok(!sensitive.test("/etc/passwd"));
  assert.ok(!sensitive.test("/data/dump.rdb"));
  const sa = new RegExp(SA_TOKEN_PATH_REGEX);
  assert.ok(sa.test("/var/run/secrets/kubernetes.io/serviceaccount/token"));
  assert.ok(sa.test("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"));
  assert.ok(!sa.test("/var/run/secrets/kubernetes.io/serviceaccount/other"));
  // k8s API service CIDR 10.96.0.0/12 (any port) as a raw AF_INET sockaddr REM:
  // srcip is a static field, so the (0,3) overlay matches the raw saddr= record
  // (issue #42, TDS 7.3.1)
  const frag = saddrAllowedFragment("10.96.0.0", 12, null)!;
  assert.equal(frag, "0200[0-9A-F]{4}0A6[0-9A-F]{5}0{16}", "vip fragment shape (family+any port+0A6+5 free nybbles+padding)");
  const vip = new RegExp(frag);
  assert.ok(vip.test("0200FF0F0A6AF0000000000000000".padEnd(32, "0")), "in-CIDR VIP address matches");
  assert.ok(vip.test("020001F40A6FC1010000000000000000"), "10.111.193.1:500 matches");
  assert.ok(!vip.test("0200FF0F0A5AF0000000000000000".padEnd(32, "0")), "below the /12 does not match");
  assert.ok(!vip.test("0200FF0F0B0AF0000000000000000".padEnd(32, "0")), "above the /12 does not match");
});

test("containerAllowed=true suppresses rule + audit line entirely", () => {
  const ir = irWithPolicies({ "module-load": { containerAllowed: true } });
  const audit = signatureAuditLines(ir).join("\n");
  assert.match(audit, /module-load: audit line omitted — containerAllowed=true/);
  assert.ok(!audit.includes("-S init_module"));
  const { xml } = linuxRules(ir);
  assert.ok(!xml.includes('id="100060"'), "module-load rule suppressed");
  assert.ok(xml.includes('id="100061"'), "other policies still emitted");
});

test("processAllowed emits a CDB sigexempts list and not_match_key on the rule", () => {
  const ir = irWithPolicies({ "process-tracing": { processAllowed: ["systemd", "kubelet"] } });
  const { files, xml } = linuxRules(ir);
  const listFile = files.find((f) => f.path === "wazuh/lists/sbob/redis/sigexempts/process-tracing");
  assert.ok(listFile, "sigexempts list file emitted");
  assert.match(listFile!.content, /^kubelet:1$/m);
  const block = ruleBlock(xml, 100062);
  assert.match(block, /field="audit\.command" lookup="not_match_key"/);
  assert.match(block, /etc\/lists\/sbob\/redis\/sigexempts\/process-tracing/);
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

test("kubernetes-api-access suppression kills both the overlay and the manager rule", () => {
  const ir = irWithPolicies({ "kubernetes-api-access": { containerAllowed: true } });
  const { xml } = k8sRules(ir);
  assert.ok(!xml.includes('id="100064"'));
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

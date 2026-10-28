/**
 * M7 — Phase-3 enforcement (issue #8, TDS 14): Monitor->Audit->Enforce
 * rollout state machine, seccomp / AppArmor / NetworkPolicy / AppLocker
 * codegen, active responses, enforcement telemetry, NP declared-vs-enforced
 * diff, and the sbobctl enforce CLI orchestration.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import type { IR, NetCompiled } from "../src/types.ts";
import { makeAllocator, type IdAllocator } from "../src/ruleids.ts";
import {
  parseEnforceState,
  effectiveState,
  sectionsInState,
  runEnforce,
  type EnforceStateFile,
} from "../src/enforce.ts";
import { seccompProfile, seccompBlocklist, seccompSystemdDropin } from "../src/codegen/seccomp.ts";
import { apparmorProfile } from "../src/codegen/apparmor.ts";
import { networkPolicy, npRuleModel, npDiff } from "../src/codegen/networkpolicy.ts";
import { applockerPolicy } from "../src/codegen/applocker.ts";
import {
  activeResponseConf,
  processKillScript,
  enforceTelemetryRule,
  generateEnforceBundle,
} from "../src/codegen/enforcement.ts";
import { SbobError } from "../src/errors.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;
const FIX = (f: string) => new URL(`./enforce-fixtures/${f}`, import.meta.url).pathname;

function redisIR(): IR {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  return buildIR(validateSbob(parsed), parsed);
}

function loadState(f: string): EnforceStateFile {
  return parseEnforceState(readFileSync(FIX(f), "utf8"));
}

function throwsSbob(code: string, fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof SbobError, `expected SbobError, got ${String(e)}`);
    assert.equal((e as SbobError).code, code);
    return;
  }
  assert.fail(`expected SbobError ${code}, nothing thrown`);
}

// ---------------------------------------------------------------------------
// rollout state machine (TDS 14.6)
// ---------------------------------------------------------------------------

test("state: audit fixture — global default, all sections effectively audit", () => {
  const s = loadState("redis-audit.state.yaml");
  assert.equal(s.workload, "redis");
  assert.equal(s.state, "audit");
  assert.deepEqual(s.sections, {});
  for (const k of ["execs", "opens", "egress", "ingress"] as const) {
    assert.equal(effectiveState(s, k), "audit");
  }
  assert.deepEqual(sectionsInState(s, "enforce"), []);
});

test("state: enforce fixture — execs/egress/ingress enforcing, opens auditing", () => {
  const s = loadState("redis-enforce.state.yaml");
  assert.deepEqual(sectionsInState(s, "enforce").sort(), ["egress", "execs", "ingress"]);
  assert.equal(effectiveState(s, "opens"), "audit");
  for (const k of ["execs", "egress", "ingress"] as const) {
    const rec = s.auditRecords[k]!;
    assert.equal(rec.incidents, 0);
    assert.equal(rec.windowDays, 14);
  }
});

test("state: unknown section rejected", () => {
  throwsSbob("ERR_ENFORCE_STATE_INVALID", () =>
    parseEnforceState("workload: redis\nstate: audit\nsections:\n  nonsense: audit\n"));
});

test("state: bad state token rejected", () => {
  throwsSbob("ERR_ENFORCE_STATE_INVALID", () =>
    parseEnforceState("workload: redis\nstate: audit\nsections:\n  execs: on\n"));
});

test("state: enforce without an audit record rejected (TDS 14.6)", () => {
  throwsSbob("ERR_ENFORCE_NOT_AUDITED", () => {
    parseEnforceState(readFileSync(FIX("redis-bad-enforce.state.yaml"), "utf8"));
  });
});

test("state: enforce with incidents in the audit record rejected", () => {
  throwsSbob("ERR_ENFORCE_NOT_AUDITED", () =>
    parseEnforceState(
      'workload: redis\nstate: audit\nsections:\n  execs: enforce\nauditRecords:\n  execs:\n    started: "2026-10-01"\n    windowDays: 14\n    incidents: 2\n',
    ));
});

test("state: the ladder may not skip rungs", () => {
  throwsSbob("ERR_ENFORCE_STATE_INVALID", () => {
    parseEnforceState(readFileSync(FIX("redis-skip.state.yaml"), "utf8"));
  });
});

test("state: one rung above the default is legal (audit -> enforce, clean record)", () => {
  const s = parseEnforceState(
    'workload: redis\nstate: audit\nsections:\n  execs: enforce\nauditRecords:\n  execs:\n    started: "2026-10-01"\n    windowDays: 14\n    incidents: 0\n',
  );
  assert.equal(effectiveState(s, "execs"), "enforce");
});

test("state: monitor default caps sections at audit (enforce rung unreachable)", () => {
  const s = parseEnforceState("workload: redis\nstate: monitor\nsections:\n  execs: audit\n");
  assert.equal(effectiveState(s, "execs"), "audit");
});

test("runEnforce: state file for a different workload rejected", async () => {
  const dir = mkdtempSync(join(tmpdir(), "m7-"));
  const otherState = join(dir, "postgres.state.yaml");
  writeFileSync(otherState, "workload: postgres\nstate: audit\n");
  try {
    await assert.rejects(
      runEnforce(REDIS, {
        registryPath: "docs/sbob-registry.yaml",
        outDir: join(dir, "out"),
        target: "linux",
        statePath: otherState,
        enforcedNpPath: "",
        skipSignatureVerify: true,
        confirmNone: [],
      }),
      (e: unknown) => e instanceof SbobError && e.code === "ERR_ENFORCE_STATE_INVALID",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// seccomp (TDS 14.2)
// ---------------------------------------------------------------------------

test("seccomp: audit -> SCMP_ACT_LOG, enforce -> SCMP_ACT_ERRNO, full blocklist", () => {
  const ir = redisIR();
  const audit = JSON.parse(seccompProfile(ir, "audit").content) as any;
  assert.equal(audit.defaultAction, "SCMP_ACT_ALLOW");
  assert.equal(audit.syscalls[0].action, "SCMP_ACT_LOG");
  const enforce = JSON.parse(seccompProfile(ir, "enforce").content) as any;
  assert.equal(enforce.syscalls[0].action, "SCMP_ACT_ERRNO");
  const names = audit.syscalls[0].names as string[];
  assert.deepEqual(names, [
    "init_module",
    "finit_module",
    "delete_module",
    "unshare",
    "setns",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "memfd_create",
  ]);
});

test("seccomp: containerAllowed removes the policy syscall surface", () => {
  const ir = redisIR();
  ir.rulePolicies = { processTracing: { containerAllowed: true } };
  const names = seccompBlocklist(ir).map((s) => s.syscall);
  assert.ok(!names.includes("ptrace"));
  assert.ok(!names.includes("process_vm_readv"));
  assert.ok(!names.includes("process_vm_writev"));
  assert.ok(names.includes("memfd_create"), "non-exempt policies untouched");
});

test("seccomp: systemd drop-in deny-list, audit comment", () => {
  const f = seccompSystemdDropin(redisIR(), "audit");
  assert.ok(f.path.includes("systemd/redis-seccomp.conf"));
  assert.ok(f.content.includes("SystemCallFilter=~init_module finit_module delete_module"));
  assert.ok(f.content.includes("memfd_create"));
  assert.ok(f.content.includes("[Service]"));
});

// ---------------------------------------------------------------------------
// AppArmor (TDS 14.3)
// ---------------------------------------------------------------------------

test("apparmor: ixr exec rules, deduped rwka perms, complain in audit", () => {
  const ir = redisIR();
  const f = apparmorProfile(ir, loadState("redis-audit.state.yaml"));
  assert.ok(f.content.includes("/usr/bin/redis-server ixr,"));
  assert.ok(f.content.includes("/bin/sh ixr,"));
  assert.ok(f.content.includes("/data/** rwka,"), "O_RDONLY|O_WRONLY|O_CREAT|O_APPEND -> r,w,k,a");
  assert.ok(!f.content.includes("rwwkwa"), "no duplicated permission letter");
  assert.ok(f.content.includes("/etc/resolv.conf r,"));
  assert.ok(f.content.includes("complain"));
});

test("apparmor: enforcing sections drop the complain flag", () => {
  const ir = redisIR();
  const f = apparmorProfile(ir, loadState("redis-enforce.state.yaml"));
  assert.ok(!f.content.includes("complain"), "no complain flag when execs is enforcing");
  assert.ok(f.content.includes("flags=(attach_disconnected)"), "attachment flags survive");
});

test("apparmor: monitor sections emit commented inert rules only", () => {
  const ir = redisIR();
  const f = apparmorProfile(ir, loadState("redis-mixed.state.yaml"));
  assert.ok(f.content.includes("monitor (inert): /data/**"), "opens in monitor -> commented glob");
  assert.ok(!/^  \/data\*\* rwka,/m.test(f.content), "no live rule for a monitor section");
  assert.ok(f.content.includes("/usr/bin/redis-server ixr,"), "execs (enforce) stays live");
});

// ---------------------------------------------------------------------------
// NetworkPolicy (TDS 14.4)
// ---------------------------------------------------------------------------

test("networkpolicy: ipBlock peers, ports, enforce-mode annotation", () => {
  const f = networkPolicy(redisIR(), loadState("redis-enforce.state.yaml"));
  assert.ok(f.path.endsWith("networkpolicy/redis.yaml"));
  assert.ok(f.content.includes("cidr: 10.96.0.10/32"));
  assert.ok(f.content.includes("protocol: UDP"));
  assert.ok(f.content.includes("port: 53"));
  assert.ok(f.content.includes("cidr: 162.0.217.171/32"));
  assert.ok(f.content.includes("cidr: 10.244.0.0/16"));
  assert.ok(f.content.includes("sbob.k8sstormcenter.io/mode: \"enforce\""));
  assert.ok(f.content.includes("namespace: cache-tier"));
  assert.ok(f.content.includes("dnsNames not evaluable"), "DNS-NAME blind documented in-band");
});

test("networkpolicy: audit mode must not be applied live", () => {
  const f = networkPolicy(redisIR(), loadState("redis-audit.state.yaml"));
  assert.ok(f.content.includes("sbob.k8sstormcenter.io/mode: \"audit\""));
  assert.ok(f.content.includes("Calico staged policy or --dry-run=server only"));
});

test("networkpolicy: podSelector/namespaceSelector peers render (k8sPeer closure)", () => {
  const ir = redisIR();
  const peerEntry: NetCompiled = {
    addrEntries: [],
    anyIp: false,
    dnsPatterns: [],
    dnsExact: [],
    ports: [],
    k8sPeer: true,
    source: {
      identifier: "cache-pods",
      podSelector: { matchLabels: { app: "frontend" } },
      namespaceSelector: { matchLabels: { team: "cache" } },
      ports: [{ protocol: "TCP", port: 8080 }],
    },
  };
  ir.sections.egress!.entries.push(peerEntry);
  const model = npRuleModel(ir, loadState("redis-audit.state.yaml")) as any;
  const rule = model.egress.find((r: any) => Array.isArray(r.peers) && r.peers.some((p: any) => p.podSelector));
  assert.ok(rule, "label-selector rule in the model");
  const peer = rule.peers.find((p: any) => p.podSelector);
  assert.deepEqual(peer.namespaceSelector, { matchLabels: { team: "cache" } });
  assert.deepEqual(peer.podSelector, { matchLabels: { app: "frontend" } });
  assert.deepEqual(rule.ports, [{ protocol: "TCP", port: 8080 }]);

  const np = networkPolicy(ir, loadState("redis-enforce.state.yaml")).content;
  assert.ok(np.includes("podSelector:"), "podSelector peer in the live policy");
  assert.ok(np.includes("namespaceSelector:"), "namespaceSelector peer in the live policy");
  assert.ok(np.includes("app: frontend"));
});

test("np-diff: missing and extra rules, canonical detail", () => {
  const declared = npRuleModel(redisIR(), loadState("redis-enforce.state.yaml"));
  const enforced = JSON.parse(readFileSync(FIX("redis-np-enforced.json"), "utf8"));
  const drift = npDiff(declared, enforced);
  assert.equal(drift.length, 2);
  assert.ok(drift.every((d) => d.kind === "missing-rule"));
  assert.ok(drift.some((d) => d.direction === "egress" && d.detail.includes("162.0.217.171/32")));
  assert.ok(drift.some((d) => d.direction === "ingress" && d.detail.includes("10.244.0.0/16")));

  // an enforced-but-not-declared rule surfaces as extra-rule
  const extra = [
    ...enforced.egress,
    { peers: [{ ipBlock: { cidr: "203.0.113.9/32" } }], ports: [{ protocol: "TCP", port: 8080 }] },
  ];
  const drift2 = npDiff(declared, { egress: extra, ingress: enforced.ingress });
  assert.equal(drift2.filter((d) => d.kind === "extra-rule").length, 1);
  assert.ok(drift2.find((d) => d.kind === "extra-rule")!.detail.includes("203.0.113.9/32"));
});

// ---------------------------------------------------------------------------
// AppLocker (TDS 14.5)
// ---------------------------------------------------------------------------

test("applocker: deterministic uuid-v5 rule ids and mode transitions", () => {
  const ir = redisIR();
  const enforceState = loadState("redis-enforce.state.yaml");
  const f1 = applockerPolicy(ir, enforceState);
  const f2 = applockerPolicy(redisIR(), enforceState);
  assert.equal(f1.content, f2.content, "deterministic across fresh runs");
  assert.ok(f1.content.includes('EnforcementMode="Enabled"'));
  assert.ok(f1.content.includes("/usr/bin/redis-server"));
  assert.ok(f1.content.includes("/bin/sh"));
  const id = /Id="(\{[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\})"/.exec(f1.content);
  assert.ok(id, "RFC-4122 v5 GUID rule ids");

  assert.ok(applockerPolicy(ir, loadState("redis-audit.state.yaml")).content.includes('EnforcementMode="AuditMode"'));
  assert.ok(
    applockerPolicy(ir, parseEnforceState("workload: redis\nstate: monitor\n")).content.includes(
      'EnforcementMode="NotConfigured"',
    ),
  );

  const opens = (f1.content.match(/<FileRule /g) ?? []).length;
  const closes = (f1.content.match(/<\/FileRule>/g) ?? []).length;
  assert.equal(opens, closes, "well-formed FileRule elements");
});

// ---------------------------------------------------------------------------
// active responses + telemetry (TDS 14.1, 14.6)
// ---------------------------------------------------------------------------

test("active responses: disabled unless the section enforces", () => {
  const ir = redisIR();
  const conf = (fixture: string) => activeResponseConf(ir, loadState(fixture), makeAllocator("redis", 0)).content;
  const auditConf = conf("redis-audit.state.yaml");
  assert.ok(auditConf.includes("<rules_id>100011</rules_id>"), "exec drift rule");
  assert.ok(auditConf.includes("<rules_id>100031</rules_id>"), "egress drift rule");
  assert.ok(auditConf.includes("<rules_id>100041</rules_id>"), "ingress drift rule");
  assert.equal((auditConf.match(/<disabled>yes<\/disabled>/g) ?? []).length, 3, "all disabled in audit");

  const enforceConf = conf("redis-enforce.state.yaml");
  assert.equal((enforceConf.match(/<disabled>no<\/disabled>/g) ?? []).length, 3, "all live when enforcing");
  assert.ok(enforceConf.includes("<command>sbob-redis-process-kill</command>"));
  assert.ok(enforceConf.includes("<command>firewall-drop</command>"));

  const mixed = conf("redis-mixed.state.yaml");
  const blocks = mixed.split("<active-response>").slice(1);
  assert.equal(blocks.length, 3);
  assert.ok(blocks[0].includes("execs: enforce") && blocks[0].includes("<disabled>no</disabled>"));
  assert.ok(blocks[1].includes("egress: audit") && blocks[1].includes("<disabled>yes</disabled>"));
});

test("telemetry rule: (11,1) -> 100111, fires on the enforce localfile", () => {
  const f = enforceTelemetryRule(redisIR(), makeAllocator("redis", 0));
  assert.ok(f.path.endsWith("100000_redis_enforce.xml"));
  assert.ok(f.content.includes('<rule id="100111" level="10">'));
  assert.ok(f.content.includes('^redis$'));
  assert.ok(f.content.includes("^process-kill(?:-revert|-failed)?$|^firewall-drop$"));
  assert.ok(f.content.includes("sbob-enforce.log"));
});

test("process-kill script: reverts on delete, writes telemetry, fails honestly", () => {
  const f = processKillScript(redisIR());
  assert.ok(f.path.endsWith("sbob-redis-process-kill.sh"));
  assert.ok(f.content.includes('"action":"process-kill-revert"'));
  assert.ok(f.content.includes('"action":"process-kill-failed"'));
  assert.ok(f.content.includes("kill -9"));
  assert.ok(f.content.includes(">> /var/ossec/logs/sbob-enforce.log"));
  assert.ok(f.content.includes("ACTION=$1"));
});

// ---------------------------------------------------------------------------
// bundle orchestration + CLI
// ---------------------------------------------------------------------------

test("bundle: k8s-node manifest summarizes state, artifacts, pending lab validation", () => {
  const ir = redisIR();
  const state = loadState("redis-enforce.state.yaml");
  const enforcedNp = JSON.parse(readFileSync(FIX("redis-np-enforced.json"), "utf8"));
  const result = generateEnforceBundle(ir, state, makeAllocator("redis", 0), { target: "k8s-node", enforcedNp });
  const manifest = JSON.parse(result.files.find((f) => f.path === "redis-enforce.manifest.json")!.content) as any;
  assert.equal(manifest.state.default, "audit");
  assert.deepEqual(manifest.state.enforcing, ["execs", "egress", "ingress"]);
  assert.equal(manifest.labValidation, "pending");
  assert.ok(manifest.artifacts.includes("enforcement/sbob/redis/seccomp/redis.json"));
  assert.ok(manifest.artifacts.includes("enforcement/sbob/redis/networkpolicy/redis-np-diff.json"));
  assert.ok(result.notes.some((n) => n.startsWith("np-diff: 2 drifted")));
});

test("bundle: windows ships conf/doc only — no process-kill script, no seccomp", () => {
  const result = generateEnforceBundle(redisIR(), loadState("redis-enforce.state.yaml"), makeAllocator("redis", 0), { target: "windows" });
  assert.ok(result.files.some((f) => f.path.endsWith("applocker/redis.xml")));
  assert.ok(result.files.every((f) => !f.path.includes("process-kill.sh")));
  assert.ok(result.files.every((f) => !f.path.includes("seccomp")));
});

test("bundle: monitor global state emits no seccomp and no live enforcement", () => {
  const state = parseEnforceState("workload: redis\nstate: monitor\n");
  const k8s = generateEnforceBundle(redisIR(), state, makeAllocator("redis", 0), { target: "k8s-node" });
  assert.ok(k8s.files.every((f) => !f.path.includes("seccomp")));
  assert.ok(k8s.files.every((f) => !f.path.includes("networkpolicy")), "net sections monitor -> no NP");
  assert.ok(k8s.notes.some((n) => n.includes("seccomp: not emitted")));
});

test("runEnforce: end-to-end k8s-node + np drift exit signal", async () => {
  const dir = mkdtempSync(join(tmpdir(), "m7-e2e-"));
  try {
    const enforcedNpPath = FIX("redis-np-enforced.json");
    const result = await runEnforce(REDIS, {
      registryPath: "docs/sbob-registry.yaml",
      outDir: join(dir, "out"),
      target: "k8s-node",
      statePath: FIX("redis-enforce.state.yaml"),
      enforcedNpPath,
      skipSignatureVerify: true,
      confirmNone: [],
    });
    assert.equal(result.workload, "redis");
    assert.equal(result.slot, 0);
    assert.deepEqual(result.enforcing.sort(), ["egress", "execs", "ingress"]);
    assert.ok(result.files.includes("wazuh/rules/sbob/100000_redis_enforce.xml"));
    for (const rel of result.files) {
      assert.ok(existsSync(join(dir, "out", rel)), `file written: ${rel}`);
    }
    assert.equal(result.npDrift, 2, "missing stripe egress + declared ingress absent from the live policy");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runEnforce: clean enforced NP -> zero drift, exit 0 path", async () => {
  const dir = mkdtempSync(join(tmpdir(), "m7-clean-"));
  try {
    const cleanNp = join(dir, "clean-np.json");
    writeFileSync(
      cleanNp,
      JSON.stringify({
        egress: [
          { peers: [{ ipBlock: { cidr: "10.96.0.10/32" } }], ports: [{ protocol: "UDP", port: 53 }] },
          { peers: [{ ipBlock: { cidr: "162.0.217.171/32" } }], ports: [{ protocol: "TCP", port: 443 }] },
        ],
        ingress: [
          { peers: [{ ipBlock: { cidr: "10.244.0.0/16" } }], ports: [{ protocol: "TCP", port: 6379 }] },
        ],
      }),
    );
    const result = await runEnforce(REDIS, {
      registryPath: "docs/sbob-registry.yaml",
      outDir: join(dir, "out"),
      target: "k8s-node",
      statePath: FIX("redis-enforce.state.yaml"),
      enforcedNpPath: cleanNp,
      skipSignatureVerify: true,
      confirmNone: [],
    });
    assert.equal(result.npDrift, 0);
    assert.ok(result.files.includes("enforcement/sbob/redis/networkpolicy/redis-np-diff.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("determinism: two fresh enforce bundles are byte-identical", () => {
  const state = loadState("redis-enforce.state.yaml");
  const enforcedNp = JSON.parse(readFileSync(FIX("redis-np-enforced.json"), "utf8"));
  const run = () =>
    generateEnforceBundle(redisIR(), state, makeAllocator("redis", 0), { target: "k8s-node", enforcedNp });
  const a = run();
  const b = run();
  assert.deepEqual(a.files, b.files);
  assert.deepEqual(a.notes, b.notes);
});

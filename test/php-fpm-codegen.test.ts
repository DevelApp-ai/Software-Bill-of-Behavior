/**
 * PHP2Shell scenario tests (issue #23, docs/php2shell-scenario.md) — the
 * php-fpm SBoB (slot 1) maps the two October 2026 PHP RCEs (CVE-2026-109618
 * in-worker RCE, CVE-2026-109619 stale-global-state RCE) onto SBoB drift:
 * php-fpm declares a single exec and never shells out, so the post-exploit
 * behaviors — /bin/sh spawn, webshell drop, reverse-shell C2 connect — are
 * drift by definition, regardless of which CVE was the entry vector.
 *
 * Asserts the slot-1 rule band (1001xx), the fail-closed execs CDB (any
 * /bin/sh exec is drift), the corpus mapping in test/corpus/php-*.audit and
 * the enforcement artifacts that would have BLOCKED the behavior (AppArmor
 * exec allowlist, NetworkPolicy C2 deny, seccomp memfd_create).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { lintIR } from "../src/lint.ts";
import { makeAllocator } from "../src/ruleids.ts";
import type { IR } from "../src/types.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { transpile } from "../src/transpile.ts";
import { parseEnforceState } from "../src/enforce.ts";
import { apparmorProfile } from "../src/codegen/apparmor.ts";
import { networkPolicy, npRuleModel } from "../src/codegen/networkpolicy.ts";
import { seccompProfile, seccompBlocklist } from "../src/codegen/seccomp.ts";
import { activeResponseConf, generateEnforceBundle } from "../src/codegen/enforcement.ts";

const SBOB = new URL("../sbobs/php-fpm.yaml", import.meta.url).pathname;
const REGISTRY = new URL("../docs/sbob-registry.yaml", import.meta.url).pathname;
const CORPUS = (f: string) => new URL(`../test/corpus/${f}`, import.meta.url).pathname;

function phpIR(): IR {
  const parsed = parseYaml(readFileSync(SBOB, "utf8"));
  const ir = buildIR(validateSbob(parsed), parsed);
  lintIR(ir, { confirmNone: [], requireScope: true });
  return ir;
}

function phpBundle() {
  return generateLinuxBundle(phpIR(), makeAllocator("php-fpm", 1));
}

function byPath(files: ReturnType<typeof generateLinuxBundle>) {
  return new Map(files.map((f) => [f.path, f.content]));
}

// ---------------------------------------------------------------------------
// slot-1 rule band (TDS 6.1): 100000 + slot*100 + section*10 + variant
// ---------------------------------------------------------------------------

test("php-fpm bundle has the documented file structure at slot 1", () => {
  const paths = phpBundle().map((f) => f.path).sort();
  assert.deepEqual(paths, [
    "php-fpm.manifest.json",
    "wazuh/agent-conf/sbob/php-fpm-audit-digest.sh",
    "wazuh/agent-conf/sbob/php-fpm.xml",
    "wazuh/audit/sbob/php-fpm.rules",
    "wazuh/decoders/sbob/php-fpm.xml",
    "wazuh/lists/sbob/php-fpm/egress_addrs",
    "wazuh/lists/sbob/php-fpm/execs",
    "wazuh/lists/sbob/php-fpm/ingress_addrs",
    "wazuh/lists/sbob/php-fpm/opens",
    "wazuh/rules/sbob/100100_php-fpm_linux.xml",
  ]);
});

test("drift rules land on the slot-1 band: 100111/100121/100131 + sustained", () => {
  const xml = byPath(phpBundle()).get("wazuh/rules/sbob/100100_php-fpm_linux.xml")!;
  // base chain
  assert.ok(xml.includes('<rule id="100100" level="0">'));
  assert.ok(xml.includes('<rule id="100110" level="0">'));
  // exec drift (CVE-2026-109618 in-worker RCE -> /bin/sh spawn)
  assert.ok(xml.includes('<rule id="100111" level="9">'));
  assert.ok(xml.includes('<rule id="100112" level="12">'));
  // open drift (webshell drop to /var/tmp)
  assert.ok(xml.includes('<rule id="100121" level="9">'));
  // connect drift (reverse shell / C2, CVE-2026-109619)
  assert.ok(xml.includes('<rule id="100131" level="9">'));
  // port allowlist carries only the declared memcache port
  assert.ok(xml.includes("^(?!(?:11211)$)"), "negated port alternation for 11211");
  // signature pack at (6,x): 100160-100163 — memfd (fileless variant) included
  assert.ok(xml.includes('<rule id="100163" level="10">'));
  assert.ok(xml.match(/<rule id="100163"[\s\S]*?sbob-memfd/) !== null, "memfd signature keyed on sbob-memfd");
  // slot 0 (redis) band must be untouched
  assert.ok(!xml.includes('id="100011"'));
  // MITRE mapping
  assert.ok(xml.includes("T1059"));
  assert.ok(xml.includes("T1005"));
  assert.ok(xml.includes("T1071"));
  assert.ok(xml.includes("T1620"), "memfd signature carries T1620");
});

test("fail-closed execs: only the php-fpm binary is declared — any /bin/sh is drift", () => {
  const m = byPath(phpBundle());
  const execs = m.get("wazuh/lists/sbob/php-fpm/execs")!;
  assert.ok(execs.includes("/usr/local/sbin/php-fpm:"));
  assert.ok(!execs.includes("/bin/sh"), "no shell exec declared — the PHP2Shell catch by construction");
  assert.equal((execs.match(/^[^#].*$/gm) ?? []).length, 1, "exactly one exec allowlist entry");
  const audit = m.get("wazuh/audit/sbob/php-fpm.rules")!;
  assert.ok(audit.includes("-F exe=/usr/local/sbin/php-fpm -k sbob-exec-php-fpm"));
  assert.ok(audit.includes("-S execve"));
  // Mode A scopes exec/open/connect telemetry to the php-fpm binary
  assert.ok(audit.includes("-k sbob-open-php-fpm"));
  assert.ok(audit.includes("-k sbob-connect-php-fpm"));
});

test("opens allowlist: web root + sessions wildcards live in the rule regex, resolv.conf in CDB", () => {
  const m = byPath(phpBundle());
  const opens = m.get("wazuh/lists/sbob/php-fpm/opens")!;
  assert.ok(opens.includes("/etc/resolv.conf:"));
  assert.ok(!opens.includes("/var/www"), "wildcarded web root is not a CDB entry");
  const xml = m.get("wazuh/rules/sbob/100100_php-fpm_linux.xml")!;
  assert.ok(
    xml.includes("^(?!(?:/var/www/html/[^/]+(?:/[^/]+)*|/var/lib/php/sessions/[^/]+(?:/[^/]+)*)$)"),
    "negated allow-alternation covers the web root and session dir",
  );
});

test("egress/ingress CDB: internal memcache declared, nginx frontends inbound", () => {
  const m = byPath(phpBundle());
  const egress = m.get("wazuh/lists/sbob/php-fpm/egress_addrs")!;
  assert.ok(egress.includes("10.96.100.10/32:internal-memcache"));
  const ingress = m.get("wazuh/lists/sbob/php-fpm/ingress_addrs")!;
  assert.ok(ingress.includes("10.244.0.0/16:nginx-frontends"));
  assert.ok(ingress.includes("10.244.0.0/16:nginx-frontends"));
});

test("manifest carries the web-tier workload scope and pending lab validation", () => {
  const manifest = JSON.parse(byPath(phpBundle()).get("php-fpm.manifest.json")!);
  assert.equal(manifest.workload.name, "php-fpm");
  assert.equal(manifest.workload.namespace, "web-tier");
  assert.deepEqual(manifest.workload.scope.linuxGroups, ["sbob-php-fpm"]);
  assert.equal(manifest.labValidation, "pending");
});

test("determinism: two fresh php-fpm bundles are byte-identical", () => {
  const a = phpBundle();
  const b = phpBundle();
  assert.deepEqual(a, b);
});

// ---------------------------------------------------------------------------
// corpus mapping (test/corpus/php-{benign,drift}.audit — the PHP2Shell lines)
// ---------------------------------------------------------------------------

/** AF_INET sockaddr hex -> {ip, port} the way the TDS 7.3.1 decode will. */
function decodeSaddr(hex: string): { ip: string; port: number } {
  assert.ok(hex.startsWith("0200"), "AF_INET saddr");
  return {
    port: parseInt(hex.slice(4, 8), 16),
    ip: [8, 10, 12, 14].map((i) => parseInt(hex.slice(i, i + 2), 16)).join("."),
  };
}

test("drift corpus maps the two PHP2Shell CVEs to the mapped rule inputs", () => {
  const drift = readFileSync(CORPUS("php-drift.audit"), "utf8");
  // CVE-2026-109618: in-worker RCE — the hijacked worker spawns /bin/sh (-> 100111)
  assert.ok(drift.includes('exe="/bin/sh"'));
  assert.ok(drift.includes('key="sbob-exec-php-fpm"'));
  assert.ok(drift.includes('a0="/bin/sh"'));
  // webshell drop to an undeclared path (-> 100121)
  assert.ok(drift.includes('name="/var/tmp/.php2shell.php"'));
  // CVE-2026-109619: reverse shell to an undeclared C2 (-> 100131)
  const c2 = /saddr=([0-9A-F]+)/.exec(drift)![1]!;
  const { ip, port } = decodeSaddr(c2);
  assert.equal(ip, "45.155.148.12");
  assert.equal(port, 4444);
  // fileless variant: memfd_create signature (-> 100163)
  assert.ok(drift.includes("syscall=319"));
  assert.ok(drift.includes('key="sbob-memfd"'));
});

test("benign corpus stays inside the declared contract", () => {
  const benign = readFileSync(CORPUS("php-benign.audit"), "utf8");
  // only the declared exec appears
  assert.ok(benign.includes('exe="/usr/local/sbin/php-fpm"'));
  assert.ok(!benign.includes('exe="/bin/sh"'));
  // app files read-only, session write, resolver read — all declared paths
  assert.ok(benign.includes('name="/var/www/html/index.php"'));
  assert.ok(benign.includes('name="/var/lib/php/sessions/sess_9a8b7c6d5e4f3a2b1c0d"'));
  assert.ok(benign.includes('name="/etc/resolv.conf"'));
  // the only connect goes to the declared memcache peer
  const saddr = /saddr=([0-9A-F]+)/.exec(benign)![1]!;
  const { ip, port } = decodeSaddr(saddr);
  assert.equal(ip, "10.96.100.10", "declared internal-memcache");
  assert.equal(port, 11211);
});

test("corpus audit keys match the generated audit fragment (logtest contract)", () => {
  const fragment = byPath(phpBundle()).get("wazuh/audit/sbob/php-fpm.rules")!;
  for (const key of ["sbob-exec-php-fpm", "sbob-open-php-fpm", "sbob-connect-php-fpm", "sbob-memfd"]) {
    assert.ok(fragment.includes(`-k ${key}`), `fragment emits ${key}`);
    const inCorpus =
      readFileSync(CORPUS("php-drift.audit"), "utf8").includes(key) ||
      readFileSync(CORPUS("php-benign.audit"), "utf8").includes(key);
    assert.ok(inCorpus, `corpus carries ${key}`);
  }
});

// ---------------------------------------------------------------------------
// enforcement: what would have BLOCKED the PHP2Shell behavior (TDS 14, M7)
// ---------------------------------------------------------------------------

/** php-fpm ladder: audit default, execs+egress+ingress graduated to enforce. */
function phpEnforceState() {
  return parseEnforceState([
    "workload: php-fpm",
    "state: audit",
    "sections:",
    "  execs: enforce",
    "  opens: audit",
    "  egress: enforce",
    "  ingress: enforce",
    "auditRecords:",
    "  execs:",
    '    started: "2026-10-01"',
    "    windowDays: 14",
    "    incidents: 0",
    "  egress:",
    '    started: "2026-10-01"',
    "    windowDays: 14",
    "    incidents: 0",
    "  ingress:",
    '    started: "2026-10-01"',
    "    windowDays: 14",
    "    incidents: 0",
    "",
  ].join("\n"));
}

test("apparmor: the exec allowlist DENIES the php2shell /bin/sh spawn when enforcing", () => {
  const f = apparmorProfile(phpIR(), phpEnforceState());
  assert.ok(f.content.includes("/usr/local/sbin/php-fpm ixr,"), "declared exec allowed");
  assert.ok(!f.content.includes("/bin/sh"), "no shell rule — /bin/sh exec is denied in enforce mode");
  assert.ok(!f.content.includes("complain"), "execs enforcing -> blocking profile");
});

test("networkpolicy: C2 egress denied — only the memcache peer leaves the pod", () => {
  const ir = phpIR();
  const state = phpEnforceState();
  const f = networkPolicy(ir, state);
  assert.ok(f.content.includes("cidr: 10.96.100.10/32"));
  assert.ok(f.content.includes("port: 11211"));
  assert.ok(f.content.includes("cidr: 10.244.0.0/16"), "declared nginx ingress stays");
  assert.ok(f.content.includes("port: 9000"));
  assert.ok(!f.content.includes("45.155.148.12"), "the C2 ip never enters the policy");
  assert.ok(f.content.includes("namespace: web-tier"));
  assert.ok(
    f.content.includes('sbob.k8sstormcenter.io/mode: "enforce"'),
    "egress+ingress enforcing -> live policy (undeclared traffic blocked)",
  );
  // the declared model has exactly one egress rule — a C2 rule would be extra
  const model = npRuleModel(ir, state) as { egress: unknown[] };
  assert.equal(model.egress.length, 1);
});

test("seccomp: the memfd_create surface is on the blocklist (fileless variant)", () => {
  const names = seccompBlocklist(phpIR()).map((s) => s.syscall);
  assert.ok(names.includes("memfd_create"));
  const profile = JSON.parse(seccompProfile(phpIR(), "enforce").content) as any;
  assert.equal(profile.syscalls[0].action, "SCMP_ACT_ERRNO");
  assert.ok((profile.syscalls[0].names as string[]).includes("memfd_create"));
});

test("active responses bind the slot-1 drift rules (process-kill on 100111)", () => {
  const conf = activeResponseConf(phpIR(), phpEnforceState(), makeAllocator("php-fpm", 1)).content;
  assert.ok(conf.includes("<rules_id>100111</rules_id>"), "exec drift rule id");
  assert.ok(conf.includes("<rules_id>100131</rules_id>"), "egress drift rule id");
  assert.ok(conf.includes("<rules_id>100141</rules_id>"), "ingress drift rule id");
  assert.ok(conf.includes("<command>sbob-php-fpm-process-kill</command>"));
  assert.ok((conf.match(/<disabled>no<\/disabled>/g) ?? []).length === 3, "all three ARs live when enforcing");
});

test("enforce bundle: linux target ships apparmor + seccomp drop-in + telemetry", () => {
  const result = generateEnforceBundle(phpIR(), phpEnforceState(), makeAllocator("php-fpm", 1), { target: "linux" });
  assert.deepEqual(result.enforcing.sort(), ["egress", "execs", "ingress"]);
  const manifest = JSON.parse(result.files.find((f) => f.path === "php-fpm-enforce.manifest.json")!.content) as any;
  assert.ok(manifest.artifacts.includes("enforcement/sbob/php-fpm/apparmor/php-fpm.profile"));
  assert.ok(manifest.artifacts.includes("enforcement/sbob/php-fpm/systemd/php-fpm-seccomp.conf"));
  assert.ok(manifest.artifacts.includes("wazuh/agent-conf/sbob/php-fpm-ar.xml"));
  assert.equal(manifest.labValidation, "pending");
});

// ---------------------------------------------------------------------------
// CLI pipeline: php-fpm against the committed registry (slot 1 pinned)
// ---------------------------------------------------------------------------

test("transpile: php-fpm allocates no new slot — registry already carries slot 1", async () => {
  const dir = mkdtempSync(join(tmpdir(), "php-cli-"));
  try {
    const regCopy = join(dir, "registry.yaml");
    writeFileSync(regCopy, readFileSync(REGISTRY, "utf8"));
    const result = await transpile([SBOB], {
      registryPath: regCopy,
      outDir: join(dir, "out"),
      target: "linux",
      skipSignatureVerify: true,
      confirmNone: [],
    });
    assert.equal(result.workloads.length, 1);
    assert.equal(result.workloads[0]!.name, "php-fpm");
    assert.equal(result.workloads[0]!.slot, 1);
    assert.ok(result.workloads[0]!.files.includes("wazuh/rules/sbob/100100_php-fpm_linux.xml"));
    assert.equal(result.registryUpdated, false, "php-fpm: slot 1 is committed — no registry evolution");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

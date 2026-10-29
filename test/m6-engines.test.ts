/**
 * M6 Phase-2 engine codegen (TDS 13, issue #7) — Sigma, Velociraptor, MDE,
 * Falco artifacts, Envoy endpoints[] ingestion and the engine blind-spot
 * matrix gates.
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
import { generateSigmaBundle } from "../src/codegen/sigma.ts";
import { generateVelociraptorBundle } from "../src/codegen/velociraptor.ts";
import { generateMdeBundle } from "../src/codegen/mde.ts";
import { generateFalcoBundle } from "../src/codegen/falco.ts";
import { generateK8sNodeBundle } from "../src/codegen/k8s.ts";
import { parseEngineRows, runEngineMatrixCheck, ENGINE_STATUS } from "../src/enginescheck.ts";
import { parseMatrixRows } from "../src/attackcheck.ts";
import { buildCoverageMatrix } from "../src/coverage.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;
const SUITE = new URL("../docs/upstream-redis-attacks.yaml", import.meta.url).pathname;
const ATTACK_MATRIX = new URL("../docs/attack-matrix.md", import.meta.url).pathname;
const ENGINE_MATRIX = new URL("../docs/engine-matrix.md", import.meta.url).pathname;

function redisIR(): IR {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  return buildIR(validateSbob(parsed), parsed);
}

function pick(files: { path: string; content: string }[], path: string): string {
  const f = files.find((x) => x.path === path);
  assert.ok(f, `bundle file ${path}`);
  return f.content;
}

// --- Sigma -----------------------------------------------------------------

test("sigma bundle: 7 rule files + manifest, deterministic RFC-4122 v5 UUIDs", () => {
  const ir = redisIR();
  const a = generateSigmaBundle(ir);
  const b = generateSigmaBundle(redisIR());
  const paths = a.map((f) => f.path);
  assert.deepEqual(paths.filter((p) => p.startsWith("sigma/sbob/")), [
    "sigma/sbob/redis_execs_linux.yml",
    "sigma/sbob/redis_execs_windows.yml",
    "sigma/sbob/redis_opens_linux.yml",
    "sigma/sbob/redis_opens_windows.yml",
    "sigma/sbob/redis_egress_linux.yml",
    "sigma/sbob/redis_egress_windows.yml",
    "sigma/sbob/redis_dns_windows.yml",
  ]);
  assert.ok(paths.includes("redis.manifest.json"));
  assert.deepEqual(a, b); // deterministic — no Date.now/Math.random leakage

  for (const f of a.filter((x) => x.path.endsWith(".yml"))) {
    const id = /^id: ([0-9a-f-]+)$/m.exec(f.content)![1]!;
    assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }
});

test("sigma execs_linux: auditd execve selection + inverted execs[] filter", () => {
  const yml = pick(generateSigmaBundle(redisIR()), "sigma/sbob/redis_execs_linux.yml");
  assert.match(yml, /product: linux/);
  assert.match(yml, /service: auditd/);
  assert.match(yml, /syscall: execve/);
  assert.match(yml, /"\/usr\/bin\/redis-server"/);
  assert.match(yml, /"\/bin\/sh"/);
  assert.match(yml, /condition: selection and not filter_sbob_execs/);
  assert.match(yml, /sbob\.execs_linux/);
});

test("sigma egress_linux: per-peer filter blocks with 1 of filter_peer_*", () => {
  const yml = pick(generateSigmaBundle(redisIR()), "sigma/sbob/redis_egress_linux.yml");
  assert.match(yml, /filter_peer_0:/);
  assert.match(yml, /filter_peer_1:/);
  assert.match(yml, /"10\.96\.0\.10"/);
  assert.match(yml, /- 53/);
  assert.match(yml, /condition: selection and not 1 of filter_peer_\*/);
});

test("sigma dns_windows: Sysmon EID 22 closes DNS-NAME on the windows plane", () => {
  const yml = pick(generateSigmaBundle(redisIR()), "sigma/sbob/redis_dns_windows.yml");
  assert.match(yml, /product: windows/);
  assert.match(yml, /EventID: 22/);
  assert.match(yml, /QueryName:/);
  assert.match(yml, /stripe/); // dns glob escaped pattern (\.dots) — needle kept dot-free for robustness
  assert.match(yml, /condition: selection and not filter_sbob_dns/);
});

test("sigma opens_windows: EID 11 file-create partial semantics", () => {
  const yml = pick(generateSigmaBundle(redisIR()), "sigma/sbob/redis_opens_windows.yml");
  assert.match(yml, /EventID: 11/);
  assert.match(yml, /TargetFilename:/);
});

test("sigma titles are quoted scalars — unquoted \": \" breaks strict YAML (pySigma/SigmaHQ)", () => {
  const files = generateSigmaBundle(redisIR()).filter((f) => f.path.endsWith(".yml"));
  assert.equal(files.length, 7);
  for (const f of files) {
    const title = /^title: (.+)$/m.exec(f.content)![1]!;
    assert.ok(title.startsWith('"') && title.endsWith('"'), `title of ${f.path} must be a double-quoted scalar`);
  }
});

// --- Velociraptor ------------------------------------------------------------

test("velociraptor artifact: pslist/netstat sweeps with RE2-safe anchored PCRE", () => {
  const yml = pick(generateVelociraptorBundle(redisIR()), "velociraptor/sbob/redis.yaml");
  assert.match(yml, /name: Custom\.SBoB\.Redis\.Conformance/);
  assert.match(yml, /FROM pslist\(\)/);
  assert.match(yml, /NOT Exe =~ '\^\(\?:\/usr\/bin\/redis-server\|\/bin\/sh\)\$'/);
  assert.match(yml, /FROM netstat\(\)/);
  assert.ok(
    yml.includes("NOT Raddr =~ '^(?:(?:10\\.96\\.0\\.10):(?:53)|(?:162\\.0\\.217\\.171):(?:443))$'"),
    "anchored per-pair netstat PCRE",
  );
  // RE2 rejects lookaheads and backreferences — the generated PCRE must not use them
  assert.ok(!/\(\?=\|\(\?!</.test(yml), "no lookahead in RE2 queries");
  assert.ok(!/\\[0-9]/.test(yml), "no backreferences in RE2 queries");
});

// --- MDE ----------------------------------------------------------------------

test("mde bundle: execs/opens/egress KQL hunts with pair conditions", () => {
  const files = generateMdeBundle(redisIR());
  assert.deepEqual(files.map((f) => f.path), [
    "mde/sbob/redis_execs.kql",
    "mde/sbob/redis_opens.kql",
    "mde/sbob/redis_egress.kql",
    "redis.manifest.json",
  ]);
  const execs = pick(files, "mde/sbob/redis_execs.kql");
  assert.match(execs, /DeviceProcessEvents/);
  assert.match(execs, /FolderPath in~ \("\/usr\/bin\/redis-server", "\/bin\/sh"\)/);
  const opens = pick(files, "mde/sbob/redis_opens.kql");
  assert.match(opens, /DeviceFileEvents/);
  assert.match(opens, /ActionType == "FileCreated"/);
  const egress = pick(files, "mde/sbob/redis_egress.kql");
  assert.match(egress, /DeviceNetworkEvents/);
  assert.match(egress, /ActionType == "ConnectionEstablished"/);
  assert.match(egress, /RemoteIP in~ \("10\.96\.0\.10"\) and RemotePort in \(53\)/);
  assert.match(egress, /RemoteIP in~ \("162\.0\.217\.171"\) and RemotePort in \(443\)/);
  assert.match(egress, /DNS-NAME documented blind/);
});

// --- Falco --------------------------------------------------------------------

test("falco bundle: lists, drift rules, daemonset, wazuh correlation rule 100103", () => {
  const files = generateFalcoBundle(redisIR(), makeAllocator("redis", 0));
  const paths = files.map((f) => f.path);
  assert.deepEqual(paths, [
    "falco/sbob/redis_rules.yaml",
    "falco/sbob/redis-daemonset.yaml",
    "wazuh/manager/sbob/redis-falco.md",
    "wazuh/rules/sbob/100000_redis_falco.xml",
    "redis.manifest.json",
  ]);
  const rules = pick(files, "falco/sbob/redis_rules.yaml");
  assert.match(rules, /- list: sbob_redis_execs/);
  assert.match(rules, /items: \[\/usr\/bin\/redis-server, \/bin\/sh\]/);
  assert.match(rules, /not proc\.exepath in \(sbob_redis_execs\) and not proc\.exepath pmatch \(sbob_redis_execs_patterns\)/);
  assert.match(rules, /evt\.type in \(connect\) and evt\.dir=< and fd\.typechar=4/);
  const ds = pick(files, "falco/sbob/redis-daemonset.yaml");
  assert.match(ds, /ConfigMap/);
  assert.match(ds, /FALCOSIDEKICK_WAZUH_URL/);
  const xml = pick(files, "wazuh/rules/sbob/100000_redis_falco.xml");
  assert.match(xml, /<rule id="100103" level="3">/);
  assert.match(xml, /name="output_fields\.container\.name" type="pcre2">\^redis\$/);
  assert.match(pick(files, "wazuh/manager/sbob/redis-falco.md"), /localfile/);
});

// --- Envoy endpoints[] ingestion (synthetic IR — redis has no endpoints) ------

function endpointsIR(): IR {
  const ir = redisIR();
  ir.sections.endpoints = [
    { endpoint: "/api/v1/ping", methods: ["GET"], direction: "inbound" },
    { endpoint: "https://internal-metrics:9090/metrics", methods: ["GET"], direction: "outbound" },
  ];
  return ir;
}

test("envoy: endpoints[] emits CDB allowlists, (9,1)/(9,2) rules and the ingestion doc", () => {
  const ir = endpointsIR();
  lintIR(ir, { confirmNone: [], requireScope: true }); // throws on lint failure
  const files = generateK8sNodeBundle(ir, makeAllocator("redis", 0));
  const paths = files.map((f) => f.path);
  assert.ok(paths.includes("wazuh/lists/sbob/redis/endpoints_in"));
  assert.ok(paths.includes("wazuh/lists/sbob/redis/endpoints_out"));
  assert.ok(paths.includes("wazuh/manager/sbob/redis-envoy.md"));
  assert.match(pick(files, "wazuh/lists/sbob/redis/endpoints_in"), /\/api\/v1\/ping:1/);

  const xml = files.find((f) => f.path.endsWith("_k8s-node.xml"))!.content;
  const inbound = new RegExp(`<rule id="100091"[^>]*>([\\s\\S]*?)</rule>`, "m").exec(xml);
  const outbound = new RegExp(`<rule id="100092"[^>]*>([\\s\\S]*?)</rule>`, "m").exec(xml);
  assert.ok(inbound, "endpoint inbound drift rule 100091");
  assert.ok(outbound, "endpoint outbound drift rule 100092");
  assert.ok(inbound[1]!.includes('<field name="direction" type="pcre2">^inbound$</field>'));
  assert.match(outbound[1]!, /sbob\/redis\/endpoints_out/);
  assert.match(xml, /<rule id="100091" level="9">/);

  assert.match(pick(files, "wazuh/manager/sbob/redis-envoy.md"), /json_format:/);
  assert.match(pick(files, "wazuh/manager/sbob/redis-envoy.md"), /ENVOY_L7/);
});

test("envoy: coverage matrix marks endpoints partial [ENVOY_L7] on k8s only", () => {
  const matrix = buildCoverageMatrix(endpointsIR());
  const endpoints = matrix.rows.find((r) => r.section === "endpoints")!;
  assert.ok(endpoints, "endpoints coverage row");
  assert.equal(endpoints.cells.k8s.status, "partial");
  assert.ok(endpoints.cells.k8s.reasons.includes("ENVOY_L7"));
  assert.equal(endpoints.cells.linux.status, "gap");
  // redis (no endpoints[]) stays a documented gap ENDPOINTS_L7, no envoy rules
  const redisMatrix = buildCoverageMatrix(redisIR());
  assert.equal(redisMatrix.rows.find((r) => r.section === "endpoints")!.cells.k8s.status, "absent");
  const redisFiles = generateK8sNodeBundle(redisIR(), makeAllocator("redis", 0));
  assert.ok(!redisFiles.some((f) => f.path.includes("endpoints_")), "no envoy artifacts without endpoints[]");
});

// --- Engine blind-spot matrix gates ------------------------------------------

test("engine matrix: committed doc accounts for all 62 suite attacks across 6 engines", () => {
  const suite = readFileSync(SUITE, "utf8");
  const engineMd = readFileSync(ENGINE_MATRIX, "utf8");
  const attackRows = parseMatrixRows(readFileSync(ATTACK_MATRIX, "utf8"));
  const result = runEngineMatrixCheck(suite, engineMd, attackRows, 6);
  assert.deepEqual(result.problems, []);
  assert.equal(result.attackCount, 62);
  assert.equal(result.rowCount, 62);
});

test("engine matrix: statuses restricted to detect/partial/blind/n-a", () => {
  const rows = parseEngineRows(readFileSync(ENGINE_MATRIX, "utf8"), 6);
  assert.equal(rows.size, 62);
  for (const row of rows.values()) {
    assert.equal(row.statuses.length, 6);
    for (const s of row.statuses) assert.ok((ENGINE_STATUS as readonly string[]).includes(s), `bad status "${s}" in #${row.num}`);
  }
});

test("engine matrix gate: detects missing rows, bad statuses and undocumented all-blind rows", () => {
  const suite = readFileSync(SUITE, "utf8");
  const engineMd = readFileSync(ENGINE_MATRIX, "utf8");
  const attackRows = parseMatrixRows(readFileSync(ATTACK_MATRIX, "utf8"));

  // 1. missing row
  const missing = engineMd.replace(/^\| 55 \|.*$/m, "");
  const r1 = runEngineMatrixCheck(suite, missing, attackRows, 6);
  assert.ok(r1.problems.some((p) => p.includes("recon-redis-cli-bigkeys")));

  // 2. invalid status token
  const bad = engineMd.replace(/^\| 55 \|(.*)\| detect \|(.*)$/m, (_m, a, b) => `| 55 |${a}| maybe |${b}`);
  const r2 = runEngineMatrixCheck(suite, bad, attackRows, 6);
  assert.ok(r2.problems.some((p) => p.includes('status "maybe"')));

  // 3. all-blind without a documented class (EXEC row → blind everywhere)
  const blinded = engineMd.replace(/^\| 55 \|(.*)$/m, (_m, rest) => `| 55 |${rest.replace(/detect/g, "blind")}`);
  const r3 = runEngineMatrixCheck(suite, blinded, attackRows, 6);
  assert.ok(r3.problems.some((p) => p.includes("no engine detects")), "EXEC row blinded everywhere must fail");

  // 4. documented-class row (FILELESS-EXE) may stay blind everywhere
  const l7 = engineMd.replace(/^\| 7 \|(.*)$/m, (_m, rest) => `| 7 |${rest.replace(/detect/g, "blind")}`);
  const r4 = runEngineMatrixCheck(suite, l7, attackRows, 6);
  assert.ok(!r4.problems.some((p) => p.includes("lua-fileless-memfd")), "documented-class blind must not fail the gate");
});

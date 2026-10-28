import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync, existsSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { makeAllocator } from "../src/ruleids.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { transpile } from "../src/transpile.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;
const REGISTRY = new URL("../docs/sbob-registry.yaml", import.meta.url).pathname;

function redisBundle() {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  const ir = buildIR(validateSbob(parsed), parsed);
  return generateLinuxBundle(ir, makeAllocator("redis", 0));
}

function byPath(files: ReturnType<typeof redisBundle>) {
  return new Map(files.map((f) => [f.path, f.content]));
}

// ---------------------------------------------------------------------------

test("redis bundle has the documented file structure", () => {
  const paths = redisBundle().map((f) => f.path).sort();
  assert.deepEqual(paths, [
    "redis.manifest.json",
    "wazuh/agent-conf/sbob/redis-audit-digest.sh",
    "wazuh/agent-conf/sbob/redis.xml",
    "wazuh/audit/sbob/redis.rules",
    "wazuh/decoders/sbob/redis.xml",
    "wazuh/lists/sbob/redis/egress_addrs",
    "wazuh/lists/sbob/redis/execs",
    "wazuh/lists/sbob/redis/ingress_addrs",
    "wazuh/lists/sbob/redis/opens",
    "wazuh/rules/sbob/100000_redis_linux.xml",
  ]);
});

test("codegen is deterministic: two independent runs are byte-identical", () => {
  const a = redisBundle();
  const b = redisBundle();
  assert.deepEqual(a, b);
});

test("full transpile pipeline is deterministic on disk (incl. checksums.txt)", async () => {
  const dirA = mkdtempSync(join(tmpdir(), "sbob-a-"));
  const dirB = mkdtempSync(join(tmpdir(), "sbob-b-"));
  const regA = join(dirA, "..", "registry-a.yaml"); // outside bundle dirs
  const regB = join(dirB, "..", "registry-b.yaml");
  // each run gets its own copy of the registry (registry file may be updated in place)
  const registrySource = readFileSync(REGISTRY, "utf8");
  const { writeFileSync } = await import("node:fs");
  writeFileSync(regA, registrySource);
  writeFileSync(regB, registrySource);
  const outA = join(dirA, "bundle");
  const outB = join(dirB, "bundle");
  const rA = await transpile([REDIS], {
    registryPath: regA, outDir: outA, target: "linux",
    skipSignatureVerify: true, confirmNone: [],
  });
  const rB = await transpile([REDIS], {
    registryPath: regB, outDir: outB, target: "linux",
    skipSignatureVerify: true, confirmNone: [],
  });
  assert.equal(rA.registryUpdated, false, "registry already has redis: slot 0, no update");
  assert.equal(rB.registryUpdated, false);

  /** recursive file listing with contents */
  function snapshot(dir: string, base = ""): Map<string, string> {
    const out = new Map<string, string>();
    for (const e of readdirSync(dir)) {
      const rel = base ? `${base}/${e}` : e;
      const abs = join(dir, e);
      if (statSync(abs).isDirectory()) {
        for (const [k, v] of snapshot(abs, rel)) out.set(k, v);
      } else {
        out.set(rel, readFileSync(abs, "utf8"));
      }
    }
    return out;
  }
  const snapA = snapshot(outA);
  const snapB = snapshot(outB);
  assert.ok(snapA.size >= 9, `bundle has >=9 files, got ${snapA.size}`);
  assert.deepEqual([...snapA.keys()].sort(), [...snapB.keys()].sort());
  for (const [k, v] of snapA) assert.equal(v, snapB.get(k), `file differs: ${k}`);
  assert.ok(snapA.has("checksums.txt"));
  rmSync(dirA, { recursive: true, force: true });
  rmSync(dirB, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------

test("audit fragment: Mode A exe-scoped execve for every declared exe", () => {
  const audit = byPath(redisBundle()).get("wazuh/audit/sbob/redis.rules")!;
  assert.ok(audit.includes("Mode A"), "Mode A banner present");
  for (const exe of ["/usr/bin/redis-server", "/bin/sh"]) {
    assert.ok(audit.includes(`-F exe=${exe} -k sbob-exec-redis`), `exe-scoped rule for ${exe}`);
  }
  assert.ok(audit.includes("-S execve"));
  assert.ok(audit.includes("-F arch=b64"));
  assert.ok(audit.includes("-F arch=b32"));
  // node-wide fallback (Mode B) must NOT appear when exact execs exist
  assert.ok(!audit.includes("-k sbob-exec\n"), "no unscoped Mode B key");
});

test("CDB lists: exact entries only; wildcards live in rule regexes", () => {
  const m = byPath(redisBundle());
  const execs = m.get("wazuh/lists/sbob/redis/execs")!;
  assert.ok(execs.includes("/usr/bin/redis-server:"));
  assert.ok(execs.includes("/bin/sh:"));
  const opens = m.get("wazuh/lists/sbob/redis/opens")!;
  assert.ok(opens.includes("/etc/resolv.conf:"));
  assert.ok(!opens.includes("/data"), "wildcarded /data/* is not a CDB entry");
  const egress = m.get("wazuh/lists/sbob/redis/egress_addrs")!;
  assert.ok(egress.includes("10.96.0.10/32:cluster-dns"));
  assert.ok(egress.includes("162.0.217.171/32:stripe-api"));
  const ingress = m.get("wazuh/lists/sbob/redis/ingress_addrs")!;
  assert.ok(ingress.includes("10.244.0.0/16:app-clients"));
});

test("rule XML: base/drift/sustained chain with correct ids and lookups", () => {
  const xml = byPath(redisBundle()).get("wazuh/rules/sbob/100000_redis_linux.xml")!;
  // execs drift: CDB not_match_key over the exact list
  assert.ok(xml.includes('<rule id="100011"'));
  assert.ok(xml.includes('lookup="not_match_key"'), "negated CDB lookup present");
  // opens drift: negated-alternation regex for wildcarded /data/* + CDB for exact
  assert.ok(xml.includes('<rule id="100021"'));
  assert.ok(xml.includes("^(?!(?:/data/[^/]+(?:/[^/]+)*)$)"), "negated allow-alternation present");
  // egress drift: negated port alternation + address list lookup
  assert.ok(xml.includes('<rule id="100031"'));
  assert.ok(xml.includes("^(?!(?:53|443)$)"), "port allowlist alternation present");
  assert.ok(xml.includes('lookup="not_address_match_key"'), "address CDB lookup present");
  // sustained escalation children
  assert.ok(xml.includes('<rule id="100012"'));
  assert.ok(xml.includes("<frequency>8</frequency>"));
  // MITRE mapping
  assert.ok(xml.includes("T1059"));
  assert.ok(xml.includes("T1005"));
  assert.ok(xml.includes("T1071"));
  // ingress is informational only on Linux (accept() attribution gap)
  assert.ok(xml.includes('<rule id="100043"'));
  assert.ok(xml.includes("sbob-info"));
  // generated-bundle banner
  assert.ok(xml.includes("LAB VALIDATION PENDING"));
  assert.ok(xml.includes("do not edit by hand"));
  // description variables reference decoded fields
  assert.ok(xml.includes("$(sbob.exe)"));
});

test("decoder XML: chains SYSCALL and PATH records into sbob.* fields", () => {
  const dec = byPath(redisBundle()).get("wazuh/decoders/sbob/redis.xml")!;
  assert.ok(dec.includes("<decoder"), "has decoders");
  assert.ok(dec.includes("sbob.key"));
  assert.ok(dec.includes("sbob.exe"));
  assert.ok(dec.includes("sbob.path"));
  assert.ok(dec.includes("LAB VALIDATION PENDING"));
});

test("manifest: workload scope, file inventory, and coverage notes", () => {
  const m = byPath(redisBundle());
  const manifest = JSON.parse(m.get("redis.manifest.json")!);
  assert.equal(manifest.workload.name, "redis");
  assert.equal(manifest.workload.namespace, "cache-tier");
  assert.deepEqual(manifest.workload.scope.linuxGroups, ["sbob-redis"]);
  assert.ok(manifest.files.includes("wazuh/rules/sbob/100000_redis_linux.xml"));
  assert.ok(manifest.coverageNotes.some((n: string) => n.startsWith("ingress:")));
  assert.ok(manifest.coverageNotes.some((n: string) => n.includes("capabilities: section-absent")));
  assert.equal(manifest.labValidation, "pending");
});

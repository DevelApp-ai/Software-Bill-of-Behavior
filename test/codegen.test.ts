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
    "wazuh/lists/sbob/redis/egress_saddrs",
    "wazuh/lists/sbob/redis/execs",
    "wazuh/lists/sbob/redis/ingress_addrs",
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

test("CDB lists: exact entries only; wildcards live in rule regexes (issue #42 shape)", () => {
  const m = byPath(redisBundle());
  const execs = m.get("wazuh/lists/sbob/redis/execs")!;
  assert.ok(execs.includes("/usr/bin/redis-server:1"));
  assert.ok(execs.includes("/bin/sh:1"));
  // NO opens list on 4.14: audit.directory.name decodes quote-wrapped, and
  // quoted CDB keys are fragile — exact opens are compiled into the rule
  // regexes and wildcard entries stay there too
  assert.ok(!m.has("wazuh/lists/sbob/redis/opens"), "opens list is gone (quote-wrapped field)");
  // egress keys are the saddr hex spellings of the declared peers (both padded
  // 32-hex and truncated 16-hex forms): wazuh 4.14 decodes SOCKADDR saddr=
  // into the STATIC srcip field, and PCRE2 conditions on static fields are
  // rejected by analysisd while list lookups are allowed
  const egress = m.get("wazuh/lists/sbob/redis/egress_saddrs")!;
  assert.ok(egress.includes("020000350A60000A:".split(":")[0]), "10.96.0.10:53 padded-16 hex key");
  assert.ok(egress.includes("020001BBA200D9AB"), "162.0.217.171:443 truncated hex key");
  assert.ok(egress.includes("020001BBA200D9AB0000000000000000"), "padded 32-hex spelling");
  const ingress = m.get("wazuh/lists/sbob/redis/ingress_addrs")!;
  assert.ok(ingress.includes("10.244.0.0/16:app-clients"));
});

test("rule XML: base/drift/sustained chain with correct ids and lookups (wazuh 4.14 schema)", () => {
  const xml = byPath(redisBundle()).get("wazuh/rules/sbob/100000_redis_linux.xml")!;
  // rules ride the SHIPPED auditd decoder family (if_group audit + audit.* fields)
  assert.ok(xml.includes('<rule  id="100000"'));
  assert.ok(xml.includes('<field name="audit.key" type="pcre2">^sbob-exec(?:-redis)?$</field>'));
  // execs drift: CDB not_match_key over the exact list on audit.exe
  assert.ok(xml.includes('<rule  id="100011"'));
  assert.ok(xml.includes('<list field="audit.exe" lookup="not_match_key">etc/lists/sbob/redis/execs</list>'));
  // opens drift: quote-anchored negated alternation (audit.directory.name keeps
  // its quotes); NO opens CDB list
  assert.ok(xml.includes('<rule  id="100021"'));
  assert.ok(xml.includes(`^"(?!/etc/resolv\\.conf"$|/data/[^/"]+(?:/[^/"]+)*"$)[^"]+"$`), "quote-anchored negated allow-alternation present");
  assert.ok(!xml.includes("lists/sbob/redis/opens"), "no opens CDB reference");
  // egress drift: CDB on the STATIC srcip field (list lookups on static fields
  // are allowed; PCRE2 on static fields is not) keyed by saddr hex spellings
  assert.ok(xml.includes('<rule  id="100031"'));
  assert.ok(xml.includes('<list field="srcip" lookup="not_match_key">etc/lists/sbob/redis/egress_saddrs</list>'));
  // sustained escalation children: frequency/timeframe are RULE ATTRIBUTES on
  // 4.14, children chain via if_matched_sid + same_field/same_srcip
  assert.ok(xml.includes('<rule  id="100012" level="13" frequency="8" timeframe="120">'), "frequency/timeframe as rule attributes");
  assert.ok(xml.includes("<if_matched_sid>100011</if_matched_sid>"));
  assert.ok(xml.includes("<same_field>audit.exe</same_field>"));
  assert.ok(xml.includes('<rule  id="100032" level="13" frequency="8" timeframe="120">'));
  assert.ok(xml.includes("<same_srcip />"));
  assert.ok(!xml.includes("<frequency>"), "no legacy frequency element spelling");
  // (0,9) overlay-sustained child (winner-context finding, issue #42): the
  // level-12 sensitive-file overlay steals the winner slot from the level-9
  // drift parent, so its repetition is escalated by a child of the OVERLAY
  assert.ok(xml.includes('<rule  id="100009" level="13" frequency="8" timeframe="120">'));
  assert.ok(xml.includes("<if_matched_sid>100001</if_matched_sid>"), "sustained sensitive-file repetition chains off the overlay");
  // MITRE mapping
  assert.ok(xml.includes("T1059"));
  assert.ok(xml.includes("T1005"));
  assert.ok(xml.includes("T1071"));
  // ingress is informational only on Linux (accept() attribution gap)
  assert.ok(xml.includes('<rule  id="100043"'));
  assert.ok(xml.includes("sbob-info"));
  // generated-bundle banner
  assert.ok(xml.includes("LAB VALIDATION PENDING"));
  assert.ok(xml.includes("do not edit by hand"));
  // description variables reference decoded fields
  assert.ok(xml.includes("$(audit.exe)"));
  // rules are wrapped in a <group> (bare-rule files fail the 4.14 loader)
  assert.ok(xml.includes('<group name="sbob,redis">'));
});

test("decoder XML: config-check only; audit lines ride the shipped auditd family", () => {
  const dec = byPath(redisBundle()).get("wazuh/decoders/sbob/redis.xml")!;
  // issue #42: on wazuh 4.14.6 the SHIPPED auditd decoder family preempts any
  // custom audit decoder root, so the bundle emits ONLY the config-check
  // digest decoder and the rules ride audit.* fields from the shipped family
  assert.ok(dec.includes("<decoder"), "has decoders");
  assert.ok(dec.includes("sbob-redis-config-check"), "config-check decoder present");
  assert.ok(dec.includes("sbob-audit-digest"), "command-wodle prematch present");
  assert.ok(dec.includes("sbob.audit_digest"), "digest field order");
  assert.ok(!dec.includes("sbob.key"), "no preemptable custom audit root decoders");
  assert.ok(!/order>sbob\.(exe|path)/.test(dec), "no SYSCALL/PATH shadow decoders");
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

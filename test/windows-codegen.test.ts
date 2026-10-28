import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { makeAllocator } from "../src/ruleids.ts";
import { generateWindowsBundle } from "../src/codegen/windows.ts";
import { commandLineRegex } from "../src/codegen/windows.ts";
import type { ExecCompiled } from "../src/types.ts";
import { parsePathPattern, compilePathSegs } from "../src/wildcards.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;

function redisWindowsBundle() {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  const ir = buildIR(validateSbob(parsed), parsed);
  return { ir, files: generateWindowsBundle(ir, makeAllocator("redis", 0)) };
}

function byPath(files: ReturnType<typeof generateWindowsBundle>) {
  return new Map(files.map((f) => [f.path, f.content]));
}

/** Extract the <field> regex content for a rule id / field name from XML. */
function fieldRegex(xml: string, ruleId: number, fieldName: string): string {
  const ruleRe = new RegExp(`<rule id="${ruleId}"[^>]*>([\\s\\S]*?)</rule>`, "m");
  const rule = ruleRe.exec(xml)?.[1];
  assert.ok(rule, `rule ${ruleId} present`);
  const f = new RegExp(`<field name="${fieldName.replace(/\./g, "\\.")}" type="pcre2">([\\s\\S]*?)</field>`).exec(rule);
  assert.ok(f, `field ${fieldName} present on rule ${ruleId}`);
  return f[1]
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function ruleBlock(xml: string, ruleId: number): string {
  const m = new RegExp(`<rule id="${ruleId}"[^>]*>([\\s\\S]*?)</rule>`, "m").exec(xml);
  assert.ok(m, `rule ${ruleId} present`);
  return m[1];
}

// ---------------------------------------------------------------------------

test("redis windows bundle has the documented file structure", () => {
  const paths = redisWindowsBundle().files.map((f) => f.path).sort();
  assert.deepEqual(paths, [
    "redis.manifest.json",
    "wazuh/agent-conf/sbob/redis.xml",
    "wazuh/lists/sbob/redis/egress_addrs",
    "wazuh/lists/sbob/redis/ingress_addrs",
    "wazuh/rules/sbob/100000_redis_windows.xml",
  ]);
});

test("windows bundle is deterministic across runs", () => {
  const a = redisWindowsBundle().files;
  const b = redisWindowsBundle().files;
  assert.deepEqual(a, b);
});

test("agent configuration fragment matches TDS 4.3 (eventchannel localfile)", () => {
  const { files } = redisWindowsBundle();
  const conf = byPath(files).get("wazuh/agent-conf/sbob/redis.xml")!;
  assert.match(conf, /<location>Microsoft-Windows-Sysmon\/Operational<\/location>/);
  assert.match(conf, /<log_format>eventchannel<\/log_format>/);
  assert.match(conf, /<query>Event\/System\[EventID=1 or EventID=3 or EventID=10 or EventID=11 or EventID=22\]<\/query>/);
});

test("windows rules carry type=\"pcre2\" on every field condition (OS_Regex default would fail to compile)", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  const fields = [...xml.matchAll(/<field name="[^"]+"( type="pcre2")?>/g)].map((m) => m[1]);
  assert.ok(fields.length >= 8, `expected >= 8 field conditions, saw ${fields.length}`);
  for (const t of fields) assert.equal(t, ' type="pcre2"');
});

test("rule ids follow the TDS 6.1 layout; every if_sid resolves inside the file or to the shipped 61600 parent", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  const ids = [...xml.matchAll(/<rule id="(\d+)" level="(\d+)">/g)].map((m) => Number(m[1]));
  // 100000 + slot*100 + section*10 + variant (windows variants 5-9)
  assert.deepEqual(ids.sort((a, b) => a - b), [
    100005, 100006, 100007, 100008, // base section: global base, args drift, dns drift, prereq info
    100015, 100016, 100017,         // execs: base, drift, escalation
    100025, 100026, 100027,         // opens: base, drift, escalation
    100035, 100036, 100037,         // egress: base, drift, escalation
    100048,                         // ingress info
  ]);
  for (const sid of [...xml.matchAll(/<if_sid>(\d+)<\/if_sid>/g)].map((m) => Number(m[1]))) {
    assert.ok(sid === 61600 || ids.includes(sid), `if_sid ${sid} resolves`);
  }
});

test("EID routing: execs->1, opens->11, egress->3(initiated true), dns->22, prereq->4, ingress->3(initiated false)", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  assert.match(fieldRegex(xml, 100015, "win.system.eventID"), /^\^1\$$/);
  assert.match(fieldRegex(xml, 100025, "win.system.eventID"), /^\^11\$$/);
  assert.match(fieldRegex(xml, 100035, "win.system.eventID"), /^\^3\$$/);
  assert.match(fieldRegex(xml, 100035, "win.eventdata.initiated"), /^\^\[Tt\]rue\$$/);
  assert.match(fieldRegex(xml, 100007, "win.system.eventID"), /^\^22\$$/);
  assert.match(fieldRegex(xml, 100008, "win.system.eventID"), /^\^4\$$/);
  assert.match(fieldRegex(xml, 100048, "win.eventdata.initiated"), /^\^\[Ff\]alse\$$/);
});

test("execs image drift regex: declared images are allowed, others drift (verified with JS RegExp)", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  const neg = new RegExp(fieldRegex(xml, 100016, "win.eventdata.image"));
  assert.equal(neg.test("/usr/bin/redis-server"), false); // allowed
  assert.equal(neg.test("/bin/sh"), false);               // allowed
  assert.equal(neg.test("/usr/bin/nc"), true);            // drift
  assert.equal(neg.test("/usr/bin/redis-server2"), true); // prefix leak must not pass
});

test("args drift regex (TDS 7.3.4): token-aware command-line semantics", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  const neg = new RegExp(fieldRegex(xml, 100006, "win.eventdata.commandLine"));
  const pos = new RegExp(fieldRegex(xml, 100006, "win.eventdata.image"));
  assert.equal(pos.test("/usr/bin/redis-server"), true); // image allowlist
  // redis-server entry declares [argv[0], ⋯⋯] — any (or no) extra args are fine
  assert.equal(neg.test("/usr/bin/redis-server"), false);
  assert.equal(neg.test("/usr/bin/redis-server --port 6379"), false);
  assert.equal(neg.test('"/usr/bin/redis-server" --port 6379'), false);
  // /bin/sh entry declares [argv[0], ⋯] — exactly one argument
  assert.equal(neg.test("/bin/sh -c"), false);
  assert.equal(neg.test("/bin/sh -c ls"), true);  // two args = drift
  assert.equal(neg.test("/bin/sh"), true);        // zero args = drift
  // undeclared image handled by the image drift rule; args rule image condition gates it
  assert.equal(pos.test("/usr/bin/nc"), false);
});

test("dns drift regex: QueryName form (no trailing dot), wildcards per RFC 4592", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  const neg = new RegExp(fieldRegex(xml, 100007, "win.eventdata.queryName"));
  assert.equal(neg.test("pay.api.stripe.com"), false); // allowed by *.api.stripe.com.
  assert.equal(neg.test("api.stripe.com"), true);      // drift: only one label before .api…
  assert.equal(neg.test("evil.com"), true);            // drift
  // SBoB's canonical trailing-dot spelling must NOT require a dot in Sysmon data
  assert.doesNotMatch(fieldRegex(xml, 100007, "win.eventdata.queryName"), /stripe\\.com\\\\\.\$\)/);
});

test("opens drift regex compiles wildcard tails; flags are documented as not evaluated", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  const neg = new RegExp(fieldRegex(xml, 100026, "win.eventdata.targetFilename"));
  assert.equal(neg.test("/data/dump.rdb"), false);
  assert.equal(neg.test("/data/sub/dir/a.rdb"), false);
  assert.equal(neg.test("/etc/resolv.conf"), false);
  assert.equal(neg.test("/etc/passwd"), true);
  assert.match(xml, /opens\[\]\.flags are NOT evaluated on Windows/);
});

test("egress drift uses the shared CDB address list and a negated port alternation", () => {
  const { files } = redisWindowsBundle();
  const xml = byPath(files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  const drift = ruleBlock(xml, 100036);
  assert.match(drift, /<list field="win.eventdata.destinationIp" lookup="not_address_match_key">sbob\/redis\/egress_addrs<\/list>/);
  assert.equal(new RegExp(fieldRegex(xml, 100036, "win.eventdata.destinationPort")).test("443"), false);
  assert.equal(new RegExp(fieldRegex(xml, 100036, "win.eventdata.destinationPort")).test("4444"), true);
  const cdb = byPath(files).get("wazuh/lists/sbob/redis/egress_addrs")!;
  assert.match(cdb, /10\.96\.0\.10\/32:cluster-dns/);
  assert.match(cdb, /162\.0\.217\.171\/32:stripe-api/);
});

test("escalation rules repeat at 8 events / 120s and chain from their drift rule", () => {
  const xml = byPath(redisWindowsBundle().files).get("wazuh/rules/sbob/100000_redis_windows.xml")!;
  for (const [id, parent] of [[100017, 100016], [100027, 100026], [100037, 100036]] as const) {
    const block = ruleBlock(xml, id);
    assert.match(block, new RegExp(`<if_sid>${parent}</if_sid>`));
    assert.match(block, /<frequency>8<\/frequency>/);
    assert.match(block, /<timeframe>120<\/timeframe>/);
    assert.match(xml, new RegExp(`<rule id="${id}" level="12">`));
  }
});

test("manifest records the windows coverage posture honestly", () => {
  const { files } = redisWindowsBundle();
  const manifest = JSON.parse(byPath(files).get("redis.manifest.json")!);
  assert.equal(manifest.target, "windows");
  assert.equal(manifest.labValidation, "pending");
  const notes = manifest.coverageNotes.join("\n");
  assert.match(notes, /args drift is heuristic-equivalent/);
  assert.match(notes, /opens\[\]\.flags are not evaluable/);
  assert.match(notes, /capabilities\[\] is N\/A on Windows/);
  assert.match(notes, /drive-letter ':'/);
  assert.match(notes, /parent rule 61600/);
});

test("commandLineRegex: ⋯ is exactly one token, ⋯⋯ is zero or more, quoting tolerated", () => {
  const mk = (path: string, args: string[] | undefined): ExecCompiled => {
    const segs = parsePathPattern(path, "test");
    return { pathSegs: segs, pathRegex: compilePathSegs(segs), argsRegex: null, isExact: true, source: { path, args } };
  };
  // ⋯⋯ as the tail: zero or more arguments
  const tail = new RegExp(`^${commandLineRegex(mk("/usr/bin/tool", ["/usr/bin/tool", "⋯⋯"]))}$`);
  assert.equal(tail.test("/usr/bin/tool"), true);
  assert.equal(tail.test("/usr/bin/tool --flag value"), true);
  assert.equal(tail.test('"/usr/bin/tool" --flag "quoted value"'), true);
  assert.equal(tail.test("/usr/bin/toolx"), false);
  // ⋯: exactly one argument, quoted or bare
  const one = new RegExp(`^${commandLineRegex(mk("/bin/app", ["/bin/app", "⋯"]))}$`);
  assert.equal(one.test("/bin/app"), false);
  assert.equal(one.test("/bin/app -c"), true);
  assert.equal(one.test('/bin/app "quoted arg"'), true);
  assert.equal(one.test("/bin/app -c extra"), false);
  // literal args stay literal ('*' is not a wildcard in args)
  const lit = new RegExp(`^${commandLineRegex(mk("/bin/a", ["/bin/a", "-o", "*.conf"]))}$`);
  assert.equal(lit.test("/bin/a -o *.conf"), true);
  assert.equal(lit.test("/bin/a -o x.conf"), false);
  assert.equal(lit.test('/bin/a -o "*.conf"'), true);
});

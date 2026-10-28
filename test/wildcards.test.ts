import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compileArgsPattern, compileDnsPattern, compilePathSegs,
  expandIPv6, parseIpEntry, parsePathPattern,
} from "../src/wildcards.ts";
import { negatedAlternation, positiveAlternation } from "../src/regexp.ts";

/** Anchor a fragment the way the emitted rule conditions do. */
function full(fragment: string): RegExp {
  return new RegExp(`^(?:${fragment})$`);
}

// ---------------------------------------------------------------------------
// Path wildcards — golden table from SBoB spec section 5.1
// ---------------------------------------------------------------------------

test("spec 5.1 table: /etc/⋯ (ONE segment)", () => {
  const re = full(compilePathSegs(parsePathPattern("/etc/\u22EF", "t")));
  assert.ok(re.test("/etc/passwd"));
  assert.ok(re.test("/etc/hosts"));
  assert.ok(!re.test("/etc/"));
  assert.ok(!re.test("/etc/ssh/sshd_config"));
  assert.ok(!re.test("/etc/ssl/certs/ca.pem"));
});

test("spec 5.1 table: /etc/* (trailing star, 1+ segments)", () => {
  const re = full(compilePathSegs(parsePathPattern("/etc/*", "t")));
  assert.ok(re.test("/etc/passwd"));
  assert.ok(re.test("/etc/ssh/sshd_config"));
  assert.ok(!re.test("/etc"));
  assert.ok(!re.test("/etc/"));
});

test("spec 5.1 table: /a/*/b (mid star, 0+ segments)", () => {
  const re = full(compilePathSegs(parsePathPattern("/a/*/b", "t")));
  assert.ok(re.test("/a/b"));
  assert.ok(re.test("/a/x/b"));
  assert.ok(re.test("/a/x/y/b"));
  assert.ok(!re.test("/a/x/c"));
});

test("spec 5.1 table: /a/⋯/b (mid ONE segment)", () => {
  const re = full(compilePathSegs(parsePathPattern("/a/\u22EF/b", "t")));
  assert.ok(re.test("/a/x/b"));
  assert.ok(!re.test("/a/b"));
  assert.ok(!re.test("/a/x/y/b"));
});

test("mid-star matches zero segments; multi-wildcard combinations", () => {
  const re = full(compilePathSegs(parsePathPattern("/opt/*/vendor/app/node/*", "t")));
  assert.ok(re.test("/opt/vendor/app/node/x.js"));
  assert.ok(re.test("/opt/v/vendor/app/node/deep/x.js"));
  const re2 = full(compilePathSegs(parsePathPattern("/opt/\u22EF/vendor/app/node/*", "t")));
  assert.ok(re2.test("/opt/v/vendor/app/node/x.js"));
  assert.ok(!re2.test("/opt/vendor/app/node/x.js"));
});

test("literal paths match exactly, no substring surprises", () => {
  const re = full(compilePathSegs(parsePathPattern("/etc/resolv.conf", "t")));
  assert.ok(re.test("/etc/resolv.conf"));
  assert.ok(!re.test("/etc/resolv.conf.bak"));
  assert.ok(!re.test("/x/etc/resolv.conf"));
});

test("regex metacharacters in literal segments are escaped", () => {
  const re = full(compilePathSegs(parsePathPattern("/opt/a.b+c(d)/file", "t")));
  assert.ok(re.test("/opt/a.b+c(d)/file"));
  assert.ok(!re.test("/opt/aXbYcZd/file"));
});

test("mid-segment ⋯ is rejected (spec 4.5 rejection rule)", () => {
  assert.throws(() => parsePathPattern("/a/b/elasticsearch\u22EF", "t"), /mid-segment/);
  assert.throws(() => parsePathPattern("relative/path", "t"), /absolute/);
  assert.throws(() => parsePathPattern("/a//b", "t"), /empty path segment/);
});

// ---------------------------------------------------------------------------
// Exec args — spec 5.3
// ---------------------------------------------------------------------------

test("args: ⋯⋯ absorbs zero or more trailing arguments", () => {
  const re = full(compileArgsPattern(["/bin/foo", "\u22EF\u22EF"], "t"));
  assert.ok(re.test("/bin/foo"));
  assert.ok(re.test("/bin/foo -x"));
  assert.ok(re.test("/bin/foo --flag=1 arg2 arg3"));
  // bare entry without ⋯⋯ matches only the bare invocation
  const bare = full(compileArgsPattern(["/bin/foo"], "t"));
  assert.ok(bare.test("/bin/foo"));
  assert.ok(!bare.test("/bin/foo -x"));
});

test("args: ⋯ matches exactly one argument; * is literal", () => {
  const re = full(compileArgsPattern(["/bin/sh", "\u22EF"], "t"));
  assert.ok(re.test("/bin/sh -c"));
  assert.ok(!re.test("/bin/sh"));
  assert.ok(!re.test("/bin/sh -c ls"));
  const star = full(compileArgsPattern(["/bin/tool", "*"], "t"));
  assert.ok(star.test("/bin/tool *"));
  assert.ok(!star.test("/bin/tool x"));
});

// ---------------------------------------------------------------------------
// DNS wildcards — spec 4.7 / 5.8
// ---------------------------------------------------------------------------

test("DNS: leading *.suffix matches exactly one label (RFC 4592)", () => {
  const re = full(compileDnsPattern("*.api.stripe.com.", "t"));
  assert.ok(re.test("x.api.stripe.com."));
  assert.ok(!re.test("api.stripe.com."));       // zero labels: not matched
  assert.ok(!re.test("y.z.api.stripe.com."));   // two labels: not matched
});

test("DNS: trailing prefix.* matches one or more labels", () => {
  const re = full(compileDnsPattern("telemetry.", "t")); // plain: byte equality
  assert.ok(re.test("telemetry."));
  const re2 = full(compileDnsPattern("telemetry.*", "t"));
  assert.ok(re2.test("telemetry.a."));
  assert.ok(re2.test("telemetry.a.b"));
  assert.ok(!re2.test("telemetry."));
});

test("DNS: mid ⋯ matches exactly one label; multi-wildcard rejected", () => {
  const re = full(compileDnsPattern("a.\u22EF.b.", "t"));
  assert.ok(re.test("a.x.b."));
  assert.ok(!re.test("a.b."));
  assert.ok(!re.test("a.x.y.b."));
  assert.throws(() => compileDnsPattern("*.a.*.", "t"), /multiple wildcard/);
  assert.throws(() => compileDnsPattern("a*b.", "t"), /only valid as/);
});

// ---------------------------------------------------------------------------
// IP canonicalization — spec 5.7
// ---------------------------------------------------------------------------

test("IPv6 literals canonicalize to lowercase full form", () => {
  assert.equal(expandIPv6("2001:DB8::1", "t"), "2001:db8:0:0:0:0:0:1");
  assert.equal(expandIPv6("::1", "t"), "0:0:0:0:0:0:0:1");
  assert.throws(() => expandIPv6("1::2::3", "t"), /multiple/);
  assert.throws(() => expandIPv6("2001:db8:::1", "t"));
});

test("IP entries: literal, CIDR, and * sentinel", () => {
  assert.deepEqual(parseIpEntry("162.0.217.171", "t"), { cdb: "162.0.217.171/32", any: false });
  assert.deepEqual(parseIpEntry("10.0.0.0/8", "t"), { cdb: "10.0.0.0/8", any: false });
  assert.deepEqual(parseIpEntry("2001:db8::/32", "t"), { cdb: "2001:db8:0:0:0:0:0:0/32", any: false });
  assert.deepEqual(parseIpEntry("*", "t"), { cdb: "", any: true });
  assert.throws(() => parseIpEntry("10.0.0.0/33", "t"), /netmask/);
  assert.throws(() => parseIpEntry("999.1.1.1", "t"), /invalid/);
});

// ---------------------------------------------------------------------------
// Negated-alternation emission — TDS 5.3
// ---------------------------------------------------------------------------

test("negated alternation: allow exact + pattern, deny everything else", () => {
  const allowed = ["/usr/bin/redis\\-server", "/data/[^/]+(?:/[^/]+)*"];
  const neg = new RegExp(negatedAlternation(allowed)!);
  // allowlist members are NOT matched => the "not_" CDB lookup misses => no drift
  assert.ok(!neg.test("/usr/bin/redis-server"));
  assert.ok(!neg.test("/data/x/y"));
  // anything else IS matched => lookup hits => drift fires
  assert.ok(neg.test("/tmp/evil"));
  assert.ok(neg.test("/data"));                    // trailing star never matches zero segments
  assert.ok(neg.test("/usr/bin/redis-serverx"));   // no substring bleed
});

test("positive alternation is the inverse condition", () => {
  const allowed = ["/data/[^/]+"];
  const pos = new RegExp(positiveAlternation(allowed)!);
  assert.ok(pos.test("/data/x"));
  assert.ok(!pos.test("/etc/x"));
});

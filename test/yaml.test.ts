import { test } from "node:test";
import assert from "node:assert/strict";
import { parseYaml, YamlParseError } from "../src/yaml.ts";

test("parses block maps, sequences, and nested structures", () => {
  const doc = parseYaml(`
a: 1
b: hello world
c:
  - x
  - y
d:
  e: true
  f: null
`) as Record<string, unknown>;
  assert.equal(doc["a"], 1);
  assert.equal(doc["b"], "hello world");
  assert.deepEqual(doc["c"], ["x", "y"]);
  const d = doc["d"] as Record<string, unknown>;
  assert.equal(d["e"], true);
  assert.equal(d["f"], null);
});

test("parses flow sequences and maps", () => {
  const doc = parseYaml(`
ports: [{name: TCP-443, protocol: TCP, port: 443}]
addrs: ["10.0.0.0/8", 162.0.217.171/32]
inline: {a: 1, b: [x, y]}
`) as Record<string, unknown>;
  const ports = doc["ports"] as Array<Record<string, unknown>>;
  assert.equal(ports[0]["port"], 443);
  const addrs = doc["addrs"] as unknown[];
  assert.equal(addrs[0], "10.0.0.0/8");
  const inline = doc["inline"] as Record<string, unknown>;
  assert.deepEqual(inline["b"], ["x", "y"]);
});

test("quoted scalars keep special characters literal", () => {
  const doc = parseYaml(`
single: 'it has: colons # and stuff'
double: "line1\\nline2"
wild: '*literal'
`) as Record<string, unknown>;
  assert.equal(doc["single"], "it has: colons # and stuff");
  assert.equal(doc["double"], "line1\nline2");
  assert.equal(doc["wild"], "*literal");
});

test("comments are stripped; empty document parses to null", () => {
  const doc = parseYaml("# just a comment\n\n# another\n");
  assert.equal(doc, null); // YAML-correct: empty document is null; asMap(null) is {}
});

test("tabs in indentation fail loudly", () => {
  assert.throws(() => parseYaml("a:\n\tb: 1"), YamlParseError);
});

test("block scalars are explicitly unsupported", () => {
  assert.throws(() => parseYaml("a: |\n  block text\n"), /block scalar/i);
});

test("anchors and aliases are explicitly unsupported", () => {
  assert.throws(() => parseYaml("a: &anchor 1\nb: *anchor\n"), /anchor|alias/i);
});

test("invalid structure fails loudly with line info", () => {
  let caught: unknown;
  try {
    parseYaml("a: 1\n  b: 2\n");
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof YamlParseError, "deeper indentation is rejected");
  assert.match((caught as Error).message, /line \d+/);
});

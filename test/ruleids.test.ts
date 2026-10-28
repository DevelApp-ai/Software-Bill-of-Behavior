import { test } from "node:test";
import assert from "node:assert/strict";
import {
  emptyRegistry, makeAllocator, parseRegistry, registryToYaml,
  SECTION_CODES, slotFor, ID_BAND_MIN, MAX_SLOT,
} from "../src/ruleids.ts";
import { SbobError } from "../src/errors.ts";

const REGISTRY = `# comment
workloads:
  redis: {slot: 0}
  web: {slot: 1}
`;

test("registry parses (string and number slot spellings) and round-trips", () => {
  const reg = parseRegistry(REGISTRY);
  assert.equal(reg.slots.get("redis"), 0);
  assert.equal(reg.slots.get("web"), 1);
  // number spelling (our own emitter output must re-parse)
  const reg2 = parseRegistry(registryToYaml(reg));
  assert.equal(reg2.slots.get("web"), 1);
  const reg3 = parseRegistry("workloads:\n  x: {slot: 3}\n");
  assert.equal(reg3.slots.get("x"), 3);
});

test("duplicate slot allocation in registry is ERR_ID_COLLISION", () => {
  assert.throws(
    () => parseRegistry("workloads:\n  a: {slot: 0}\n  b: {slot: 0}\n"),
    (e: SbobError) => e.code === "ERR_ID_COLLISION",
  );
});

test("slotFor returns existing slots; allocates max+1 for new workloads", () => {
  const reg = parseRegistry(REGISTRY);
  assert.equal(slotFor("redis", reg), 0);
  assert.equal(slotFor("new-workload", reg), 2); // max(1)+1
  assert.equal(slotFor("new-workload", reg), 2); // stable after first call
});

test("allocator derives deterministic ids from the TDS 6.1 formula", () => {
  // 100000 + slot*100 + section*10 + variant
  const alloc = makeAllocator("redis", 0);
  assert.equal(alloc.linux("execs", "base"), 100000 + 0 * 100 + SECTION_CODES.execs * 10 + 0);
  assert.equal(alloc.linux("execs", "drift"), 100011);
  assert.equal(alloc.linux("execs", "escalation"), 100012);
  assert.equal(alloc.linux("opens", "drift"), 100021);
  assert.equal(alloc.linux("egress", "drift"), 100031);
  assert.equal(alloc.linux("ingress", "info"), 100043);
  assert.equal(alloc.windows("execs", "base"), 100015);
  assert.equal(alloc.windows("execs", "drift"), 100016);
});

test("distinct slots never collide; a collision throws ERR_ID_COLLISION", () => {
  const a = makeAllocator("redis", 0);
  const b = makeAllocator("web", 1);
  assert.notEqual(a.linux("execs", "drift"), b.linux("execs", "drift"));
  // force a collision by issuing the same section/variant twice on one allocator
  a.linux("execs", "exemption");
  assert.throws(
    () => a.linux("execs", "exemption"),
    (e: SbobError) => e.code === "ERR_ID_COLLISION",
  );
});

test("band overflow is detected", () => {
  // slot 999 stays inside the band for the highest section/variant
  const edge = makeAllocator("big", MAX_SLOT);
  assert.equal(edge.linux("attribution", "exemption"), ID_BAND_MIN + 99900 + 74); // 199974
  // but the registry itself is exhausted afterwards
  const regFull = emptyRegistry();
  for (let i = 0; i <= MAX_SLOT; i++) regFull.slots.set(`w${i}`, i);
  assert.throws(
    () => slotFor("next", regFull),
    (e: SbobError) => e.code === "ERR_ID_COLLISION" && /exhausted/.test(e.message),
  );
});

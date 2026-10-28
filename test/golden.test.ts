import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { makeAllocator } from "../src/ruleids.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";

const GOLDEN = join(import.meta.dirname, "golden/redis-linux");

/** Recursively map relative path -> content under a directory. */
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

test("regenerated bundle is byte-identical to the committed golden (run scripts/regen-golden.ts after intentional changes)", () => {
  assert.ok(existsSync(GOLDEN), "golden bundle committed under test/golden/redis-linux");
  const raw = readFileSync(new URL("../sbobs/redis.yaml", import.meta.url), "utf8");
  const parsed = parseYaml(raw);
  const ir = buildIR(validateSbob(parsed), parsed);
  const files = generateLinuxBundle(ir, makeAllocator("redis", 0));

  const generated = new Map(files.map((f) => [f.path, f.content]));
  const golden = snapshot(GOLDEN);
  assert.deepEqual([...generated.keys()].sort(), [...golden.keys()].sort(),
    "file inventory matches; if intentional, regenerate with scripts/regen-golden.ts");
  const diffs: string[] = [];
  for (const [path, content] of generated) {
    if (content !== golden.get(path)) diffs.push(path);
  }
  assert.deepEqual(diffs, [],
    "byte-identical bundle expected; if intentional, regenerate with scripts/regen-golden.ts");
});

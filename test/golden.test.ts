import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { makeAllocator } from "../src/ruleids.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { generateWindowsBundle } from "../src/codegen/windows.ts";

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

function checkGolden(goldenDir: string, generated: Array<{ path: string; content: string }>) {
  assert.ok(existsSync(goldenDir), `golden bundle committed under ${goldenDir}`);
  const gm = new Map(generated.map((f) => [f.path, f.content]));
  const golden = snapshot(goldenDir);
  assert.deepEqual([...gm.keys()].sort(), [...golden.keys()].sort(),
    "file inventory matches; if intentional, regenerate with scripts/regen-golden.ts");
  const diffs: string[] = [];
  for (const [path, content] of gm) {
    if (content !== golden.get(path)) diffs.push(path);
  }
  assert.deepEqual(diffs, [],
    "byte-identical bundle expected; if intentional, regenerate with scripts/regen-golden.ts");
}

function redisIR() {
  const raw = readFileSync(new URL("../sbobs/redis.yaml", import.meta.url), "utf8");
  const parsed = parseYaml(raw);
  return buildIR(validateSbob(parsed), parsed);
}

test("regenerated linux bundle is byte-identical to the committed golden (run scripts/regen-golden.ts after intentional changes)", () => {
  checkGolden(join(import.meta.dirname, "golden/redis-linux"),
    generateLinuxBundle(redisIR(), makeAllocator("redis", 0)));
});

test("regenerated windows bundle is byte-identical to the committed golden (run scripts/regen-golden.ts after intentional changes)", () => {
  checkGolden(join(import.meta.dirname, "golden/redis-windows"),
    generateWindowsBundle(redisIR(), makeAllocator("redis", 0)));
});

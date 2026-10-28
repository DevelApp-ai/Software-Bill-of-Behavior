#!/usr/bin/env node
/**
 * Regenerate the committed golden bundle (test/golden/redis-linux/**) from
 * sbobs/redis.yaml. Run after any intentional codegen change:
 *
 *   node scripts/regen-golden.ts
 *
 * The golden comparison test (test/golden.test.ts) fails CI whenever the
 * emitted bundle changes without this regeneration — reviewers see the exact
 * byte diff of every Wazuh artifact.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { makeAllocator, parseRegistry } from "../src/ruleids.ts";
import { generateLinuxBundle } from "../src/codegen/linux.ts";
import { generateWindowsBundle } from "../src/codegen/windows.ts";
import { generateK8sNodeBundle } from "../src/codegen/k8s.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const sbobPath = join(root, "sbobs/redis.yaml");
const registryPath = join(root, "docs/sbob-registry.yaml");

const raw = readFileSync(sbobPath, "utf8");
const parsed = parseYaml(raw);
const ir = buildIR(validateSbob(parsed), parsed);
const slot = parseRegistry(readFileSync(registryPath, "utf8")).slots.get("redis") ?? 0;

const bundles: Array<{ dir: string; files: ReturnType<typeof generateLinuxBundle> }> = [
  { dir: join(root, "test/golden/redis-linux"), files: generateLinuxBundle(ir, makeAllocator("redis", slot)) },
  { dir: join(root, "test/golden/redis-windows"), files: generateWindowsBundle(ir, makeAllocator("redis", slot)) },
  { dir: join(root, "test/golden/redis-k8s"), files: generateK8sNodeBundle(ir, makeAllocator("redis", slot)) },
];

for (const bundle of bundles) {
  rmSync(bundle.dir, { recursive: true, force: true });
  for (const f of bundle.files) {
    const dest = join(bundle.dir, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.content);
  }
  console.log(`wrote ${bundle.files.length} golden files under ${relative(root, bundle.dir)}`);
}

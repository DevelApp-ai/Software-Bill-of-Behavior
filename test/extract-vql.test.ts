/**
 * Engines-lab lane helper (M6 / issue #7) — extract-vql: the Velociraptor
 * artifact's embedded sweep queries dedented into runnable .vql files for
 * the `velociraptor query -f` live lane.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { generateVelociraptorBundle } from "../src/codegen/velociraptor.ts";

const ROOT = new URL("..", import.meta.url).pathname;
const REDIS = join(ROOT, "sbobs", "redis.yaml");

test("extract-vql: dedents the artifact sweep queries into runnable .vql files", () => {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  const ir = buildIR(validateSbob(parsed), parsed);
  const artifact = generateVelociraptorBundle(ir).find((f) => f.path === "velociraptor/sbob/redis.yaml")!;

  const dir = mkdtempSync(join(tmpdir(), "sbob-xvql-"));
  try {
    const artifactPath = join(dir, "redis.yaml");
    writeFileSync(artifactPath, artifact.content);
    const out = join(dir, "vql");
    const r = spawnSync(process.execPath, [join(ROOT, "scripts", "extract-vql.ts"), artifactPath, out], {
      encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /extracted 2 VQL queries/);

    const q1 = readFileSync(join(out, "sbob-q1.vql"), "utf8");
    assert.match(q1, /FROM pslist\(\)/);
    assert.match(q1, /NOT Exe =~ '\^\(\?:\/usr\/bin\/redis-server\|\/bin\/sh\)\$'/);
    assert.doesNotMatch(q1, /^ {8}/m); // dedented — runnable VQL, not artifact YAML

    const q2 = readFileSync(join(out, "sbob-q2.vql"), "utf8");
    assert.match(q2, /FROM netstat\(\)/);
    assert.match(q2, /NOT Raddr =~ /);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("extract-vql: usage error (exit 2) without both arguments", () => {
  const r = spawnSync(process.execPath, [join(ROOT, "scripts", "extract-vql.ts")], { encoding: "utf8" });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /usage: node scripts\/extract-vql\.ts/);
});

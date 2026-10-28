/**
 * Attack-suite false-negative check (TDS 11.3, M4 / issue #5) — suite parser,
 * matrix parser, documented-class accounting.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  DOCUMENTED_CLASSES,
  parseAttackNames,
  parseMatrixRows,
  runAttackSuiteCheck,
} from "../src/attackcheck.ts";

const SUITE = new URL("../docs/upstream-redis-attacks.yaml", import.meta.url).pathname;
const MATRIX = new URL("../docs/attack-matrix.md", import.meta.url).pathname;

// ---------------------------------------------------------------------------

test("suite parser extracts the 62 attack names, order preserved", () => {
  const names = parseAttackNames(readFileSync(SUITE, "utf8"));
  assert.equal(names.length, 62);
  assert.equal(names[0], "recon-info-server");
  assert.equal(names[4], "lua-cve-full-chain");
  assert.equal(names[61], "cleanup-config-restore-dbfilename");
  assert.ok(names.every((n) => /^[a-z0-9-]+$/.test(n)), "kebab-case suite names");
});

test("suite parser ignores metadata block scalars outside the attacks sequence", () => {
  const fixture = [
    "apiVersion: bobctl.k8sstormcenter.io/v1alpha1",
    "kind: AttackSuite",
    "metadata:",
    "  name: redis-killchain-attacks",
    "  description: >-",
    "    folded block scalar that the strict parser rejects",
    "attacks:",
    "  - name: attack-one",
    "    type: custom",
    "  - name: attack-two",
    "    type: custom",
    "other: value",
    "",
  ].join("\n");
  assert.deepEqual(parseAttackNames(fixture), ["attack-one", "attack-two"]);
});

test("matrix parser reads all 62 rows with detection + class columns", () => {
  const rows = parseMatrixRows(readFileSync(MATRIX, "utf8"));
  assert.equal(rows.size, 62);
  const row51 = rows.get("rootkit-init-module")!;
  assert.ok(row51, "row 51 present");
  assert.match(row51.detection, /100060/);
  assert.match(row51.coverageClass, /SIG/);
  const row52 = rows.get("rootkit-ebpf-load")!;
  assert.ok(row52.detection.includes("M4-PENDING") || row52.coverageClass.includes("M4-PENDING"));
});

test("documented classes cover the declared blind/partial vocabulary", () => {
  assert.deepEqual([...DOCUMENTED_CLASSES], ["BLIND-L7", "DNS-NAME", "M4-PENDING", "FILELESS-EXE", "K8S-API"]);
});

test("runAttackSuiteCheck passes on the committed suite + matrix", () => {
  const result = runAttackSuiteCheck(readFileSync(SUITE, "utf8"), readFileSync(MATRIX, "utf8"));
  assert.equal(result.attackCount, 62);
  assert.equal(result.rowCount, 62);
  assert.deepEqual(result.problems, []);
  assert.equal(result.ok, true);
});

test("runAttackSuiteCheck fails on an unaccounted attack (the false negative)", () => {
  const suiteFixture = "attacks:\n  - name: brand-new-attack\n  - name: rootkit-init-module\n";
  const result = runAttackSuiteCheck(suiteFixture, readFileSync(MATRIX, "utf8"));
  assert.equal(result.ok, false);
  assert.ok(result.problems.some((p) => p === "no matrix row: brand-new-attack"));
  assert.ok(!result.problems.some((p) => p.includes("rootkit-init-module")));
});

test("runAttackSuiteCheck fails on a stale matrix row", () => {
  const suiteFixture = "attacks:\n  - name: rootkit-init-module\n";
  const result = runAttackSuiteCheck(suiteFixture, readFileSync(MATRIX, "utf8"));
  assert.ok(result.problems.some((p) => p.startsWith("stale matrix row: ")));
});

test("runAttackSuiteCheck fails on a row with neither rule id nor documented class", () => {
  const matrixFixture = [
    "| # | Attack | Phase / Technique | Primitive | Detection (k8s-node) | Class |",
    "| --- | --- | --- | --- | --- | --- |",
    "| 1 | attack-one | P1 | whatever | — | EXEC |",
    "| 2 | attack-two | P1 | whatever | 100011 | EXEC |",
    "| 3 | attack-three | P1 | whatever | — | BLIND-L7 |",
    "",
  ].join("\n");
  const suiteFixture = "attacks:\n  - name: attack-one\n  - name: attack-two\n  - name: attack-three\n";
  const result = runAttackSuiteCheck(suiteFixture, matrixFixture);
  assert.equal(result.ok, false);
  assert.deepEqual(result.problems, ["row #1 (attack-one): neither a detection rule id nor a documented blind/partial class"]);
});

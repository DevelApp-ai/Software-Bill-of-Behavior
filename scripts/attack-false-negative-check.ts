#!/usr/bin/env node
/**
 * Attack-suite false-negative gate (TDS 11.3, M4 / issue #5).
 *
 *   node scripts/attack-false-negative-check.ts
 *
 * Asserts every attack in the upstream kill-chain suite
 * (docs/upstream-redis-attacks.yaml — the 62-attack redis suite from
 * k8sstormcenter/bob example/redis-attacks.yaml) is accounted for in
 * docs/attack-matrix.md: either a generated rule id detects it, or the row
 * declares a documented blind/partial class (BLIND-L7, DNS-NAME,
 * M4-PENDING, FILELESS-EXE, K8S-API). Exits non-zero on any gap.
 *
 * Operational flow (TDS 11.3): `bobctl simulate --suite <suite>.yaml`
 * generates the kill-chain traffic against a live workload; captured runs
 * are replayed through scripts/logtest-corpus.sh against the generated
 * bundle (benign corpus silent, drift corpus fires the mapped rule ids).
 * This script is the static half of the gate: the suite and the matrix
 * cannot drift apart silently.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runAttackSuiteCheck } from "../src/attackcheck.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const suitePath = join(root, "docs/upstream-redis-attacks.yaml");
const matrixPath = join(root, "docs/attack-matrix.md");

const result = runAttackSuiteCheck(
  readFileSync(suitePath, "utf8"),
  readFileSync(matrixPath, "utf8"),
);

console.log(`attack-suite false-negative check: ${result.attackCount} attacks, ${result.rowCount} matrix rows`);
if (result.ok) {
  console.log("PASS: every attack is detected or documented (docs/attack-matrix.md)");
} else {
  console.error("FAIL: attacks neither detected nor documented:");
  for (const p of result.problems) console.error(`  - ${p}`);
  process.exit(1);
}

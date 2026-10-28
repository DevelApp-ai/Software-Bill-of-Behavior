/**
 * CI gate: per-engine blind-spot matrix completeness (M6 / issue #7).
 *
 * Fails the build if docs/engine-matrix.md does not account for every
 * attack in the upstream kill-chain suite across the phase-2 engines
 * (sigma-win, sigma-linux, mde, falco, velociraptor), or if any attack is
 * blind in every engine without a documented blind class in
 * docs/attack-matrix.md. TDS 13 acceptance; see src/enginescheck.ts.
 */
import { readFileSync } from "node:fs";
import { runEngineMatrixCheck } from "../src/enginescheck.ts";
import { parseMatrixRows } from "../src/attackcheck.ts";

const suite = readFileSync("docs/upstream-redis-attacks.yaml", "utf8");
const engineMatrix = readFileSync("docs/engine-matrix.md", "utf8");
const attackMatrix = parseMatrixRows(readFileSync("docs/attack-matrix.md", "utf8"));

const result = runEngineMatrixCheck(suite, engineMatrix, attackMatrix, 5);

for (const problem of result.problems) {
  console.error("FAIL: " + problem);
}
if (!result.ok) {
  process.exit(1);
}
console.log(
  "PASS: engine matrix accounts for all " + result.attackCount + " suite attacks across 5 engines " +
    "(" + result.rowCount + " rows, statuses detect/partial/blind/n-a, no undocumented all-blind rows)",
);

/**
 * Per-engine blind-spot matrix check (TDS 13 acceptance, M6 / issue #7).
 *
 * Asserts that docs/engine-matrix.md accounts for every attack in the
 * upstream kill-chain suite (docs/upstream-redis-attacks.yaml) across the
 * phase-2 engines (sigma-win, sigma-linux, mde, falco, velociraptor,
 * logpoint):
 *   - every suite attack has a row (same paper-trail contract as
 *     src/attackcheck.ts, TDS 11.3);
 *   - every cell status is one of detect / partial / blind / n-a;
 *   - every attack is detect|partial in at least ONE engine, OR its
 *     attack-matrix coverage class is a documented blind (BLIND-L7, K8S-API,
 *     ...) — engines cover each other's documented blind spots (TDS 13).
 */
import { DOCUMENTED_CLASSES, parseAttackNames, type MatrixRow } from "./attackcheck.ts";

export const ENGINE_STATUS: readonly string[] = ["detect", "partial", "blind", "n-a"];

export interface EngineRow {
  num: number;
  attack: string;
  /** cell status per engine, in the doc's column order */
  statuses: string[];
  notes: string;
}

/** Rows of the engine matrix table: | # | attack | sigma-win | sigma-linux | mde | falco | velociraptor | logpoint | notes | */
export function parseEngineRows(markdownSource: string, engineCount: number): Map<string, EngineRow> {
  const rows = new Map<string, EngineRow>();
  for (const line of markdownSource.split("\n")) {
    const cells = line.split("|").map((c) => c.trim());
    if (cells.length !== engineCount + 5) continue; // leading + trailing empty cells + num/attack/engines/notes
    if (!/^\d+$/.test(cells[1] ?? "")) continue; // header / separator / rule-table rows
    rows.set(cells[2]!, {
      num: Number(cells[1]),
      attack: cells[2]!,
      statuses: cells.slice(3, 3 + engineCount).map((c) => c.split(/\s+/)[0] ?? ""),
      notes: cells[3 + engineCount] ?? "",
    });
  }
  return rows;
}


export interface EngineCheckResult {
  ok: boolean;
  attackCount: number;
  rowCount: number;
  problems: string[];
}

export function runEngineMatrixCheck(
  suiteYaml: string,
  engineMarkdown: string,
  attackMatrixRows: Map<string, MatrixRow>,
  engineCount: number,
): EngineCheckResult {
  const problems: string[] = [];
  const attacks = parseAttackNames(suiteYaml);
  const rows = parseEngineRows(engineMarkdown, engineCount);

  for (const name of attacks) {
    const row = rows.get(name);
    if (row === undefined) {
      problems.push(`no engine-matrix row: ${name}`);
      continue;
    }
    for (let i = 0; i < row.statuses.length; i++) {
      if (!(ENGINE_STATUS as readonly string[]).includes(row.statuses[i] ?? "")) {
        problems.push(`row #${row.num} (${name}): engine column ${i} status "${row.statuses[i]}" is not one of ${ENGINE_STATUS.join("/")}`);
      }
    }
    const covered = row.statuses.some((s) => s === "detect" || s === "partial");
    const documentedBlind =
      DOCUMENTED_CLASSES.some((c) => (attackMatrixRows.get(name)?.coverageClass ?? "").includes(c));
    if (!covered && !documentedBlind) {
      problems.push(`row #${row.num} (${name}): no engine detects/partially covers it and no documented blind class`);
    }
  }
  const attackSet = new Set(attacks);
  for (const row of rows.values()) {
    if (!attackSet.has(row.attack)) {
      problems.push(`stale engine-matrix row: ${row.attack} (#${row.num}) — not in the upstream suite`);
    }
  }

  return {
    ok: problems.length === 0,
    attackCount: attacks.length,
    rowCount: rows.size,
    problems,
  };
}

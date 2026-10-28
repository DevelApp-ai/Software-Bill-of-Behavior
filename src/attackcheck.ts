/**
 * Attack-suite false-negative check (TDS 11.3, M4 / issue #5).
 *
 * Asserts that every attack in the upstream kill-chain suite
 * (docs/upstream-redis-attacks.yaml, from k8sstormcenter/bob
 * example/redis-attacks.yaml) has a row in docs/attack-matrix.md that is
 * either:
 *   - detected: the row names at least one generated rule id (100xxx band), or
 *   - documented: the row carries a declared blind/partial coverage class
 *     (BLIND-L7, DNS-NAME, M4-PENDING, FILELESS-EXE, K8S-API).
 *
 * An attack that is neither detected nor documented is a false negative in
 * the making: the CI gate fails the build until the matrix accounts for it.
 *
 * Operational flow (TDS 11.3): `bobctl simulate --suite redis-attacks.yaml`
 * generates the kill-chain traffic in a lab cluster; captured runs are
 * replayed against the generated bundle with scripts/logtest-corpus.sh
 * (benign corpus must stay silent, drift corpus must fire the mapped rules).
 * This module statically asserts the paper trail between the suite and the
 * rules so the two cannot drift apart.
 */

/** Coverage classes that document a blind or partial spot instead of a rule id. */
export const DOCUMENTED_CLASSES: readonly string[] = [
  "BLIND-L7",
  "DNS-NAME",
  "M4-PENDING",
  "FILELESS-EXE",
  "K8S-API",
];

export interface MatrixRow {
  num: number;
  attack: string;
  detection: string;
  coverageClass: string;
}

/**
 * Attack names from the upstream suite YAML, in suite order.
 *
 * The suite file uses block scalars (`>-`) in metadata, which the sbobctl
 * YAML-subset parser intentionally rejects (anchors/aliases/block scalars are
 * loud-failure constructs for SBoB sources, TDS Appendix B). The suite is
 * reference data, not a source SBoB, so attack names are extracted with a
 * strict line scanner over the `attacks:` sequence: entries are exactly
 * `  - name: <kebab-name>` — anything else in the file is metadata or attack
 * detail and does not match.
 */
export function parseAttackNames(yamlSource: string): string[] {
  const names: string[] = [];
  let inAttacks = false;
  for (const line of yamlSource.split("\n")) {
    if (/^attacks:/.test(line)) {
      inAttacks = true;
      continue;
    }
    if (inAttacks) {
      const m = line.match(/^  - name: (\S+)\s*$/);
      if (m !== null) {
        names.push(m[1]);
        continue;
      }
      // end of the attacks sequence: a top-level key after `attacks:`
      if (/^\S/.test(line)) inAttacks = false;
    }
  }
  return names;
}

/** Rows of the markdown matrix table, keyed by attack name. */
export function parseMatrixRows(markdownSource: string): Map<string, MatrixRow> {
  const rows = new Map<string, MatrixRow>();
  for (const line of markdownSource.split("\n")) {
    const m = line.match(/^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|\s*$/);
    if (m === null) continue;
    const num = Number(m[1]);
    const attack = m[2].trim();
    if (attack === "Attack" || attack.startsWith("---")) continue; // header / separator
    rows.set(attack, {
      num,
      attack,
      detection: m[5].trim(),
      coverageClass: m[6].trim(),
    });
  }
  return rows;
}

/** True when the detection column names at least one 100xxx-band rule id. */
export function namesRuleId(detection: string): boolean {
  return /\b100\d{3}\b/.test(detection);
}

/** True when the class column declares a documented blind/partial class. */
export function namesDocumentedClass(coverageClass: string): boolean {
  return DOCUMENTED_CLASSES.some((c) => coverageClass.includes(c));
}

export interface AttackCheckResult {
  ok: boolean;
  attackCount: number;
  rowCount: number;
  problems: string[];
}

/**
 * Full suite-vs-matrix check. Problems:
 *   - `no matrix row: <attack>` — attack missing from the matrix (false negative)
 *   - `stale matrix row: <attack> (#<num>)` — matrix row without a suite attack
 *   - `row #<num> (<attack>): neither a detection rule id nor a documented class`
 */
export function runAttackSuiteCheck(yamlSource: string, markdownSource: string): AttackCheckResult {
  const problems: string[] = [];
  const attackNames = parseAttackNames(yamlSource);
  const rows = parseMatrixRows(markdownSource);

  for (const name of attackNames) {
    const row = rows.get(name);
    if (row === undefined) {
      problems.push(`no matrix row: ${name}`);
      continue;
    }
    if (!namesRuleId(row.detection) && !namesDocumentedClass(row.coverageClass)) {
      problems.push(`row #${row.num} (${name}): neither a detection rule id nor a documented blind/partial class`);
    }
  }
  const attackSet = new Set(attackNames);
  for (const row of rows.values()) {
    if (!attackSet.has(row.attack)) {
      problems.push(`stale matrix row: ${row.attack} (#${row.num}) — not in the upstream suite`);
    }
  }

  return {
    ok: problems.length === 0,
    attackCount: attackNames.length,
    rowCount: rows.size,
    problems,
  };
}

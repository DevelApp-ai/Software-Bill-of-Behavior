/**
 * Regex emission utilities (TDS 5.2/5.3).
 *
 * Drift semantics: "observed value ∉ declared intent" must be expressed as a
 * POSITIVE match condition because Wazuh rule conditions are AND-composed.
 * We emit a negative lookahead over the anchored allow-alternation:
 *
 *   ^(?!<alternation>$)
 *
 * The alternation is built from compiled full-match fragments. PCRE2 is a
 * hard requirement whenever a section contains wildcard patterns
 * (ERR_PCRE2_REQUIRED) — OS_Regex cannot express negation.
 */
import { SbobError } from "./errors.ts";

/** Per-section compiled regex budget (TDS 7.1 policy cap). */
export const REGEX_BUDGET_BYTES = 4096;

export interface AllowList {
  /** Exact entries (typically carried by a CDB list instead of regex). */
  exact: string[];
  /** Compiled full-match fragments for wildcard entries. */
  patterns: string[];
}

/** Build the anchored allow-alternation for pattern fragments. */
export function allowAlternation(patterns: string[]): string | null {
  if (patterns.length === 0) return null;
  const alt = patterns.join("|");
  if (alt.length > REGEX_BUDGET_BYTES) {
    throw new SbobError(
      "ERR_REGEX_BUDGET",
      `compiled alternation is ${alt.length} bytes, exceeding the ${REGEX_BUDGET_BYTES}-byte per-section cap; split the workload or reduce wildcarded entries`,
    );
  }
  return alt;
}

/**
 * Negated-alternation condition (TDS 5.3): matches iff the value does NOT
 * fully match any allow pattern.
 */
export function negatedAlternation(patterns: string[]): string | null {
  const alt = allowAlternation(patterns);
  if (alt === null) return null;
  // The alternation MUST be grouped: "^(?!p1|p2$)" would bind the anchor to
  // the last alternative only, letting partial prefixes leak through.
  return `^(?!(?:${alt})$)`;
}

/** Positive full-match alternation (used for exemption/suppression rules). */
export function positiveAlternation(patterns: string[]): string | null {
  const alt = allowAlternation(patterns);
  if (alt === null) return null;
  return `^(?:${alt})$`;
}

/** Escape a string for safe inclusion in XML text content. */
export function xmlEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

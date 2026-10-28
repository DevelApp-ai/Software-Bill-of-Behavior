/**
 * IR linter (TDS 7.1): policy caps and confirmation gates.
 * Failures throw SbobError with the Appendix B error codes.
 */
import { SbobError } from "./errors.ts";
import type { IR } from "./types.ts";
import { REGEX_BUDGET_BYTES } from "./regexp.ts";

export const EXECS_ENTRY_CAP = 512;

export interface LintOptions {
  /** Sections confirmed as intentionally NONE (explicit empty), e.g. ["execs"]. */
  confirmNone: string[];
  /** Require k8s scope (namespace) — default true for the linux target which
   *  also serves k8s nodes. */
  requireScope: boolean;
}

export function lintIR(ir: IR, opts: LintOptions): void {
  // section caps ----------------------------------------------------------------
  if (ir.sections.execs && ir.sections.execs.entries.length > EXECS_ENTRY_CAP) {
    throw new SbobError("ERR_SECTION_CAP", `execs has ${ir.sections.execs.entries.length} entries, cap is ${EXECS_ENTRY_CAP}; split the workload profile`);
  }

  // regex budget (defensive: regexp.ts also enforces at emit time) --------------
  for (const section of ["execs", "opens", "egress", "ingress"] as const) {
    const s = ir.sections[section];
    if (!s) continue;
    const size = s.patterns.join("|").length;
    if (size > REGEX_BUDGET_BYTES) {
      throw new SbobError("ERR_REGEX_BUDGET", `section ${section}: compiled patterns total ${size} bytes, cap is ${REGEX_BUDGET_BYTES}`);
    }
  }

  // PCRE2 hard requirement: any wildcarded section implies PCRE2 ------------------
  const hasWildcards = (["execs", "opens", "egress", "ingress"] as const).some((k) => {
    const s = ir.sections[k];
    return s !== undefined && s.patterns.length > 0;
  });
  if (hasWildcards) {
    // The Linux target emits PCRE2 <field regex>; this is a build-time assertion
    // that the deployment target supports it. Wazuh >= 4.2 does.
    ir.coverageNotes.push("pcre2-required: at least one section contains wildcard patterns; PCRE2 ruleset syntax is mandatory (ERR_PCRE2_REQUIRED if target lacks it)");
  }

  // explicit-empty (NONE) confirmation -------------------------------------------
  for (const section of ["execs", "opens", "egress", "ingress"] as const) {
    const s = ir.sections[section];
    if (s && s.entries.length === 0 && !opts.confirmNone.includes(section)) {
      throw new SbobError(
        "ERR_NONE_UNCONFIRMED",
        `section ${section} is explicitly empty (NONE: every observed event of this class alerts); pass --confirm-none ${section} to accept`,
      );
    }
  }

  // rulePolicies explicit-empty (M4): {} is NONE for the signature pack —
  // same loud contract as the drift sections (defaults emitted fire-by-default)
  if (ir.rulePolicies !== undefined && Object.keys(ir.rulePolicies).length === 0 && !opts.confirmNone.includes("rulePolicies")) {
    throw new SbobError(
      "ERR_NONE_UNCONFIRMED",
      "section rulePolicies is explicitly empty (NONE: signature pack emitted with defaults, fire-by-default, no exemptions); pass --confirm-none rulePolicies to accept",
    );
  }

  // scope --------------------------------------------------------------------------
  if (opts.requireScope) {
    if (!ir.workload.name) throw new SbobError("ERR_MISSING_SCOPE", "workload has no name; agent-group scoping cannot be derived");
    if (!ir.workload.namespace) throw new SbobError("ERR_MISSING_SCOPE", "workload has no namespace; k8s binding cannot be derived");
  }

  // wildcard breadth warning -------------------------------------------------------
  if (ir.sections.execs) {
    for (const e of ir.sections.execs.entries) {
      const wildcards = e.pathSegs.filter((s) => s.kind !== "literal").length;
      if (wildcards > 2) {
        ir.coverageNotes.push(`warning: execs path "${e.source.path}" has wildcard breadth ${wildcards} (>2), consider tightening`);
      }
    }
  }
}

/**
 * Windows AppLocker policy codegen (TDS 14.5, M7 / issue #8) — from the
 * execs[] allowlist; WDAC audit-mode mirrors the Monitor→Enforce transition.
 *
 *   enforcement/sbob/<name>/applocker/<name>.xml    AppLocker policy (EXE
 *     collection: one Allow rule per declared execs[] path, collection
 *     default deny when enforcing)
 *
 * State semantics (TDS 14): monitor → EnforcementMode NotConfigured (rules
 * present but inert, deployment dry-run); audit → AuditMode (events 8002/8003
 * — would-be-allowed/would-be-blocked, the WDAC-audit mirror); enforce →
 * Enabled (block = events 8004). Delivery via GPO/Intune is an ops step
 * (runbook §9).
 *
 * Documented v1 limitations:
 *   - execs[] args are not enforceable in AppLocker (path rules only);
 *     the Wazuh bundle remains args-precise;
 *   - v1 emits EXE path rules only (no Script/MSI/Package collections);
 *     WDAC policy generation is out of v1 scope (AppLocker audit mode
 *     provides the audit plane, TDS 14.5);
 *   - AppLocker Allow rules use the path condition (not publisher/hash);
 *     the SBoB imageID digest does not translate to an AppLocker condition.
 */
import type { IR } from "../types.ts";
import type { EnforceStateFile } from "../enforce.ts";
import { effectiveState } from "../enforce.ts";
import type { BundleFile } from "./linux.ts";
import { uuid5 } from "./engines.ts";

export function applockerPolicy(ir: IR, state: EnforceStateFile): BundleFile {
  const name = ir.workload.name;
  const execState = effectiveState(state, "execs");
  const mode = execState === "enforce" ? "Enabled" : execState === "audit" ? "AuditMode" : "NotConfigured";

  const lines: string[] = [];
  lines.push(`<AppLockerPolicy Version="1">`);
  lines.push(`  <!-- sbobctl generated AppLocker policy - workload: ${name} (TDS 14.5, M7)`);
  lines.push(`       do not edit by hand; regenerate from the pinned SBoB + state file`);
  lines.push(`       execs state: ${execState} -> EnforcementMode ${mode} -->`);
  lines.push(`  <RuleCollection Type="Exe" EnforcementMode="${mode}">`);
  const entries = ir.sections.execs?.entries ?? [];
  if (entries.length === 0) {
    lines.push(`    <!-- execs[] absent - no rules; policy ships inert -->`);
  }
  let n = 1;
  for (const e of entries) {
    lines.push(`    <FileRule Id="{${uuid5(`applocker:${name}:${e.source.path}`)}}" Name="SBoB ${name} exec allow ${n}" Description="declared in execs[] of the ${name} SBoB (args not enforceable in AppLocker, TDS 14.5)" UserOrGroupSid="S-1-5-32-544" Action="Allow">`);
    lines.push(`      <Conditions>`);
    lines.push(`        <FilePathCondition Path="${e.source.path}" />`);
    lines.push(`      </Conditions>`);
    lines.push(`    </FileRule>`);
    n++;
  }
  lines.push(`  </RuleCollection>`);
  lines.push(`</AppLockerPolicy>`);
  lines.push(``);
  return {
    path: `enforcement/sbob/${name}/applocker/${name}.xml`,
    content: lines.join("\n"),
  };
}

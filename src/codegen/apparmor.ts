/**
 * AppArmor profile codegen (TDS 14.3, M7 / issue #8) — generated from the
 * execs[] / opens[] allowlists.
 *
 *   enforcement/sbob/<name>/apparmor/<name>.profile
 *
 * State semantics (TDS 14): sections in monitor contribute commented-out
 * rules (visible but inert); audit contributes live rules under the
 * profile-global `complain` flag (AppArmor's audit mode — violations are
 * logged, allowed); enforce removes `complain`. The profile covers execs +
 * opens only — network (egress/ingress) is enforced by the NetworkPolicy
 * artifact, not AppArmor.
 *
 * Documented v1 limitations:
 *   - wildcard opens broaden: SBoB `/data/*` (starTail, one-or-more) maps to
 *     AppArmor `/data/**` (zero-or-more) — engine broadening, same policy as
 *     the Sigma glob handling (TDS 13);
 *   - opens flags map coarsely: O_RDONLY → r, O_WRONLY/O_CREAT/O_APPEND → w
 *     (+ k for O_CREAT); m stays with the base abstractions;
 *   - execs[] args are not enforced (AppArmor has no argv rules) — the
 *     Wazuh bundle remains args-precise;
 *   - the profile entry point is the first execs[] path (the workload
 *     binary); attach_disconnected keeps container behavior sane.
 */
import type { IR } from "../../types.ts";
import type { OpenCompiled, ExecCompiled } from "../../types.ts";
import type { EnforceStateFile, EnforceSectionKey } from "../enforce.ts";
import { effectiveState } from "../enforce.ts";
import type { BundleFile } from "./linux.ts";

/** SBoB opens flags → AppArmor permission chars. */
function apparmorPerms(entry: OpenCompiled): string {
  const flags = entry.source.flags ?? [];
  const perm = new Set<string>();
  if (flags.includes("O_RDONLY")) perm.add("r");
  if (flags.includes("O_WRONLY")) perm.add("w");
  if (flags.includes("O_CREAT")) {
    perm.add("w");
    perm.add("k");
  }
  if (flags.includes("O_APPEND")) {
    perm.add("w");
    perm.add("a");
  }
  if (perm.size === 0) return "rw";
  // deterministic order: r, w, k, a
  return ["r", "w", "k", "a"].filter((c) => perm.has(c)).join("");
}

/** SBoB path → AppArmor glob (starTail one-or-more broadens to ** zero-or-more). */
export function apparmorGlob(path: string): string {
  return path.replace(/\*$/, "**");
}

export function apparmorProfile(ir: IR, state: EnforceStateFile): BundleFile {
  const name = ir.workload.name;
  const execState = effectiveState(state, "execs");
  const openState = effectiveState(state, "opens");
  const enforcing = execState === "enforce" || openState === "enforce";
  if (execState === "monitor" && openState === "monitor") {
    // both sections inert: no profile (the enforce command checks this before calling)
    throw new Error("apparmorProfile called with execs and opens both in monitor state");
  }

  const lines: string[] = [];
  lines.push(`# sbobctl generated AppArmor profile — workload: ${name} (TDS 14.3, M7)`);
  lines.push(`# do not edit by hand; regenerate from the pinned SBoB + state file`);
  lines.push(`# states: execs=${execState} opens=${openState} — ${
    enforcing ? "ENFORCE (blocking) mode" : "AUDIT (complain) mode: violations are logged, allowed"
  }`);
  lines.push(`abi <abi/3.0>,`);
  lines.push(``);
  lines.push(`#include <tunables/global>`);
  lines.push(``);
  const flags = enforcing ? "attach_disconnected" : "attach_disconnected, complain";
  // attachment point = the first declared execs[] path (the workload binary)
  const attach = ir.sections.execs?.entries[0]?.source.path ?? `/usr/bin/${name}`;
  lines.push(`profile sbob-${name} ${attach} flags=(${flags}) {`);
  lines.push(`  #include <abstractions/base>`);
  lines.push(``);

  lines.push(`  # execs[] — process execution allowlist (args not enforceable, TDS 14.3)`);
  const execs: ExecCompiled[] = ir.sections.execs?.entries ?? [];
  if (execs.length === 0) {
    lines.push(`  # (execs[] absent — no execution rules; the profile only observes opens)`);
  }
  for (const e of execs) {
    if (execState === "monitor") {
      lines.push(`  # monitor (inert): ${e.source.path} ixr — section still in Monitor state`);
    } else {
      lines.push(`  ${e.source.path} ixr,`);
    }
  }
  lines.push(``);

  lines.push(`  # opens[] — file access allowlist (flags map coarsely, TDS 14.3)`);
  const opens: OpenCompiled[] = ir.sections.opens?.entries ?? [];
  if (opens.length === 0) {
    lines.push(`  # (opens[] absent — no file rules)`);
  }
  for (const o of opens) {
    const glob = apparmorGlob(o.source.path);
    if (openState === "monitor") {
      lines.push(`  # monitor (inert): ${glob} ${apparmorPerms(o)} — section still in Monitor state`);
    } else {
      lines.push(`  ${glob} ${apparmorPerms(o)},`);
    }
  }
  lines.push(`}`);
  lines.push(``);

  return {
    path: `enforcement/sbob/${name}/apparmor/${name}.profile`,
    content: lines.join("\n"),
  };
}

/** Whether the profile should be emitted at all (any live or audited section). */
export function apparmorApplicable(state: EnforceStateFile): boolean {
  const s: EnforceSectionKey[] = ["execs", "opens"];
  return s.some((k) => effectiveState(state, k) !== "monitor");
}

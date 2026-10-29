/**
 * LogPoint codegen (TDS 13, M6 / issue #7): IR sections → LogPoint search
 * rules on the linux/auditd plane.
 *
 * One rule file per section:
 *   logpoint/sbob/<name>_execs_linux.lql    auditd execve allowlist inversion
 *   logpoint/sbob/<name>_opens_linux.lql    auditd open/openat allowlist inversion
 *   logpoint/sbob/<name>_egress_linux.lql   auditd connect (ip/port pairs)
 *
 * Semantics: the SBoB allowlist is inverted with LQL negation (`-`), so the
 * rule matches undeclared behavior — a LogPoint search/alert built on it
 * fires exactly on drift. Field names follow LogPoint's own auditd taxonomy
 * as shipped in the official pySigma backend (logpoint/pySigma-backend-
 * logpoint, sigma/pipelines/logpoint/logpoint_mapping.py): auditd
 * type→event_type, exe→path, name→path, comm→command. Fields the taxonomy
 * does not normalize (syscall, daddr, dport) pass through raw — the same
 * field set `sigma convert -t logpoint -p logpoint_linux` produces from the
 * sigma bundle, which the engines-lab CI lane cross-checks against LogPoint's
 * own conversion.
 *
 * Documented v1 limitations (docs/engine-matrix.md):
 *   - windows planes are v1-blind here — windows coverage rides the Sysmon
 *     sigma rules through LogPoint's own logpoint_windows pipeline (CI lane);
 *   - execs[] args are not enforced (path-level `path IN [...]` filters) —
 *     the Wazuh bundle remains the args-precise detector;
 *   - opens[] flags are not enforced;
 *   - egress[] remote addressing uses raw auditd daddr/dport — LogPoint's
 *     auditd taxonomy does not normalize destination fields (matrix connect
 *     cells stay `partial`);
 *   - egress DNS names are not evaluable on the auditd plane (DNS-NAME
 *     documented blind);
 *   - `*` globs may cross a `/` where the SBoB ⋯ wildcard would not
 *     (engine broadening, TDS 13).
 */
import type { IR } from "../types.ts";
import type { BundleFile } from "./linux.ts";
import { engineManifest, pathGlob } from "./engines.ts";

function lqlString(s: string): string {
  return `"${s.replace(/"/g, '\\"')}"`;
}

/** Section entries partitioned into exact paths and wildcard globs. */
function splitGlobs(entries: { isExact: boolean; pathSegs: { kind: string; text?: string }[] }[]): {
  exact: string[];
  globbed: string[];
} {
  const exact: string[] = [];
  const globbed: string[] = [];
  for (const e of entries) {
    const g = pathGlob(e.pathSegs as never);
    (e.isExact ? exact : globbed).push(g);
  }
  return { exact, globbed };
}

export function generateLogPointBundle(ir: IR): BundleFile[] {
  const files: BundleFile[] = [];
  const name = ir.workload.name;
  const notes: string[] = [];

  // execs — auditd execve ------------------------------------------------------
  if (ir.sections.execs) {
    const { exact, globbed } = splitGlobs(ir.sections.execs.entries);
    if (exact.length + globbed.length > 0) {
      const filter = [...exact, ...globbed].map(lqlString).join(", ");
      files.push({
        path: `logpoint/sbob/${name}_execs_linux.lql`,
        content: `"event_type"="SYSCALL" "syscall"="execve" - ("path" IN [${filter}])\n`,
      });
    }
  } else {
    notes.push("logpoint: execs[] section absent — no exec drift rule emitted (section-absent semantics, TDS 8)");
  }

  // opens — auditd open/openat --------------------------------------------------
  if (ir.sections.opens) {
    const { exact, globbed } = splitGlobs(ir.sections.opens.entries);
    if (exact.length + globbed.length > 0) {
      const filter = [...exact, ...globbed].map(lqlString).join(", ");
      files.push({
        path: `logpoint/sbob/${name}_opens_linux.lql`,
        content: `"event_type"="SYSCALL" "syscall" IN ["open", "openat"] - ("path" IN [${filter}])\n`,
      });
    }
  } else {
    notes.push("logpoint: opens[] section absent — no open drift rule emitted (section-absent semantics, TDS 8)");
  }

  // egress — auditd connect pairs + DNS -----------------------------------------
  if (ir.sections.egress) {
    const peers = ir.sections.egress.entries.filter((e) => e.addrEntries.length > 0);
    if (peers.length > 0) {
      const groups = peers.map((peer) => {
        const ips = peer.addrEntries.map((a) => a.split("/")[0]!).map(lqlString);
        const ports = peer.ports.filter((p) => p !== null);
        const ipCond = `"daddr" IN [${ips.join(", ")}]`;
        return ports.length > 0 ? `(${ipCond} AND "dport" IN [${ports.join(", ")}])` : `(${ipCond})`;
      });
      files.push({
        path: `logpoint/sbob/${name}_egress_linux.lql`,
        content: `"event_type"="SYSCALL" "syscall"="connect" - (${groups.join(" OR ")})\n`,
      });
      notes.push("logpoint: egress[] remote addressing uses raw auditd daddr/dport — LogPoint's auditd taxonomy does not normalize destination fields (matrix connect cells stay partial)");
    }
    const dnsNames: string[] = [];
    for (const e of ir.sections.egress.entries) dnsNames.push(...e.dnsPatterns, ...e.dnsExact);
    if (dnsNames.length > 0) {
      notes.push("logpoint: egress[] dnsNames are not evaluable on the auditd plane — DNS-NAME documented blind (TDS 13); the Sysmon EID 22 sigma rule covers the windows plane");
    }
  } else {
    notes.push("logpoint: egress[] section absent — no egress drift rule emitted (section-absent semantics, TDS 8)");
  }

  // ingress — documented blind (engine v1) --------------------------------------
  if (ir.sections.ingress) {
    notes.push("logpoint: ingress[] rules are not emitted in v1 — inbound accept-side telemetry is pipeline-specific; the Wazuh bundle remains the ingress detector (documented engine blind, docs/engine-matrix.md)");
  }

  notes.push(
    "logpoint: v1 emits the linux/auditd plane only — windows coverage rides the sigma bundle through LogPoint's logpoint_windows pySigma pipeline (engines-lab CI lane)",
    "logpoint: field names follow LogPoint's auditd taxonomy (logpoint/pySigma-backend-logpoint logpoint_mapping.py: type→event_type, exe→path, name→path); the engines-lab lane cross-checks the same mapping via sigma convert -t logpoint -p logpoint_linux",
    "logpoint: `*` globs may cross a `/` where the SBoB single-segment wildcard (⋯) would not — engine broadening documented in TDS 13 / docs/engine-matrix.md",
    "logpoint: the Wazuh bundle remains the args-precise, flag-precise primary detector",
  );

  engineManifest(ir, "logpoint", files, notes);
  return files;
}

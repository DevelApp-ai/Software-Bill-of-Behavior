/**
 * Velociraptor codegen (TDS 13, M6 / issue #7): IR sections → a per-workload
 * VQL artifact for hunt-time conformance sweeps and retro-scans.
 *
 *   velociraptor/sbob/<name>.yaml   Custom.SBoB.<Name>.Conformance artifact
 *
 * Semantics: the artifact asserts SBoB conformance from live system state —
 * `pslist()` sweeps against the execs[] allowlist and `netstat()` against the
 * egress[] ip/port pairs. Hunt-time only: a process that exited (or a
 * connection that closed) before the sweep is invisible — the Wazuh auditd
 * bundle remains the always-on detector; Velociraptor adds retro-scan reach
 * (the sweep covers the whole process table, including pre-existing drift
 * that auditd rules installed later would have missed).
 *
 * Documented v1 limitations (docs/engine-matrix.md):
 *   - execs[] args are not enforced (path-level);
 *   - egress DNS names are not evaluable from netstat state (DNS-NAME blind);
 *   - CIDR peers broader than /32 are matched on their collapsed base where
 *     applicable, otherwise documented partial;
 *   - opens[] has no Velociraptor v1 sweep (no live "open fds of every
 *     process" state without heavy instrumentation) — documented blind.
 */
import type { IR } from "../types.ts";
import type { BundleFile } from "./linux.ts";
import { engineManifest } from "./engines.ts";
import { escapeRegExp } from "../wildcards.ts";

export function generateVelociraptorBundle(ir: IR): BundleFile[] {
  const files: BundleFile[] = [];
  const name = ir.workload.name;
  const notes: string[] = [];
  const queries: string[] = [];

  // execs — pslist sweep ------------------------------------------------------
  if (ir.sections.execs) {
    const patterns = ir.sections.execs.entries.map((e) => e.pathRegex);
    if (patterns.length > 0) {
      queries.push(
        [
          `  // undeclared process execution: any process whose executable path is not in`,
          `  // the SBoB execs[] allowlist (anchored per-entry PCRE, RE2-safe)`,
          `  SELECT Pid, Name, Exe, CommandLine FROM pslist()`,
          `  WHERE NOT Exe =~ '^(?:${patterns.join("|")})$'`,
        ].join("\n"),
      );
    }
  } else {
    notes.push("velociraptor: execs[] section absent — no process conformance sweep emitted");
  }

  // opens — documented blind ---------------------------------------------------
  if (ir.sections.opens) {
    notes.push("velociraptor: opens[] has no v1 sweep (live open-fd state is not sweepable cheaply) — documented engine blind, Wazuh/MDE cover it");
  }

  // egress — netstat sweep ------------------------------------------------------
  if (ir.sections.egress) {
    const peers = ir.sections.egress.entries.filter((e) => e.addrEntries.length > 0);
    const blocks: string[] = [];
    let nonExact = false;
    for (const peer of peers) {
      const ips = peer.addrEntries.map((a) => {
        const [ip, mask] = a.split("/");
        if (mask !== "32") nonExact = true;
        return escapeRegExp(ip!);
      });
      const ports = peer.ports.filter((p): p is number => p !== null);
      const portRe = ports.length > 0 ? `:(?:${ports.join("|")})` : `:\\d+`;
      blocks.push(`(?:${ips.join("|")})${portRe}`);
    }
    if (blocks.length > 0) {
      if (nonExact) notes.push("velociraptor: egress CIDR peers broader than /32 are matched on the collapsed base ip — port-sweep state cannot range-match (documented partial)");
      queries.push(
        [
          `  // undeclared outbound connection: established sockets whose remote addr`,
          `  // (ip:port) is not in the SBoB egress[] allowlist pairs`,
          `  SELECT Pid, Name, Laddr, Raddr, Status FROM netstat()`,
          `  WHERE NOT Raddr =~ '^(?:${blocks.join("|")})$'`,
        ].join("\n"),
      );
    }
    if (ir.sections.egress.entries.some((e) => e.dnsPatterns.length > 0 || e.dnsExact.length > 0)) {
      notes.push("velociraptor: egress DNS names are not evaluable from socket state (DNS-NAME documented blind — Sysmon EID 22 / Wazuh cover it)");
    }
  } else {
    notes.push("velociraptor: egress[] section absent — no connection conformance sweep emitted");
  }

  notes.push(
    "velociraptor: hunt-time only — short-lived processes/connections between sweeps are invisible; the Wazuh auditd bundle remains the always-on detector (TDS 13)",
  );

  const body: string[] = [
    `name: Custom.SBoB.${name.charAt(0).toUpperCase()}${name.slice(1)}.Conformance`,
    `description: |`,
    `  SBoB conformance sweeps for workload ${name} (sbobctl transpile --target velociraptor; TDS 13).`,
    `  Each query returns rows that violate the pinned SBoB allowlists (drift).`,
    `  Hunt-time / retro-scan semantics — see the generated coverage notes for blind spots.`,
    `author: sbobctl (generated — do not edit by hand)`,
    `kind: server_event`,
    `parameters:`,
    `  - name: SweepInterval`,
    `    type: int`,
    `    default: 3600`,
    `    description: sweep cadence in seconds (hunt runs override)`,
    `sources:`,
    `  - name: sbob_conformance`,
    `    queries:`,
  ];
  for (const q of queries) {
    body.push(`      - |`);
    for (const line of q.split("\n")) {
      body.push(`        ${line.replace(/^  /, "")}`);
    }
  }

  files.push({ path: `velociraptor/sbob/${name}.yaml`, content: body.join("\n") + "\n" });
  if (queries.length === 0) {
    notes.push("velociraptor: no sweep queries emitted — the SBoB declares no sweepable sections");
  }

  engineManifest(ir, "velociraptor", files, notes);
  return files;
}

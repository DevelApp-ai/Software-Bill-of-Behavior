/**
 * Sigma codegen (TDS 13, M6 / issue #7): IR sections → Sigma rule YAML.
 *
 * One rule per section × logsource:
 *   sigma/sbob/<name>_execs_linux.yml    auditd execve allowlist inversion
 *   sigma/sbob/<name>_opens_linux.yml    auditd open/openat allowlist inversion
 *   sigma/sbob/<name>_egress_linux.yml   auditd connect (remote-ip pairs)
 *   sigma/sbob/<name>_execs_windows.yml  Sysmon EID 1 (Image allowlist)
 *   sigma/sbob/<name>_opens_windows.yml  Sysmon EID 11 (TargetFilename; file-create partial)
 *   sigma/sbob/<name>_egress_windows.yml Sysmon EID 3 (DestinationIp/DestinationPort pairs)
 *   sigma/sbob/<name>_dns_windows.yml    Sysmon EID 22 (QueryName)
 *
 * Semantics: Sigma rules invert the SBoB allowlist with filter blocks —
 * `condition: selection and not 1 of filter_*` alerts on undeclared behavior.
 * Community Sigma pipelines then fan the YAML out to Splunk/Sentinel/etc.
 *
 * Documented v1 limitations (docs/engine-matrix.md):
 *   - execs[] args are not enforced (path-level filters only) — the Wazuh
 *     bundle remains the args-precise detector;
 *   - opens[] flags are not enforced; the Windows rule is file-create (EID 11)
 *     only, matching the Wazuh Sysmon partial;
 *   - egress DNS names are evaluated by the EID 22 rule only — auditd/Sysmon
 *     EID 3 rules match declared IPs (DNS-NAME stays a documented blind there);
 *   - `*` glob semantics may cross `/` where the SBoB ⋯ wildcard would not
 *     (engine broadening, TDS 13).
 */
import type { IR } from "../types.ts";
import type { BundleFile } from "./linux.ts";
import { dnsGlob, engineManifest, pathGlob, uuid5 } from "./engines.ts";

function yamlQuote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function sigmaRule(ir: IR, section: string, doc: {
  title: string;
  description: string;
  logsource: string[];
  detection: string[];
  falsepositives: string;
  level: string;
}): BundleFile {
  const name = ir.workload.name;
  const lines: string[] = [
    // title is double-quoted: rule titles contain ": " (SBoB drift: ...) which
    // breaks strict YAML parsers as an unquoted scalar (pySigma/SigmaHQ issue,
    // caught by the engines-lab sigma lane)
    `title: ${yamlQuote(doc.title)}`,
    `id: ${uuid5(`${name}:${section}`)}`,
    `status: experimental`,
    `description: |`,
    `  ${doc.description}`,
    `references:`,
    `  - SBoB workload ${name} (sbobctl transpile --target sigma; TDS 13)`,
    `author: sbobctl (generated — do not edit by hand)`,
    `date: 2026/10/28`,
    `logsource:`,
    ...doc.logsource.map((l) => `  ${l}`),
    `detection:`,
    ...doc.detection.map((l) => `  ${l}`),
    `falsepositives:`,
    `  - ${doc.falsepositives}`,
    `level: ${doc.level}`,
    `tags:`,
    `  - sbob.${name}`,
    `  - sbob.drift`,
    `  - sbob.${section}`,
  ];
  return { path: `sigma/sbob/${name}_${section}.yml`, content: lines.join("\n") + "\n" };
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

export function generateSigmaBundle(ir: IR): BundleFile[] {
  const files: BundleFile[] = [];
  const name = ir.workload.name;
  const notes: string[] = [];

  // execs — linux/auditd -----------------------------------------------------
  if (ir.sections.execs) {
    const { exact, globbed } = splitGlobs(ir.sections.execs.entries);
    if (exact.length + globbed.length > 0) {
      files.push(sigmaRule(ir, "execs_linux", {
        title: `SBoB drift: ${name} undeclared process execution (execs[], auditd)`,
        description:
          `The ${name} SBoB declares its process allowlist (execs[]); an execve outside it is behavior drift. Path-level filter; exec args are enforced by the Wazuh bundle (TDS 13 limitation).`,
        logsource: [`product: linux`, `service: auditd`],
        detection: [
          `selection:`,
          `  type: SYSCALL`,
          `  syscall: execve`,
          `filter_sbob_execs:`,
          `  exe:`,
          ...[...exact, ...globbed].map((v) => `      - ${yamlQuote(v)}`),
          `condition: selection and not filter_sbob_execs`,
        ],
        falsepositives: "legitimate automation the SBoB has not declared yet — update the SBoB, not the rule",
        level: "high",
      }));
      files.push(sigmaRule(ir, "execs_windows", {
        title: `SBoB drift: ${name} undeclared process execution (execs[], Sysmon EID 1)`,
        description:
          `Sysmon process-create against the ${name} SBoB execs[] allowlist. Image path-level filter; CommandLine args are enforced by the Wazuh bundle (TDS 13 limitation).`,
        logsource: [`product: windows`, `service: sysmon`],
        detection: [
          `selection:`,
          `  EventID: 1`,
          `filter_sbob_execs:`,
          `  Image:`,
          ...[...exact, ...globbed].map((v) => `      - ${yamlQuote(v)}`),
          `condition: selection and not filter_sbob_execs`,
        ],
        falsepositives: "legitimate automation the SBoB has not declared yet — update the SBoB, not the rule",
        level: "high",
      }));
    }
  } else {
    notes.push("sigma: execs[] section absent — no exec drift rules emitted (section-absent semantics, TDS 8)");
  }

  // opens — linux/auditd + windows EID 11 ------------------------------------
  if (ir.sections.opens) {
    const { exact, globbed } = splitGlobs(ir.sections.opens.entries);
    if (exact.length + globbed.length > 0) {
      files.push(sigmaRule(ir, "opens_linux", {
        title: `SBoB drift: ${name} undeclared file open (opens[], auditd)`,
        description:
          `File opens outside the ${name} SBoB opens[] allowlist. Path-level filter; open flags are enforced by the Wazuh bundle (TDS 13 limitation).`,
        logsource: [`product: linux`, `service: auditd`],
        detection: [
          `selection:`,
          `  type: SYSCALL`,
          `  syscall:`,
          `    - open`,
          `    - openat`,
          `filter_sbob_opens:`,
          `  name:`,
          ...[...exact, ...globbed].map((v) => `      - ${yamlQuote(v)}`),
          `condition: selection and not filter_sbob_opens`,
        ],
        falsepositives: "short-lived runtime files under already-allowed directory patterns — widen the SBoB entry instead",
        level: "medium",
      }));
      files.push(sigmaRule(ir, "opens_windows", {
        title: `SBoB drift: ${name} undeclared file create (opens[], Sysmon EID 11)`,
        description:
          `Sysmon file-create against the ${name} SBoB opens[] allowlist — file-create telemetry only (the Wazuh EID 11 partial, TDS 8.2): read opens are invisible here.`,
        logsource: [`product: windows`, `service: sysmon`],
        detection: [
          `selection:`,
          `  EventID: 11`,
          `filter_sbob_opens:`,
          `  TargetFilename:`,
          ...[...exact, ...globbed].map((v) => `      - ${yamlQuote(v)}`),
          `condition: selection and not filter_sbob_opens`,
        ],
        falsepositives: "file creates by tooling the SBoB has not declared — update the SBoB",
        level: "medium",
      }));
    }
  } else {
    notes.push("sigma: opens[] section absent — no open drift rules emitted (section-absent semantics, TDS 8)");
  }

  // egress — connect pairs + DNS ----------------------------------------------
  if (ir.sections.egress) {
    const peers = ir.sections.egress.entries.filter((e) => e.addrEntries.length > 0);
    if (peers.length > 0) {
      const ipFilter = (ipField: string, portField: string): string[] => {
        const blocks: string[] = [];
        peers.forEach((peer, i) => {
          const ips = peer.addrEntries.map((a) => a.split("/")[0]!);
          const ports = peer.ports.filter((p) => p !== null);
          blocks.push(`filter_peer_${i}:`, `  ${ipField}:`);
          for (const ip of ips) blocks.push(`      - ${yamlQuote(ip)}`);
          if (ports.length > 0) {
            blocks.push(`  ${portField}:`);
            for (const p of ports) blocks.push(`      - ${p}`);
          }
        });
        return blocks;
      };
      files.push(sigmaRule(ir, "egress_linux", {
        title: `SBoB drift: ${name} undeclared outbound connect (egress[], auditd)`,
        description:
          `Outbound connects outside the ${name} SBoB egress[] allowlist (ip/port pairs). Remote-address field naming depends on the auditd pipeline (saddr decode); declared DNS names are covered by the Sysmon EID 22 rule (TDS 13 limitation).`,
        logsource: [`product: linux`, `service: auditd`],
        detection: [
          `selection:`,
          `  type: SYSCALL`,
          `  syscall: connect`,
          ...ipFilter("daddr", "dport"),
          `condition: selection and not 1 of filter_peer_*`,
        ],
        falsepositives: "new legitimately required egress — declare it in the SBoB",
        level: "medium",
      }));
      files.push(sigmaRule(ir, "egress_windows", {
        title: `SBoB drift: ${name} undeclared outbound connect (egress[], Sysmon EID 3)`,
        description:
          `Sysmon network-connect against the ${name} SBoB egress[] allowlist (DestinationIp/DestinationPort pairs); declared DNS names are covered by the EID 22 rule.`,
        logsource: [`product: windows`, `service: sysmon`],
        detection: [
          `selection:`,
          `  EventID: 3`,
          ...ipFilter("DestinationIp", "DestinationPort"),
          `condition: selection and not 1 of filter_peer_*`,
        ],
        falsepositives: "new legitimately required egress — declare it in the SBoB",
        level: "medium",
      }));
    }
    const dnsNames: string[] = [];
    for (const e of ir.sections.egress.entries) dnsNames.push(...e.dnsPatterns.map(dnsGlob), ...e.dnsExact.map(dnsGlob));
    if (dnsNames.length > 0) {
      files.push(sigmaRule(ir, "dns_windows", {
        title: `SBoB drift: ${name} undeclared DNS resolution (egress[].dnsNames, Sysmon EID 22)`,
        description:
          `DNS queries outside the ${name} SBoB egress[] dnsNames allowlist — the L7 answer to the DNS-NAME blind spot on the connect-side rules (TDS 13).`,
        logsource: [`product: windows`, `service: sysmon`],
        detection: [
          `selection:`,
          `  EventID: 22`,
          `filter_sbob_dns:`,
          `  QueryName:`,
          ...[...new Set(dnsNames)].map((v) => `      - ${yamlQuote(v)}`),
          `condition: selection and not filter_sbob_dns`,
        ],
        falsepositives: "CDN or SDK domains the workload legitimately resolves — declare them in the SBoB",
        level: "medium",
      }));
    }
  } else {
    notes.push("sigma: egress[] section absent — no egress drift rules emitted (section-absent semantics, TDS 8)");
  }

  // ingress — documented blind (engine v1) ------------------------------------
  if (ir.sections.ingress) {
    notes.push("sigma: ingress[] rules are not emitted in v1 — inbound accept-side telemetry is pipeline-specific; the Wazuh bundle remains the ingress detector (documented engine blind, docs/engine-matrix.md)");
  }

  notes.push(
    "sigma: `*` globs may cross a `/` where the SBoB single-segment wildcard (⋯) would not — engine broadening documented in TDS 13 / docs/engine-matrix.md",
    "sigma: generated for community Sigma pipelines (Splunk/Sentinel/...); the Wazuh bundle remains the args-precise, flag-precise primary detector",
  );

  engineManifest(ir, "sigma", files, notes);
  return files;
}

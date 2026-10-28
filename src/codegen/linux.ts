/**
 * Linux / k8s-node codegen (TDS sections 4.2, 6.2, 6.4, 7.2).
 *
 * Emits, per workload:
 *   - wazuh/audit/sbob/<name>.rules        auditctl fragment (Mode A preferred)
 *   - wazuh/decoders/sbob/<name>.xml       custom decoder chain (lab validation pending)
 *   - wazuh/lists/sbob/<name>/*            CDB allowlists (execs, opens, egress_addrs, ingress_addrs)
 *   - wazuh/rules/sbob/<base>_<name>_linux.xml   base + drift + escalation rules
 *   - <name>.manifest.json                 workload bundle manifest + coverage notes
 */
import { negatedAlternation, xmlEscape } from "../regexp.ts";
import { portAlternation } from "../wildcards.ts";
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { Decoder, XmlRule } from "./xml.ts";
import { renderDecoder, renderRule, xmlFileHeader } from "./xml.ts";

export interface BundleFile {
  path: string;
  content: string;
}

const LAB_NOTE = "LAB VALIDATION PENDING (M1 exit criteria): run scripts/logtest-corpus.sh against a lab node with a live wazuh manager";

export function generateLinuxBundle(ir: IR, alloc: IdAllocator): BundleFile[] {
  const name = ir.workload.name;
  const files: BundleFile[] = [];
  const s = ir.sections;
  const auditKeys: string[] = [];
  const modeA = s.execs !== undefined && s.execs.exact.length > 0;

  // --------------------------------------------------------------------------
  // 1. auditctl fragment
  // --------------------------------------------------------------------------
  {
    const lines: string[] = [
      `# sbobctl generated audit rules — workload: ${name} (SBoB v${ir.workload.sbobVersion})`,
      `# image: ${ir.workload.imageID}`,
      modeA
        ? "# Mode A (exe-scoped): only the workload's declared executables generate events."
        : "# Mode B (node-wide): workload has no literal exec paths; events are scoped by Wazuh rules only.",
      "",
    ];
    if (modeA) {
      for (const exe of s.execs!.exact) {
        lines.push(`-a always,exit -F arch=b64 -S execve -F exe=${exe} -k sbob-exec-${name}`);
        lines.push(`-a always,exit -F arch=b32 -S execve -F exe=${exe} -k sbob-exec-${name}`);
      }
    } else {
      lines.push(`-a always,exit -F arch=b64 -S execve -k sbob-exec`);
      lines.push(`-a always,exit -F arch=b32 -S execve -k sbob-exec`);
    }
    lines.push("");
    if (s.opens !== undefined) {
      if (modeA) {
        for (const exe of s.execs!.exact) {
          lines.push(`-a always,exit -F arch=b64 -S open,openat -F exe=${exe} -k sbob-open-${name}`);
        }
      } else {
        lines.push(`-a always,exit -F arch=b64 -S open,openat -k sbob-open`);
      }
    }
    if (s.egress !== undefined) {
      if (modeA) {
        for (const exe of s.execs!.exact) {
          lines.push(`-a always,exit -F arch=b64 -S connect -F exe=${exe} -k sbob-connect-${name}`);
        }
      } else {
        lines.push(`-a always,exit -F arch=b64 -S connect -k sbob-connect`);
      }
    }
    // signature-rule syscalls (rulePolicies, M4) are emitted by the M4 codegen.
    files.push({ path: `wazuh/audit/sbob/${name}.rules`, content: lines.join("\n") + "\n" });
    if (s.execs !== undefined) auditKeys.push(modeA ? `sbob-exec-${name}` : "sbob-exec");
    if (s.opens !== undefined) auditKeys.push(modeA ? `sbob-open-${name}` : "sbob-open");
    if (s.egress !== undefined) auditKeys.push(modeA ? `sbob-connect-${name}` : "sbob-connect");
  }

  // --------------------------------------------------------------------------
  // 2. CDB allowlists
  // --------------------------------------------------------------------------
  if (s.execs && s.execs.exact.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/execs`,
      content: CDB_HEADER("execs allowlist (exact entries); wildcard entries live in the rules XML") +
        s.execs.exact.map((e) => `${e}:1`).join("\n") + "\n",
    });
  }
  if (s.opens && s.opens.exact.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/opens`,
      content: CDB_HEADER("opens allowlist: key=path, value=flag bitmask (TDS 6.4); wildcard entries live in the rules XML") +
        s.opens.entries
          .filter((e) => e.isExact)
          .map((e) => `${e.source.path}:${e.flagMask}`)
          .join("\n") + "\n",
    });
  }
  for (const dir of ["egress", "ingress"] as const) {
    const sec = s[dir];
    if (!sec || sec.exact.length === 0) continue;
    files.push({
      path: `wazuh/lists/sbob/${name}/${dir}_addrs`,
      content: CDB_HEADER(`${dir} CDB address list: key=ip/mask (canonicalized), value=identifier`) +
        sec.entries
          .flatMap((e) => e.addrEntries.map((a) => `${a}:${e.source.identifier ?? "unnamed"}`))
          .join("\n") + "\n",
    });
  }

  // --------------------------------------------------------------------------
  // 3. decoder chain
  // --------------------------------------------------------------------------
  {
    const decoders: Decoder[] = [
      {
        name: `sbob-${name}-audit-root`,
        prematch: "\\d:type=SYSCALL msg=audit(\\d+): arch=\\S+ syscall=\\S+ ",
        comment: `root decoder for sbob-scoped audit events (${auditKeys.join(", ")})`,
      },
      {
        name: `sbob-${name}-audit-key`,
        parent: `sbob-${name}-audit-root`,
        regex: 'key="(\\S+)"',
        order: "sbob.key",
      },
      {
        name: `sbob-${name}-audit-exe`,
        parent: `sbob-${name}-audit-key`,
        regex: 'exe="(\\S+)"',
        order: "sbob.exe",
      },
      {
        name: `sbob-${name}-audit-comm`,
        parent: `sbob-${name}-audit-key`,
        regex: 'comm="(\\S+)"',
        order: "sbob.comm",
      },
      {
        name: `sbob-${name}-audit-saddr`,
        parent: `sbob-${name}-audit-key`,
        regex: "saddr=(\\S+)",
        order: "sbob.saddr",
        comment: "raw sockaddr; hex AF_INET decode to sbob.dst_ip/sbob.dst_port is the saddr work item (TDS 7.3.1)",
      },
      {
        name: `sbob-${name}-path-root`,
        prematch: "\\d:type=PATH msg=audit(\\d+): item=\\d+ name=",
        comment: "PATH records (opens drift); workload scoping relies on Mode A exe-filtered audit rules",
      },
      {
        name: `sbob-${name}-path-name`,
        parent: `sbob-${name}-path-root`,
        regex: 'name="(\\S+)"',
        order: "sbob.path",
      },
    ];
    const xml = [
      xmlFileHeader(`sbob decoders for workload ${name} — routing on generated audit keys`, name, LAB_NOTE),
      "",
      ...decoders.map(renderDecoder).join("\n\n").split("\n"),
      "",
    ].join("\n");
    files.push({ path: `wazuh/decoders/sbob/${name}.xml`, content: xml });
  }

  // --------------------------------------------------------------------------
  // 4. rules XML
  // --------------------------------------------------------------------------
  {
    const rules: XmlRule[] = [];
    const groups = (extra: string[]) => ["sbob", name, ...extra];

    // execs -----------------------------------------------------------------
    if (s.execs !== undefined) {
      const base = alloc.linux("base", "base");
      const baseId = alloc.linux("execs", "base");
      const driftId = alloc.linux("execs", "drift");
      const escId = alloc.linux("execs", "escalation");
      rules.push({
        id: base,
        level: 0,
        ifGroup: "auditd",
        fields: [{ name: "sbob.key", regex: `^sbob-exec(?:-${name})?$` }],
        description: `SBoB base: exec event on sbob scope (${name})`,
        groups: [groups(["sbob-exec"])],
      });
      rules.push({
        id: baseId,
        level: 0,
        ifSid: base,
        description: `SBoB base: exec base for workload ${name}`,
        groups: [groups(["sbob-exec"])],
        comment: "level-0 base child that carries the section group; drift rules chain from here",
      });
      const drift: XmlRule = {
        id: driftId,
        level: 9,
        ifSid: baseId,
        fields: [],
        description: `SBoB drift: process $(sbob.exe) not declared in execs[] of ${name} SBoB v${ir.workload.sbobVersion} (image ${ir.workload.imageID})`,
        groups: [groups(["sbob-drift", "process-execution"])],
        mitre: ["T1059"],
        options: ["no_full_log"],
      };
      if (s.execs.exact.length > 0) {
        drift.list = { field: "sbob.exe", lookup: "not_match_key", src: `sbob/${name}/execs` };
      }
      const neg = negatedAlternation(s.execs.patterns);
      if (neg !== null) drift.fields!.push({ name: "sbob.exe", regex: neg });
      rules.push(drift);
      rules.push({
        id: escId,
        level: 12,
        ifSid: driftId,
        frequency: 8,
        timeframe: 120,
        description: `SBoB sustained drift: repeated undeclared process execution on ${name} (8 in 120s)`,
        groups: [groups(["sbob-drift", "process-execution", "sustained"])],
      });
    } else {
      rules.push(sectionAbsentRule(ir, alloc, "execs", "sbob-exec", "process-execution"));
    }

    // opens -------------------------------------------------------------------
    if (s.opens !== undefined) {
      const baseId = alloc.linux("opens", "base");
      const driftId = alloc.linux("opens", "drift");
      const escId = alloc.linux("opens", "escalation");
      rules.push({
        id: baseId,
        level: 0,
        ifGroup: "auditd",
        fields: [{ name: "sbob.path", regex: "^/.+$" }],
        description: `SBoB base: PATH record observed (opens scope ${name})`,
        groups: [groups(["sbob-open"])],
        comment: "matches type=PATH records; workload scoping via Mode A exe-filtered audit rules",
      });
      const drift: XmlRule = {
        id: driftId,
        level: 9,
        ifSid: baseId,
        fields: [],
        description: `SBoB drift: file open $(sbob.path) not declared in opens[] of ${name} SBoB v${ir.workload.sbobVersion}`,
        groups: [groups(["sbob-drift", "file-access"])],
        mitre: ["T1005"],
        options: ["no_full_log"],
        comment: "path-level drift; flag-level (O_*) child rules are deferred per TDS 6.4",
      };
      if (s.opens.exact.length > 0) {
        drift.list = { field: "sbob.path", lookup: "not_match_key", src: `sbob/${name}/opens` };
      }
      const neg = negatedAlternation(s.opens.patterns);
      if (neg !== null) drift.fields!.push({ name: "sbob.path", regex: neg });
      rules.push(drift);
      rules.push({
        id: escId,
        level: 12,
        ifSid: driftId,
        frequency: 8,
        timeframe: 120,
        description: `SBoB sustained drift: repeated undeclared file opens on ${name} (8 in 120s)`,
        groups: [groups(["sbob-drift", "file-access", "sustained"])],
      });
    } else {
      rules.push(sectionAbsentRule(ir, alloc, "opens", "sbob-open", "file-access"));
    }

    // egress -------------------------------------------------------------------
    if (s.egress !== undefined) {
      const baseId = alloc.linux("egress", "base");
      const driftId = alloc.linux("egress", "drift");
      const escId = alloc.linux("egress", "escalation");
      rules.push({
        id: baseId,
        level: 0,
        ifGroup: "auditd",
        fields: [{ name: "sbob.key", regex: `^sbob-connect(?:-${name})?$` }],
        description: `SBoB base: outbound connect observed (${name})`,
        groups: [groups(["sbob-connect"])],
      });
      const allAddrs = s.egress.entries.flatMap((e) => e.addrEntries);
      const anyIp = s.egress.entries.some((e) => e.anyIp);
      const hasDnsOnly = s.egress.entries.every((e) => e.addrEntries.length === 0 && !e.anyIp);
      const ports = s.egress.entries.flatMap((e) => e.ports);
      const portAlt = portAlternation(ports);
      const drift: XmlRule = {
        id: driftId,
        level: 9,
        ifSid: baseId,
        fields: [],
        description: `SBoB drift: connect to $(sbob.dst_ip):$(sbob.dst_port) not declared in egress[] of ${name} SBoB v${ir.workload.sbobVersion}`,
        groups: [groups(["sbob-drift", "egress-traffic"])],
        mitre: ["T1071"],
        options: ["no_full_log"],
        comment:
          "fires when the saddr decoder (TDS 7.3.1) emits sbob.dst_ip/sbob.dst_port; " +
          (hasDnsOnly ? "NOTE: DNS-only egress entries are not evaluable from auditd telemetry (TDS 8)" : "") +
          (anyIp ? "NOTE: '*' any-IP entry present: address condition omitted per TDS 6.4" : ""),
      };
      if (allAddrs.length > 0 && !anyIp) {
        drift.list = { field: "sbob.dst_ip", lookup: "not_address_match_key", src: `sbob/${name}/egress_addrs` };
      }
      if (portAlt !== null && !anyIp) {
        drift.fields!.push({ name: "sbob.dst_port", regex: `^(?!(?:${portAlt})$)` });
      }
      if ((allAddrs.length > 0 && !anyIp) || portAlt !== null) rules.push(drift);
      if (rules.some((r) => r.id === driftId)) {
        rules.push({
          id: escId,
          level: 12,
          ifSid: driftId,
          frequency: 8,
          timeframe: 120,
          description: `SBoB sustained drift: repeated undeclared egress on ${name} (8 in 120s)`,
          groups: [groups(["sbob-drift", "egress-traffic", "sustained"])],
        });
      }
      if (hasDnsOnly) {
        rules.push({
          id: alloc.linux("egress", "info"),
          level: 2,
          ifSid: baseId,
          description: `SBoB informational: egress[] of ${name} declares DNS-only peers; auditd cannot evaluate them (needs DNS capture, TDS 8)`,
          groups: [groups(["sbob-info", "egress-traffic"])],
        });
      }
    } else {
      rules.push(sectionAbsentRule(ir, alloc, "egress", "sbob-connect", "egress-traffic"));
    }

    // ingress (Linux accept-path is weak; emitted for completeness) ----------------
    if (s.ingress !== undefined) {
      const infoId = alloc.linux("ingress", "info");
      rules.push({
        id: infoId,
        level: 3,
        ifGroup: "auditd",
        fields: [{ name: "sbob.key", regex: `^sbob-accept(?:-${name})?$` }],
        description: `SBoB informational: ingress[] declared for ${name} but Linux accept() telemetry cannot attribute peers; host-firewall ingestion required (TDS 8)`,
        groups: [groups(["sbob-info", "ingress-traffic"])],
      });
    }

    const xml = [
      xmlFileHeader(`sbob drift rules for workload ${name} — Linux / k8s-node target`, name, LAB_NOTE),
      "",
      ...rules.map(renderRule).join("\n\n").split("\n"),
      "",
    ].join("\n");
    files.push({
      path: `wazuh/rules/sbob/${ID_BAND_BASE(alloc)}_${name}_linux.xml`,
      content: xml,
    });
  }

  // --------------------------------------------------------------------------
  // 5. bundle manifest (minimal; full coverage matrix lands with M4)
  // --------------------------------------------------------------------------
  files.push({
    path: `${name}.manifest.json`,
    content: JSON.stringify(
      {
        workload: ir.workload,
        target: "linux",
        files: files.map((f) => f.path),
        coverageNotes: ir.coverageNotes,
        labValidation: "pending",
      },
      null,
      2,
    ) + "\n",
  });

  return files;
}

function ID_BAND_BASE(alloc: IdAllocator): number {
  // stable file name from the lowest issued base id
  return 100000 + alloc.slot * 100;
}

function sectionAbsentRule(ir: IR, alloc: IdAllocator, section: string, key: string, group: string): XmlRule {
  const name = ir.workload.name;
  const infoId = alloc.linux(section as any, "info");
  return {
    id: infoId,
    level: 2,
    ifGroup: "auditd",
    fields: [{ name: "sbob.key", regex: `^${key}(?:-${name})?$` }],
    description: `SBoB informational: section ${section}[] is absent from the ${name} SBoB; any event of this class is under-specified (spec 5.4 absent != NONE)`,
    groups: [["sbob", name, "sbob-info", group]],
  };
}

function CDB_HEADER(note: string): string {
  return `# ${note}\n`;
}

export function cdbEscape(s: string): string {
  // CDB lists: keys must not contain ':' — paths and IPs never do
  return xmlEscape(s);
}

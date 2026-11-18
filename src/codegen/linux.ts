/**
 * Linux / k8s-node codegen (TDS sections 4.2, 6.2, 6.4, 7.2).
 *
 * Emits, per workload:
 *   - wazuh/audit/sbob/<name>.rules        auditctl fragment (Mode A preferred)
 *   - wazuh/decoders/<name>.xml            auditd-generic tail-join children
 *                                          (sbob.saddr / sbob.sbob.path payloads)
 *   - wazuh/lists/sbob/<name>/*            CDB allowlists (execs, opens, egress_addrs,
 *                                          ingress_addrs, sigexempts/<policy> for
 *                                          rulePolicies.processAllowed, M4)
 *   - wazuh/rules/<base>_<name>_linux.xml   drift rules + signature pack (rulePolicies,
 *                                          M4) + ops section (config-check, M5)
 *   - wazuh/agent-conf/sbob/<name>.xml     config-check command wodle (M5, TDS 10.1)
 *   - wazuh/agent-conf/sbob/<name>-audit-digest.sh   node-side digest script (M5)
 *   - <name>.manifest.json                 workload bundle manifest + coverage matrix (TDS 8)
 *
 * Wazuh 4.14.6 engine facts this codegen is written against (lab-validated,
 * see docs/lab-validation.yaml):
 *   - Root rules never fire for auditd-decoded events: the shipped level-0
 *     rule 80700 "Audit: Messages grouped" (0365-auditd_rules.xml) matches
 *     every auditd event and the main loop stops at the first matching
 *     level-0 rule. Every sbob auditd rule therefore anchors on
 *     <if_sid>80700</if_sid>.
 *   - The shipped auditd decoder family (0040-auditd_decoders.xml) already
 *     extracts audit.key / audit.command / audit.exe / audit.type on SYSCALL
 *     lines. Custom sbob payloads (SOCKADDR saddr=, PATH name=) ride a
 *     re-declared auditd-generic tail-join; the old custom decoder chain
 *     (sbob.key / sbob.exe) was preempted by the shipped root and is gone.
 *   - Egress is evaluated in the RAW saddr hex space (family+port+ip+padding,
 *     uppercase): /32 (ip,port) pairs as exact CDB keys on sbob.saddr, wider
 *     CIDRs as PCRE2 byte patterns (src/codegen/saddr.ts).
 *   - Sustained correlation: frequency/timeframe are RULE-ELEMENT ATTRIBUTES
 *     and the parent is referenced via <if_matched_sid>, not <if_sid>.
 *
 * The audit fragment, CDB lists, decoder file and section drift rules are
 * shared with the k8s-node target (TDS 6.3: k8s nodes run the Linux agent and
 * share the variant band) and are exported for src/codegen/k8s.ts to compose.
 */
import { negatedAlternation, xmlEscape } from "../regexp.ts";
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { Decoder, XmlRule } from "./xml.ts";
import { renderDecoder, renderRule, xmlFileHeader } from "./xml.ts";
import { saddrHex, saddrCidrPattern } from "./saddr.ts";
import { signatureAuditLines, signatureExemptListFiles, signatureRulesShared, signatureCoverageNotes } from "./signatures.ts";
import {
  auditKeySetDigest,
  configCheckDecoder,
  configCheckRule,
  configCheckWodleBlock,
  auditDigestScriptContent,
  bundleVersion,
} from "./opshealth.ts";
import { buildCoverageMatrix, assertCoverageComplete } from "../coverage.ts";

export interface BundleFile {
  path: string;
  content: string;
}

/**
 * The shipped auditd anchor rule (0365-auditd_rules.xml, level 0, decoded_as
 * auditd). Every sbob auditd-facing rule MUST be its descendant: analysisd
 * stops at the first matching level-0 rule and 80700 matches every auditd
 * event, so later root rules are never evaluated (lab finding).
 */
export const AUDITD_ANCHOR_RULE = 80700;

/** Deployed CDB list paths live under /var/ossec/etc/lists/ (TDS 6.4). */
export function listSrc(name: string, rest: string): string {
  return `etc/lists/sbob/${name}/${rest}`;
}

const LAB_NOTE_PENDING =
  "LAB VALIDATION PENDING (M1 exit criteria): run scripts/logtest-corpus.sh against a lab node with a live wazuh manager";

/**
 * Banner line for generated XML headers (M1 exit criteria): LAB VALIDATED with
 * the committed evidence (docs/lab-validation.yaml, stamped via the
 * --lab-validation transpile flag) or the pending instruction.
 */
export function labNote(alloc: IdAllocator): string {
  const lab = alloc.lab;
  return lab
    ? `LAB VALIDATED (${lab.date}, ${lab.manager}): evidence ${lab.evidence}`
    : LAB_NOTE_PENDING;
}

// ---------------------------------------------------------------------------
// Shared building blocks (also consumed by src/codegen/k8s.ts)
// ---------------------------------------------------------------------------

/** auditctl fragment lines for the workload (Mode A exe-scoped preferred; TDS 4.2). */
export function auditFragmentLines(ir: IR): { lines: string[]; auditKeys: string[]; modeA: boolean } {
  const name = ir.workload.name;
  const s = ir.sections;
  const modeA = s.execs !== undefined && s.execs.exact.length > 0;
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
  // signature-rule syscalls (rulePolicies, M4): node-scoped audit keys whose
  // fire-by-default rules live in signatures.ts (shared with k8s-node).
  lines.push(...signatureAuditLines(ir));
  const auditKeys: string[] = [];
  if (s.execs !== undefined) auditKeys.push(modeA ? `sbob-exec-${name}` : "sbob-exec");
  if (s.opens !== undefined) auditKeys.push(modeA ? `sbob-open-${name}` : "sbob-open");
  if (s.egress !== undefined) auditKeys.push(modeA ? `sbob-connect-${name}` : "sbob-connect");
  return { lines, auditKeys, modeA };
}

/**
 * Compiled egress allow-model: exact CDB hex keys (raw saddr space) plus PCRE2
 * patterns for the entries a CDB key cannot express (any-port /32s, wider
 * CIDRs). IPv6 entries cannot be keyed in the AF_INET hex model and are
 * reported back to the caller for a coverage note.
 */
export function egressAllowModel(ir: IR): {
  cdbKeys: Array<{ key: string; value: string }>;
  patterns: string[];
  skippedIpv6: string[];
} {
  const cdbKeys: Array<{ key: string; value: string }> = [];
  const patterns: string[] = [];
  const skippedIpv6: string[] = [];
  for (const e of ir.sections.egress?.entries ?? []) {
    if (e.anyIp) continue; // '*' entry: no address condition is emitted (TDS 6.4)
    const identifier = e.source.identifier ?? "unnamed";
    for (const addr of e.addrEntries) {
      const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d+)$/.exec(addr);
      if (m === null) {
        skippedIpv6.push(`${addr} (${identifier})`);
        continue;
      }
      const ip = m[1]!;
      const mask = Number(m[2]);
      if (mask === 32) {
        const ports = e.ports.filter((p): p is number => typeof p === "number");
        if (ports.length > 0) {
          for (const port of ports) cdbKeys.push({ key: saddrHex(ip, port), value: identifier });
        } else {
          // ANY port on a /32: not a single CDB key; byte pattern with a free port
          patterns.push(`0200[0-9A-F]{4}${saddrHex(ip, 0).slice(8, 16)}${"0".repeat(16)}`);
        }
      } else {
        for (const port of e.ports) {
          patterns.push(saddrCidrPattern(addr, port));
        }
      }
    }
  }
  return { cdbKeys, patterns, skippedIpv6 };
}

/** CDB allowlist files for the workload (TDS 6.4). */
export function cdbListFiles(ir: IR, name: string): BundleFile[] {
  const files: BundleFile[] = [];
  const s = ir.sections;
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
  if (s.egress !== undefined) {
    const model = egressAllowModel(ir);
    if (model.cdbKeys.length > 0 || model.patterns.length > 0) {
      const header = [
        "# sbob egress CDB address list: key = raw auditd saddr hex (AF_INET:",
        "#   family 0200 + port (4 hex BE) + ip (8 hex BE) + zero padding), UPPERCASE",
        "#   — matches the SOCKADDR record byte-for-byte; CDB is exact-match and",
        "#   case-sensitive (wazuh 4.14.6 lab model, TDS 7.3.1).",
        `# value = identifier. Workload: ${name}.`,
        ...model.patterns.map((p) => `# (not a CDB key; evaluated in-rule): ${p}`),
        ...model.skippedIpv6.map((a) => `# NOT EVALUABLE (IPv6 outside the AF_INET hex model): ${a}`),
        "",
      ].join("\n");
      files.push({
        path: `wazuh/lists/sbob/${name}/egress_addrs`,
        content:
          header +
          model.cdbKeys.map((k) => `${k.key}:${k.value}`).join("\n") +
          (model.cdbKeys.length > 0 ? "\n" : ""),
      });
    }
  }
  if (s.ingress !== undefined) {
    const model = ingressAllowModel(ir);
    if (model.cdbKeys.length > 0 || model.patterns.length > 0) {
      const header = [
        "# sbob ingress CDB address list: key = raw auditd saddr hex (AF_INET,",
        "#   UPPERCASE), value = identifier (documented partial on Linux: accept()-side",
        "#   peer attribution needs host-firewall ingestion, TDS 8).",
        `# Workload: ${name}.`,
        "",
      ].join("\n");
      files.push({
        path: `wazuh/lists/sbob/${name}/ingress_addrs`,
        content:
          header +
          model.cdbKeys.map((k) => `${k.key}:${k.value}`).join("\n") +
          (model.cdbKeys.length > 0 ? "\n" : ""),
      });
    }
  }
  // signature exemptions (rulePolicies.processAllowed, M4): CDB sigexempts
  for (const f of signatureExemptListFiles(ir, name)) files.push(f);
  return files;
}

/** Ingress allow-model: CDB hex keys only (informational rules consume it). */
function ingressAllowModel(ir: IR): { cdbKeys: Array<{ key: string; value: string }>; patterns: string[] } {
  const cdbKeys: Array<{ key: string; value: string }> = [];
  for (const e of ir.sections.ingress?.entries ?? []) {
    if (e.anyIp) continue;
    const identifier = e.source.identifier ?? "unnamed";
    for (const addr of e.addrEntries) {
      const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/32$/.exec(addr);
      if (m === null) continue;
      for (const port of e.ports) {
        if (typeof port === "number") cdbKeys.push({ key: saddrHex(m[1]!, port), value: identifier });
      }
    }
  }
  return { cdbKeys, patterns: [] };
}

/**
 * Decoder file content for the workload: re-declared shipped auditd-generic
 * plus the two sbob payload tail-join children.
 *
 * Lab finding (wazuh 4.14.6): a custom root decoder (prematch type=SYSCALL…)
 * is preempted by the shipped auditd root, and the shipped auditd-syscall
 * children already decode audit.key/audit.command/audit.exe on SYSCALL lines.
 * SOCKADDR and PATH records carry NO key, so their payloads (saddr=, name=)
 * are extracted by tail-joining the shipped auditd-generic chain instead:
 * re-declaring "auditd-generic" in this file attaches our children to the
 * shipped decoder without touching it.
 */
export function auditDecoders(name: string, auditKeys: string[]): Decoder[] {
  return [
    {
      name: "auditd-generic",
      comment:
        `re-declared (NOT modified) to attach the sbob payload children below; the shipped ` +
        `auditd-generic (0040-auditd_decoders.xml) already extracts audit.type/audit.key/` +
        `audit.command/audit.exe — the old custom sbob root/key/exe chain was preempted ` +
        `by the shipped auditd root and removed (wazuh 4.14.6 lab finding)`,
    },
    {
      name: `sbob-${name}-saddr`,
      parent: "auditd-generic",
      regex: "saddr=(\\S+)",
      order: "sbob.saddr",
      comment:
        "raw sockaddr hex of SOCKADDR records (AF_INET: family 0200 + port + ip + padding, UPPERCASE); " +
        "the egress CDB lists key on this byte string (TDS 7.3.1 raw-hex model)",
    },
    {
      name: `sbob-${name}-path`,
      parent: "auditd-generic",
      regex: 'name="([^"\\s]+)"',
      order: "sbob.path",
      comment:
        "PATH record name= payload (opens drift); PATH lines carry no audit key, so the " +
        "workload scope rides Mode A exe-filtered audit rules (TDS 4.2); paths with " +
        "embedded spaces are not captured (honest limitation of the tail-join regex)",
    },
  ];
}

/**
 * Section drift rules (base, drift, escalation, informational) for the Linux
 * variant band (TDS 6.1/6.2). Shared by the linux and k8s-node targets.
 * Every auditd-facing rule anchors on the shipped 80700 parent (lab finding:
 * root rules never fire for auditd-decoded events).
 */
export function linuxSectionRules(ir: IR, alloc: IdAllocator): XmlRule[] {
  const name = ir.workload.name;
  const s = ir.sections;
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
      ifSid: AUDITD_ANCHOR_RULE,
      fields: [{ name: "audit.key", regex: `^sbob-exec(?:-${name})?$` }],
      description: `SBoB base: exec event on sbob scope (${name})`,
      groups: [groups(["sbob-exec"])],
      comment: `anchored on the shipped auditd rule ${AUDITD_ANCHOR_RULE} (root rules never fire for auditd events, lab finding); SYSCALL lines carry key= via the shipped decoders`,
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
      description: `SBoB drift: process $(audit.exe) not declared in execs[] of ${name} SBoB v${ir.workload.sbobVersion} (image ${ir.workload.imageID})`,
      groups: [groups(["sbob-drift", "process-execution"])],
      mitre: ["T1059"],
      options: ["no_full_log"],
      comment: "audit.exe is decoded by the SHIPPED auditd-syscall chain (exe=\"…\" on SYSCALL lines)",
    };
    if (s.execs.exact.length > 0) {
      drift.list = { field: "audit.exe", lookup: "not_match_key", src: listSrc(name, "execs") };
    }
    const neg = negatedAlternation(s.execs.patterns);
    if (neg !== null) drift.fields!.push({ name: "audit.exe", regex: neg });
    rules.push(drift);
    rules.push({
      id: escId,
      level: 12,
      ifMatchedSid: driftId,
      frequency: 8,
      timeframe: 120,
      description: `SBoB sustained drift: repeated undeclared process execution on ${name} (8 in 120s)`,
      groups: [groups(["sbob-drift", "process-execution", "sustained"])],
      comment: "if_matched_sid correlation; frequency/timeframe are rule-element attributes (lab finding)",
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
      ifSid: AUDITD_ANCHOR_RULE,
      fields: [
        { name: "audit.type", regex: "^PATH$" },
        { name: "sbob.path", regex: "^/.+$" },
      ],
      description: `SBoB base: PATH record observed (opens scope ${name})`,
      groups: [groups(["sbob-open"])],
      comment: "PATH lines carry NO audit key; the name= payload is decoded by the sbob tail-join child of the shipped auditd-generic",
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
      drift.list = { field: "sbob.path", lookup: "not_match_key", src: listSrc(name, "opens") };
    }
    const neg = negatedAlternation(s.opens.patterns);
    if (neg !== null) drift.fields!.push({ name: "sbob.path", regex: neg });
    rules.push(drift);
    rules.push({
      id: escId,
      level: 12,
      ifMatchedSid: driftId,
      frequency: 8,
      timeframe: 120,
      description: `SBoB sustained drift: repeated undeclared file opens on ${name} (8 in 120s)`,
      groups: [groups(["sbob-drift", "file-access", "sustained"])],
      comment: "if_matched_sid correlation; frequency/timeframe are rule-element attributes (lab finding)",
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
      ifSid: AUDITD_ANCHOR_RULE,
      fields: [{ name: "audit.type", regex: "^SOCKADDR$" }],
      description: `SBoB base: outbound connect observed (${name})`,
      groups: [groups(["sbob-connect"])],
      comment: "SOCKADDR lines carry NO audit key; saddr= is decoded by the sbob tail-join child of the shipped auditd-generic",
    });
    const model = egressAllowModel(ir);
    const anyIp = s.egress.entries.some((e) => e.anyIp);
    const hasDnsOnly = s.egress.entries.every((e) => e.addrEntries.length === 0 && !e.anyIp);
    const drift: XmlRule = {
      id: driftId,
      level: 9,
      ifSid: baseId,
      fields: [],
      description: `SBoB drift: connect to raw saddr $(sbob.saddr) not declared in egress[] of ${name} SBoB v${ir.workload.sbobVersion}`,
      groups: [groups(["sbob-drift", "egress-traffic"])],
      mitre: ["T1071"],
      options: ["no_full_log"],
      comment:
        "raw-hex saddr model (TDS 7.3.1): /32 (ip,port) pairs are exact CDB keys on sbob.saddr; " +
        "wider CIDRs and any-port /32s evaluate as in-rule PCRE2 byte patterns. " +
        (hasDnsOnly ? "NOTE: DNS-only egress entries are not evaluable from auditd telemetry (TDS 8). " : "") +
        (anyIp ? "NOTE: '*' any-IP entry present: the address condition is omitted per TDS 6.4; port intent is not evaluable in the saddr model. " : "") +
        (model.skippedIpv6.length > 0 ? `NOTE: IPv6 entries are not evaluable in the AF_INET hex model: ${model.skippedIpv6.join(", ")}. ` : ""),
    };
    if (model.cdbKeys.length > 0) {
      drift.list = { field: "sbob.saddr", lookup: "not_match_key", src: listSrc(name, "egress_addrs") };
    }
    const neg = negatedAlternation(model.patterns);
    if (neg !== null) drift.fields!.push({ name: "sbob.saddr", regex: neg });
    if (model.cdbKeys.length > 0 || model.patterns.length > 0) {
      rules.push(drift);
      rules.push({
        id: escId,
        level: 12,
        ifMatchedSid: driftId,
        frequency: 8,
        timeframe: 120,
        description: `SBoB sustained drift: repeated undeclared egress on ${name} (8 in 120s)`,
        groups: [groups(["sbob-drift", "egress-traffic", "sustained"])],
        comment: "if_matched_sid correlation; frequency/timeframe are rule-element attributes (lab finding)",
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
      ifSid: AUDITD_ANCHOR_RULE,
      fields: [{ name: "audit.key", regex: `^sbob-accept(?:-${name})?$` }],
      description: `SBoB informational: ingress[] declared for ${name} but Linux accept() telemetry cannot attribute peers; host-firewall ingestion required (TDS 8)`,
      groups: [groups(["sbob-info", "ingress-traffic"])],
      comment: `anchored on the shipped auditd rule ${AUDITD_ANCHOR_RULE} (lab finding)`,
    });
  }

  return rules;
}

// ---------------------------------------------------------------------------
// Linux bundle assembly
// ---------------------------------------------------------------------------

/** `<group name="sbob,<name>,">` wrapper for a rules XML body (wazuh container element). */
export function groupWrapper(name: string, body: string): string {
  return [`<group name="sbob,${name},">`, ...body.split("\n").map((l) => (l === "" ? "" : l)), "</group>"].join("\n");
}

export function generateLinuxBundle(ir: IR, alloc: IdAllocator): BundleFile[] {
  const name = ir.workload.name;
  const files: BundleFile[] = [];

  // 1. auditctl fragment ------------------------------------------------------
  const { lines: auditLines, auditKeys } = auditFragmentLines(ir);
  // M5: config-check digest over the emitted sbob audit key set (TDS 10.1)
  const configDigest = auditKeySetDigest(auditLines);
  files.push({ path: `wazuh/audit/sbob/${name}.rules`, content: auditLines.join("\n") + "\n" });

  // 2. CDB allowlists -----------------------------------------------------------
  for (const f of cdbListFiles(ir, name)) files.push(f);

  // 3. decoder file (auditd-generic tail-join) -------------------------------
  {
    const decoders = [...auditDecoders(name, auditKeys), configCheckDecoder(name)];
    const xml = [
      xmlFileHeader(`sbob decoders for workload ${name} — auditd-generic tail-join payloads`, name, labNote(alloc)),
      "",
      ...decoders.map(renderDecoder).join("\n\n").split("\n"),
      "",
    ].join("\n");
    files.push({ path: `wazuh/decoders/${name}.xml`, content: xml });
  }

  // 4. rules XML: section drift rules + signature pack (rulePolicies, M4) ----
  {
    const base = linuxSectionRules(ir, alloc);
    const rules = [...base, ...signatureRulesShared(ir, alloc, base), configCheckRule(ir, alloc, configDigest)];
    const body = rules.map(renderRule).join("\n\n");
    const xml = [
      xmlFileHeader(`sbob drift + signature + ops rules for workload ${name} — Linux / k8s-node target`, name, labNote(alloc)),
      "",
      groupWrapper(name, body),
      "",
    ].join("\n");
    files.push({
      path: `wazuh/rules/${ID_BAND_BASE(alloc)}_${name}_linux.xml`,
      content: xml,
    });
  }

  // 4b. agent configuration fragment (M5, TDS 10.1) -------------------------
  {
    const xml = [
      xmlFileHeader(
        "sbobctl generated agent configuration fragment — merge into the workload group agent.conf",
        name,
        "config-check wodle: reports the node's installed sbob audit key set digest every 30m; the manager-side rule (8,3) alerts when the node needs an audit.rules rollout (TDS 10.1)",
      ),
      "",
      ...configCheckWodleBlock(name),
      "",
    ].join("\n");
    files.push({ path: `wazuh/agent-conf/sbob/${name}.xml`, content: xml });
    files.push({ path: `wazuh/agent-conf/sbob/${name}-audit-digest.sh`, content: auditDigestScriptContent() });
  }

  // 5. bundle manifest (machine-generated coverage matrix: TDS 8, M4) -------
  {
    const coverage = buildCoverageMatrix(ir);
    const problems = assertCoverageComplete(coverage);
    if (problems.length > 0) {
      throw new Error(`coverage gate failed for workload ${name}: ${problems.join("; ")}`);
    }
    const egressModel = egressAllowModel(ir);
    files.push({
      path: `${name}.manifest.json`,
      content:
        JSON.stringify(
          {
            workload: ir.workload,
            target: "linux",
            sbobVersion: ir.workload.sbobVersion,
            imageID: ir.workload.imageID,
            bundleVersion: bundleVersion(ir),
            files: files.map((f) => f.path),
            coverage,
            coverageNotes: [
              ...ir.coverageNotes,
              ...signatureCoverageNotes(ir),
              ...(egressModel.skippedIpv6.length > 0
                ? [`linux: IPv6 egress entries are not evaluable in the AF_INET raw-hex saddr model: ${egressModel.skippedIpv6.join(", ")}`]
                : []),
              "linux: wazuh 4.14.6 engine model — auditd rules anchor on shipped rule 80700; SOCKADDR/PATH payloads ride the auditd-generic tail-join; egress evaluates raw saddr hex (TDS 7.3.1)",
            ],
            labValidation: alloc.lab ? "validated" : "pending",
            ...(alloc.lab ? { labValidationEvidence: alloc.lab } : {}),
          },
          null,
          2,
        ) + "\n",
    });
  }

  return files;
}

// ---------------------------------------------------------------------------

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
    ifSid: AUDITD_ANCHOR_RULE,
    fields: [{ name: "audit.key", regex: `^${key}(?:-${name})?$` }],
    description: `SBoB informational: section ${section}[] is absent from the ${name} SBoB; any event of this class is under-specified (spec 5.4 absent != NONE)`,
    groups: [["sbob", name, "sbob-info", group]],
    comment: `anchored on the shipped auditd rule ${AUDITD_ANCHOR_RULE} (lab finding)`,
  };
}

function CDB_HEADER(note: string): string {
  return `# ${note}\n`;
}

export function cdbEscape(s: string): string {
  // CDB lists: keys must not contain ':' — paths and IPs never do
  return xmlEscape(s);
}

/**
 * Linux / k8s-node codegen (TDS sections 4.2, 6.2, 6.4, 7.2), reworked for
 * the SHIPPED Wazuh decoders (issue #42).
 *
 * Emits, per workload:
 *   - wazuh/audit/sbob/<name>.rules        auditctl fragment (Mode A preferred)
 *   - wazuh/decoders/sbob/<name>.xml       config-check decoder ONLY (the old
 *                                          custom auditd chain was dropped: a
 *                                          custom decoder loses root selection
 *                                          to the shipped auditd decoder chain,
 *                                          so its fields never landed — issue
 *                                          #42 defect 9, TDS 7.3 work item)
 *   - wazuh/lists/sbob/<name>/*            CDB allowlists (execs, opens, egress_addrs, ingress_addrs,
 *                                          sigexempts/<policy> for rulePolicies.processAllowed, M4)
 *   - wazuh/rules/sbob/<base>_<name>_linux.xml   drift rules + signature pack (rulePolicies, M4)
 *                                          + ops section (config-check, M5)
 *   - wazuh/agent-conf/sbob/<name>.xml     config-check command wodle (M5, TDS 10.1)
 *   - wazuh/agent-conf/sbob/<name>-audit-digest.sh   node-side digest script (M5)
 *   - <name>.manifest.json                 workload bundle manifest + coverage matrix (TDS 8)
 *
 * Decode model (issue #42): all sbob conditions ride fields of the SHIPPED
 * auditd decoders (0040-auditd_decoders.xml) plus the raw sockaddr hex it
 * surfaces; no custom audit decoders are emitted. On wazuh-manager 4.14.6 the
 * shipped decoder chain extracts:
 *   - SYSCALL records   -> audit.command / audit.exe / audit.key / audit.type
 *   - SOCKADDR records  -> srcip = raw saddr hex (via the generic unanchored
 *                          addr=(\S+) regex; FRAGILE — depends on shipped
 *                          decoder text, not a contract)
 *   - PATH records      -> audit.directory.name (the generic name=(\S+)
 *                          capture; keeps the literal quotes, no typed
 *                          PATH decoder exists)
 * Root-preemption constraint (verified live): every auditd-decoded event
 * matches the shipped root 80700 ("Audit: Messages grouped.") and Wazuh stops
 * evaluating further ROOT rules once an earlier root matched, so a user rule
 * that is a `decoded_as auditd` root NEVER fires. All sbob auditd-keyed rules
 * chain as <if_sid>80700</if_sid> children (AUDITD_ROOT_SID in xml.ts).
 * The audit fragment, CDB lists and section drift rules are shared with the
 * k8s-node target (TDS 6.3) and exported for src/codegen/k8s.ts to compose.
 */
import { allowAlternation, negatedAlternation, xmlEscape } from "../regexp.ts";
import { escapeRegExp } from "../wildcards.ts";
import { saddrEntryFragments } from "./sockaddr.ts";
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { Decoder, XmlRule } from "./xml.ts";
import { AUDITD_ROOT_SID, renderDecoder, renderRulesFile, xmlFileHeader } from "./xml.ts";
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

const LAB_NOTE_PENDING =
  "LAB VALIDATION PENDING (M1 exit criteria): run scripts/logtest-corpus.sh against a lab node with a live wazuh manager";

/** CDB <list> src paths are etc/lists-relative on the manager (issue #42 defect 6). */
export function listSrc(name: string, list: string): string {
  return `etc/lists/sbob/${name}/${list}`;
}

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

/** CDB allowlist files for the workload (TDS 6.4). */
export function cdbListFiles(ir: IR, name: string): BundleFile[] {
  const files: BundleFile[] = [];
  const s = ir.sections;
  if (s.execs && s.execs.exact.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/execs`,
      content:
        CDB_HEADER("execs allowlist (exact entries); exact-key CDB lookup on audit.exe; wildcard entries live in the rules XML — src is etc/lists-relative (issue #42 defect 6)") +
        s.execs.exact.map((e) => `${e}:1`).join("\n") + "\n",
    });
  }
  if (s.opens && s.opens.exact.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/opens`,
      content:
        CDB_HEADER("opens allowlist: declared-intent reference (key=path, value=flag bitmask, TDS 6.4); the drift rule evaluates opens via the rules XML full-log lookahead because the shipped decoder name= capture keeps literal quotes — CDB keys would never match (issue #42, TDS 7.3)") +
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
      content:
        CDB_HEADER(`${dir} CDB address list: declared-intent reference (key=ip/mask canonicalized, value=identifier); the drift rule evaluates egress via precomputed raw-sockaddr hex REM fragments in the rules XML because srcip is a STATIC Wazuh field and cannot carry <field>/pcre2 conditions (issue #42, TDS 7.3.1)`) +
        sec.entries
          .flatMap((e) => e.addrEntries.map((a) => `${a}:${e.source.identifier ?? "unnamed"}`))
          .join("\n") + "\n",
    });
  }
  // signature exemptions (rulePolicies.processAllowed, M4): CDB sigexempts
  for (const f of signatureExemptListFiles(ir, name)) files.push(f);
  return files;
}

/**
 * Section drift rules (base, drift, escalation, informational) for the Linux
 * variant band (TDS 6.1/6.2). Shared by the linux and k8s-node targets.
 *
 * All conditions ride fields of the SHIPPED auditd decoder (+ the raw
 * sockaddr hex it emits as srcip); no custom audit decoders are emitted, and
 * every rule chains under the shipped auditd root AUDITD_ROOT_SID (80700) —
 * root preemption, issue #42).
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
      ifSid: AUDITD_ROOT_SID,
      fields: [{ name: "audit.key", regex: `^sbob-exec(?:-${name})?$` }],
      description: `SBoB base: exec event on sbob scope (${name})`,
      groups: [groups(["sbob-exec"])],
      comment: "chains under the shipped auditd root 80700 (root preemption — issue #42); audit.key comes from the shipped auditd decoder",
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
    };
    if (s.execs.exact.length > 0) {
      drift.list = { field: "audit.exe", lookup: "not_match_key", src: listSrc(name, "execs") };
    }
    const neg = negatedAlternation(s.execs.patterns);
    if (neg !== null) {
      allowAlternation(s.execs.patterns); // enforce the TDS 7.1 regex budget
      drift.fields!.push({ name: "audit.exe", regex: neg });
    }
    rules.push(drift);
    rules.push({
      id: escId,
      level: 12,
      ifMatchedSid: driftId,
      frequency: 8,
      timeframe: 120,
      description: `SBoB sustained drift: repeated undeclared process execution on ${name} (8 in 120s)`,
      groups: [groups(["sbob-drift", "process-execution", "sustained"])],
      comment: "correlation rule: frequency/timeframe are rule attributes and the parent rides if_matched_sid (issue #42 defect 3)",
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
      ifSid: AUDITD_ROOT_SID,
      match: "^type=PATH msg=audit",
      description: `SBoB base: PATH record observed (opens scope ${name})`,
      groups: [groups(["sbob-open"])],
      comment:
        "full-log anchor: the shipped decoder chain has no typed PATH decoder (the generic name= capture keeps literal quotes and lands in audit.directory.name), so the chain keys on the raw record — workload scoping relies on Mode A exe-filtered audit rules (issue #42 defect 9)",
    });
    const drift: XmlRule = {
      id: driftId,
      level: 9,
      ifSid: baseId,
      match: `name=".*`,
      description: `SBoB drift: file open $(audit.directory.name) not declared in opens[] of ${name} SBoB v${ir.workload.sbobVersion}`,
      groups: [groups(["sbob-drift", "file-access"])],
      mitre: ["T1005"],
      options: ["no_full_log"],
      comment:
        "single full-log pcre2 negative lookahead on the quoted PATH name, covering exact and wildcard entries; decoded-field keying is unusable (PATH names carry literal quotes and audit.directory.name handling varies across shipped rulesets — issue #42)",
    };
    const openAlt = [
      ...s.opens.exact.map((p) => escapeRegExp(p)),
      ...s.opens.patterns,
    ].join("|");
    if (openAlt !== "") {
      allowAlternation([openAlt]); // enforce the TDS 7.1 regex budget
      drift.match = `name="(?!(?:${openAlt}))`;
    }
    rules.push(drift);
    rules.push({
      id: escId,
      level: 12,
      ifMatchedSid: driftId,
      frequency: 8,
      timeframe: 120,
      description: `SBoB sustained drift: repeated undeclared file opens on ${name} (8 in 120s)`,
      groups: [groups(["sbob-drift", "file-access", "sustained"])],
      comment: "correlation rule: frequency/timeframe are rule attributes and the parent rides if_matched_sid (issue #42 defect 3)",
    });
  } else {
    rules.push(sectionAbsentRule(ir, alloc, "opens", "sbob-open", "file-access"));
  }

  // egress -------------------------------------------------------------------
  if (s.egress !== undefined) {
    const baseId = alloc.linux("egress", "base");
    const driftId = alloc.linux("egress", "drift");
    const escId = alloc.linux("egress", "escalation");
    const anyIp = s.egress.entries.some((e) => e.anyIp);
    const hasDnsOnly = s.egress.entries.every((e) => e.addrEntries.length === 0 && !e.anyIp);
    rules.push({
      id: baseId,
      level: 0,
      ifSid: AUDITD_ROOT_SID,
      fields: [{ name: "audit.key", regex: `^sbob-connect(?:-${name})?$` }],
      description: `SBoB base: outbound connect observed (${name})`,
      groups: [groups(["sbob-connect"])],
      comment: "informational base on the SYSCALL record (shipped auditd decoder); the SOCKADDR half of the event carries srcip",
    });
    if (!anyIp && !hasDnsOnly) {
      // per-entry (ip, port) pairs precomputed into raw AF_INET sockaddrs
      const egressFrags = s.egress.entries
        .filter((e) => !e.anyIp && e.addrEntries.length > 0)
        .flatMap((e) => saddrEntryFragments(e));
      if (egressFrags.length > 0) {
        allowAlternation(egressFrags); // enforce the TDS 7.1 regex budget
        const drift: XmlRule = {
          id: driftId,
          level: 9,
          ifSid: AUDITD_ROOT_SID,
          match: `saddr=(?!(?:${egressFrags.join("|")}))0200`,
          description: `SBoB drift: connect to raw AF_INET sockaddr $(srcip) not declared in egress[] of ${name} SBoB v${ir.workload.sbobVersion}`,
          groups: [groups(["sbob-drift", "egress-traffic"])],
          mitre: ["T1071"],
          options: ["no_full_log"],
          comment:
            "standalone node-scoped SOCKADDR gate: srcip carries the raw sockaddr hex (family+port+addr+padding) via the shipped decoder's generic addr= regex, and srcip is a STATIC Wazuh field — <field>/pcre2 on it is rejected by the loader (\"Field 'srcip' is static\"), hence the full-log match with negative lookahead over the precomputed allowed (ip, port) hex forms. AF_UNIX/AF_NETLINK records (family != 0200) are excluded by the 0200 gate (issue #42, TDS 7.3.1)",
        };
        rules.push(drift);
        rules.push({
          id: escId,
          level: 12,
          ifMatchedSid: driftId,
          frequency: 8,
          timeframe: 120,
          description: `SBoB sustained drift: repeated undeclared egress on ${name} (8 in 120s)`,
          groups: [groups(["sbob-drift", "egress-traffic", "sustained"])],
          comment: "correlation rule: frequency/timeframe are rule attributes and the parent rides if_matched_sid (issue #42 defect 3)",
        });
      }
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
      ifSid: AUDITD_ROOT_SID,
      fields: [{ name: "audit.key", regex: `^sbob-accept(?:-${name})?$` }],
      description: `SBoB informational: ingress[] declared for ${name} but Linux accept() telemetry cannot attribute peers; host-firewall ingestion required (TDS 8)`,
      groups: [groups(["sbob-info", "ingress-traffic"])],
    });
  }

  return rules;
}

// ---------------------------------------------------------------------------
// Linux bundle assembly
// ---------------------------------------------------------------------------

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

  // 3. decoder file: config-check decoder ONLY (the custom audit chain was
  //    dropped — root-decoder selection preemption, issue #42 defect 9) ------
  {
    const decoder: Decoder = configCheckDecoder(name);
    const xml = [
      xmlFileHeader(
        `sbob decoders for workload ${name} — config-check digest routing only`,
        name,
        `${labNote(alloc)}; auditd events ride the SHIPPED decoder chain (0040-auditd_decoders.xml) — custom audit decoders lose root selection and are not emitted (issue #42 defect 9); audit keys for reference: ${auditKeys.join(", ")}`,
      ),
      "",
      ...renderDecoder(decoder).split("\n"),
      "",
    ].join("\n");
    files.push({ path: `wazuh/decoders/sbob/${name}.xml`, content: xml });
  }

  // 4. rules XML: section drift rules + signature pack (rulePolicies, M4) ----
  {
    const base = linuxSectionRules(ir, alloc);
    const rules = [...base, ...signatureRulesShared(ir, alloc, base), configCheckRule(ir, alloc, configDigest)];
    files.push({
      path: `wazuh/rules/sbob/${ID_BAND_BASE(alloc)}_${name}_linux.xml`,
      content: renderRulesFile(
        `sbob drift + signature + ops rules for workload ${name} — Linux / k8s-node target`,
        name,
        labNote(alloc),
        rules,
      ),
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
              "wazuh decode model: auditd events ride the SHIPPED decoder chain; all sbob auditd-keyed rules chain under <if_sid>80700</if_sid> (a decoded_as-auditd user root never fires after the shipped root matched — issue #42)",
              "srcip carries the raw AF_INET sockaddr hex via the shipped decoder's unanchored generic addr= regex (fragile, shipped-text dependent); it is a STATIC field and cannot carry <field>/pcre2 conditions — egress/sockaddr conditions use full-log pcre2 negative lookaheads (issue #42, TDS 7.3.1)",
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
    ifSid: AUDITD_ROOT_SID,
    fields: [{ name: "audit.key", regex: `^${key}(?:-${name})?$` }],
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

/**
 * Linux / k8s-node codegen (TDS sections 4.2, 6.2, 6.4, 7.2) — wazuh-manager
 * 4.14.6 native schema (issue #42 fix).
 *
 * Emits, per workload:
 *   - wazuh/audit/sbob/<name>.rules        auditctl fragment (Mode A preferred)
 *   - wazuh/decoders/sbob/<name>.xml       config-check decoder ONLY — the
 *                                          shipped auditd decoder family
 *                                          (0365-0380) preempts custom audit
 *                                          roots on 4.14.6, so audit lines are
 *                                          decoded by the SHIPPED family into
 *                                          audit.* fields and no custom audit
 *                                          decoders are emitted
 *   - wazuh/lists/sbob/<name>/*            CDB allowlists (execs,
 *                                          egress_saddrs saddr-hex keys,
 *                                          ingress_addrs informational,
 *                                          sigexempts/<policy> for
 *                                          rulePolicies.processAllowed, M4)
 *   - wazuh/rules/sbob/<base>_<name>_linux.xml   drift rules + signature pack
 *                                          + ops section, all inside one root
 *                                          <group name="sbob,<name>">
 *   - wazuh/agent-conf/sbob/<name>.xml     config-check command wodle (M5, TDS 10.1)
 *   - wazuh/agent-conf/sbob/<name>-audit-digest.sh   node-side digest script (M5)
 *   - <name>.manifest.json                 workload bundle manifest + coverage matrix (TDS 8)
 *
 * Manager-side 4.14.6 facts this codegen depends on (verified on the replica
 * manager, issue #42):
 *   - audit events decode through the SHIPPED auditd decoder family; rules
 *     scope on the shipped fields audit.key / audit.type / audit.exe /
 *     audit.command / audit.directory.name (PATH records), audit.id, and the
 *     static srcip (SOCKADDR saddr spelling). The shipped ruleset group is
 *     "audit" (never "auditd").
 *   - CDB list sources in <list> must be ossec.conf-relative paths
 *     ("etc/lists/sbob/…") and every list must be DECLARED with a <list>
 *     element in ossec.conf — an undeclared list warns and the rule is
 *     ignored ("List could not be loaded. Rule will be ignored").
 *     <list> conditions on the STATIC srcip field are allowed; PCRE2 conditions
 *     on srcip are not ("Field 'srcip' is static").
 *   - SOCKADDR records decode saddr= hex into the static srcip field, so the
 *     egress allowlist keys are the saddr hex spellings (padded 32-hex and
 *     truncated 16-hex forms) of each declared peer ip:port.
 *   - frequency correlation needs if_matched_sid + same_field; an empty
 *     <same_field/> never correlates.
 *
 * The audit fragment, CDB lists and section drift rules are shared with the
 * k8s-node target (TDS 6.3: k8s nodes run the Linux agent and share the
 * variant band) and are exported for src/codegen/k8s.ts to compose.
 */
import { SbobError } from "../errors.ts";
import { negatedAlternation, REGEX_BUDGET_BYTES } from "../regexp.ts";
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { XmlRule } from "./xml.ts";
import { renderDecoder, renderRuleFile, xmlFileHeader } from "./xml.ts";
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
// Shared building blocks (also consumed by src/codegen/k8s.ts, signatures.ts)
// ---------------------------------------------------------------------------

/**
 * Shipped auditd decoder field names on wazuh 4.14.6 — the rules ride these
 * fields (source: the shipped decoder family; group "audit" is declared by
 * the shipped ruleset, e.g. rule 80700).
 */
export const F = {
  key: "audit.key",                       // -k <key> (Mode A/B sbob keys)
  type: "audit.type",                     // SYSCALL / PATH / SOCKADDR record
  exe: "audit.exe",                       // exe="…"
  command: "audit.command",               // comm="…"
  path: "audit.directory.name",           // PATH records: name="…" (WITH quotes)
  id: "audit.id",                         // audit(…:<id>) event id
} as const;

const SHIPPED_AUDIT_GROUP = "audit";

/** ossec.conf-relative CDB list path (the only spelling <list> accepts). */
export function listSrc(rel: string): string {
  return `etc/lists/${rel}`;
}

/** Escape a literal for use inside a PCRE2 fragment (dots, etc.). */
export function dotSafe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const REGEX_BUDGET = REGEX_BUDGET_BYTES;

/**
 * Negated-allowlist regex over an opens path value. The shipped auditd decoder
 * decodes PATH name="…" fields WITH their surrounding quotes, so allowed
 * values must be quote-anchored: the returned regex full-matches `"…"`
 * strings that are NOT one of the allowed spellings. Path fragments are
 * transformed so a segment wildcard can never cross the closing quote
 * ([^/] -> [^/"]). Bold honest limitation: CDB keys are fragile in quoted
 * form, so opens allowlisting is pure PCRE2 on Linux (no CDB list).
 */
export function quotedNameNegation(exact: string[], patterns: string[]): string | null {
  const alts: string[] = [];
  for (const e of exact) alts.push(dotSafe(e));
  // segment classes inside compiled fragments must not cross the closing quote
  for (const p of patterns) alts.push(quoteSafeClassFragment(p));
  if (alts.length === 0) return null;
  const alt = alts.map((a) => `${a}"$`).join("|");
  if (alt.length > REGEX_BUDGET) {
    throw new SbobError(
      "ERR_REGEX_BUDGET",
      `compiled opens negation is ${alt.length} bytes, exceeding the ${REGEX_BUDGET}-byte cap; split the workload or reduce wildcarded entries`,
    );
  }
  return `^"(?!${alt})[^"]+"$`;
}

/** Transform (used by quotedNameNegation) — exported for tests. */
export function quoteSafeClassFragment(p: string): string {
  return p.replace(/\[\^\/\]/g, '[^/"]');
}

// ---------------------------------------------------------------------------
// egress saddr hex keys (SOCKADDR -> static srcip)
// ---------------------------------------------------------------------------

/**
 * The sockaddr_in saddr hex spellings wazuh 4.14.6 decodes into the STATIC
 * srcip field for ip:port — BOTH the padded 16-byte form (32 hex chars:
 * family 0200 + port(BE) + ip(BE) + 8 zero bytes) and the truncated 8-byte
 * form auditd emits on some kernels (16 hex chars, no zero padding).
 */
export function saddrHexKeys(ip: string, port: number): string[] {
  const octets = ip.split(".").map((o) => Number(o).toString(16).toUpperCase().padStart(2, "0"));
  const portHex = port.toString(16).toUpperCase().padStart(4, "0");
  const core = `0200${portHex}${octets.join("")}`;
  return [core + "0".repeat(16), core];
}

export interface EgressSaddrKeys {
  /** saddr hex keys (both spellings per peer ip:port). */
  keys: string[];
  /** true when at least one entry is not evaluable from saddr telemetry. */
  nonEvaluable: boolean;
  /** true when a '*' any-IP entry is present (no address condition at all). */
  anyIp: boolean;
  /** per-entry notes for the coverage manifest. */
  notes: string[];
}

/**
 * Compile the egress[] allowlist into saddr hex keys. Honest gaps (flagged
 * nonEvaluable, TDS 8): non-/32 CIDRs, port-less entries, IPv6 peers and
 * DNS-only entries cannot be keyed exactly into the saddr spelling.
 */
export function egressSaddrKeys(ir: IR): EgressSaddrKeys {
  const sec = ir.sections.egress;
  const keys = new Set<string>();
  const notes: string[] = [];
  let nonEvaluable = false;
  let anyIp = false;
  if (sec === undefined) return { keys: [], nonEvaluable, anyIp, notes };
  for (const e of sec.entries) {
    if (e.anyIp) {
      anyIp = true;
      notes.push(`egress: '*' any-IP entry present (${e.source.identifier ?? "unnamed"}) — the address condition is omitted per TDS 6.4`);
      continue;
    }
    const specificPorts = e.ports.filter((p): p is number => typeof p === "number");
    const ident = e.source.identifier ?? "unnamed";
    if (specificPorts.length === 0) {
      nonEvaluable = true;
      notes.push(`egress: entry ${ident} declares no specific port — saddr keys need an exact ip:port (not evaluable from auditd SOCKADDR, TDS 8)`);
    }
    for (const addr of e.addrEntries) {
      const [ip, mask] = addr.split("/");
      if (mask !== "32" || ip.includes(":")) {
        nonEvaluable = true;
        notes.push(
          `egress: entry ${ident} peer ${addr} is not an exact /32 IPv4 — CIDR/IPv6 ranges cannot be keyed into a single saddr spelling (auditd SOCKADDR sees one concrete peer; TDS 8)`,
        );
        continue;
      }
      for (const p of specificPorts) {
        for (const k of saddrHexKeys(ip, p)) keys.add(k);
      }
    }
    if (e.addrEntries.length === 0 && specificPorts.length > 0 && (e.dnsPatterns.length + e.dnsExact.length) > 0) {
      nonEvaluable = true;
      notes.push(`egress: entry ${ident} is DNS-only — dnsNames are not evaluable from node auditd SOCKADDR telemetry (Windows EID 22 covers them; TDS 8)`);
    }
  }
  return { keys: [...keys].sort(), nonEvaluable, anyIp, notes };
}

/**
 * Nibble-aligned PCRE2 matching the saddr-hex srcip spelling of any address
 * inside a CIDR. Exported for completeness: the production egress rule uses
 * the CDB saddr-key list instead (srcip is STATIC, so a PCRE2 field condition
 * on it is rejected by analysisd on 4.14 — but <list> lookups on static
 * fields ARE allowed). Kept for tooling/tests; not emitted today.
 */
export function srcipHexCidrPcre2(cidr: string): string {
  const [ip, maskStr] = cidr.split("/");
  const mask = Number(maskStr);
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !(mask >= 0 && mask <= 32)) {
    throw new SbobError("ERR_SCHEMA_INVALID", `srcipHexCidrPcre2: invalid IPv4 CIDR "${cidr}"`);
  }
  let value = 0;
  for (const o of ip.split(".").map(Number)) value = (value << 8) | (o & 0xff);
  const ipHex = (value >>> 0).toString(16).toUpperCase().padStart(8, "0");
  const fullNibbles = Math.floor(mask / 4);
  const rem = mask % 4;
  let pat = "";
  for (let i = 0; i < fullNibbles; i++) pat += ipHex[i];
  if (rem > 0) {
    const v = parseInt(ipHex[fullNibbles]!, 16);
    const block = 1 << (4 - rem);
    const lo = (v & ~(block - 1)) & 0xf;
    const hi = lo | (block - 1);
    pat += `[${lo.toString(16).toUpperCase()}-${hi.toString(16).toUpperCase()}]`;
  }
  const used = fullNibbles + (rem > 0 ? 1 : 0);
  const tail = used < 8 ? `[0-9A-F]{${8 - used}}` : "";
  return `^0200[0-9A-F]{4}${pat}${tail}(?:0{16})?$`;
}

// ---------------------------------------------------------------------------
// audit fragment (auditctl)
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

// ---------------------------------------------------------------------------
// CDB allowlists
// ---------------------------------------------------------------------------

/** CDB allowlist files for the workload (TDS 6.4, wazuh 4.14 list layout). */
export function cdbListFiles(ir: IR, name: string): BundleFile[] {
  const files: BundleFile[] = [];
  const s = ir.sections;
  if (s.execs && s.execs.exact.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/execs`,
      content: CDB_HEADER("execs allowlist (exact entries); wildcard entries live in the rules XML — key=exe path, value=1") +
        s.execs.exact.map((e) => `${e}:1`).join("\n") + "\n",
    });
  }
  // NOTE: no opens list on Linux — PATH values decode WITH surrounding quotes
  // (audit.directory.name carries `"/path"`), which makes CDB keys fragile;
  // the opens drift rule uses a quote-anchored PCRE2 negation instead.
  const egressKeys = egressSaddrKeys(ir);
  if (s.egress && egressKeys.keys.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/egress_saddrs`,
      content: CDB_HEADER(
        "egress saddr allowlist — key=sockaddr hex spelling (padded 32-hex AND truncated 16-hex forms per peer ip:port; " +
          "wazuh 4.14 decodes SOCKADDR saddr= into the STATIC srcip field), value=identifier",
      ) + egressKeys.keys.map((k) => `${k}:egress-peer`).join("\n") + "\n",
    });
  }
  if (s.ingress && s.ingress.exact.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/ingress_addrs`,
      content: CDB_HEADER("ingress CDB address list (INFORMATIONAL — Linux accept() telemetry cannot attribute peers, TDS 8): key=ip/mask, value=identifier") +
        s.ingress.entries
          .flatMap((e) => e.addrEntries.map((a) => `${a}:${e.source.identifier ?? "unnamed"}`))
          .join("\n") + "\n",
    });
  }
  // signature exemptions (rulePolicies.processAllowed, M4): CDB sigexempts
  for (const f of signatureExemptListFiles(ir, name)) files.push(f);
  return files;
}

// ---------------------------------------------------------------------------
// section drift rules (LINUX variant band; shared with k8s-node)
// ---------------------------------------------------------------------------

/** Sustained (frequency) child of a drift rule — ids passed in, never re-allocated. */
function sustainedRule(
  id: number,
  driftId: number,
  sameField: XmlRule["sameField"],
  description: string,
  groups: string[][],
): XmlRule {
  // level 13 so the sustained alert outranks the level-12 signature overlays
  // in logtest/one-alert-per-event display (highest level wins).
  return {
    id,
    level: 13,
    ifMatchedSid: driftId,
    sameField,
    frequency: 8,
    timeframe: 120,
    description,
    groups,
    comment:
      "if_matched_sid + same_field correlation (an empty same_field never correlates on wazuh 4.14). " +
      "Note: the correlation context only accumulates while this rule's PARENT wins the matched-rule " +
      "selection — when a higher-level signature overlay (e.g. (0,1) sensitive-file, level 12) wins the " +
      "event, repetition is escalated by the (0,9) sustained-signature child instead (issue #42)",
  };
}

/**
 * Section drift rules (base, drift, escalation) for the Linux variant band
 * (TDS 6.1/6.2). Shared by the linux and k8s-node targets. All rules ride the
 * SHIPPED auditd decoder fields (audit.*) under the shipped "audit" group —
 * replica-verified on wazuh-manager 4.14.6.
 */
export function linuxSectionRules(ir: IR, alloc: IdAllocator): XmlRule[] {
  const name = ir.workload.name;
  const ver = ir.workload.sbobVersion;
  const s = ir.sections;
  const rules: XmlRule[] = [];
  const groups = (extra: string[]) => [["sbob", name, ...extra]];

  // execs -----------------------------------------------------------------
  if (s.execs !== undefined) {
    const baseId = alloc.linux("base", "base"); // (0,0)
    const driftId = alloc.linux("execs", "drift"); // (1,1)
    const sustainedId = alloc.linux("execs", "escalation"); // (1,2)
    rules.push({
      id: baseId,
      level: 0,
      ifGroup: SHIPPED_AUDIT_GROUP,
      fields: [{ name: F.key, regex: `^sbob-exec(?:-${dotSafe(name)})?$` }],
      description: `SBoB base: exec event on sbob scope (${name})`,
      groups: groups(["sbob-exec"]),
      comment: "shipped auditd decoder family + group 'audit' (0365 et al); Mode A keys carry the workload identity",
    });
    const drift: XmlRule = {
      id: driftId,
      level: 9,
      ifSid: baseId,
      fields: [],
      description: `SBoB drift: process $(audit.exe) not declared in execs[] of ${name} SBoB v${ver} (image ${ir.workload.imageID})`,
      groups: groups(["sbob-drift", "process-execution"]),
      mitre: ["T1059"],
      options: ["no_full_log"],
      comment: "CDB exact keys + PCRE2 negation for wildcard entries, both on the shipped audit.exe field",
    };
    if (s.execs.exact.length > 0) {
      drift.list = { field: F.exe, lookup: "not_match_key", src: listSrc(`sbob/${name}/execs`) };
    }
    const neg = negatedAlternation(s.execs.patterns);
    if (neg !== null) drift.fields!.push({ name: F.exe, regex: neg });
    rules.push(drift);
    rules.push(
      sustainedRule(
        sustainedId,
        driftId,
        { name: F.exe },
        `SBoB sustained drift: repeated undeclared process execution on ${name} (8 in 120s)`,
        groups(["sbob-drift", "process-execution", "sustained"]),
      ),
    );
  } else {
    rules.push(sectionAbsentRule(ir, alloc, "execs", "sbob-exec", "process-execution"));
  }

  // opens -------------------------------------------------------------------
  if (s.opens !== undefined) {
    const baseId = alloc.linux("opens", "base"); // (2,0)
    const driftId = alloc.linux("opens", "drift"); // (2,1)
    const sustainedId = alloc.linux("opens", "escalation"); // (2,2)
    rules.push({
      id: baseId,
      level: 0,
      ifGroup: SHIPPED_AUDIT_GROUP,
      fields: [
        { name: F.type, regex: "^PATH$" },
        { name: F.path, regex: '^"[^"]+"$' },
      ],
      description: `SBoB base: PATH record observed (opens scope ${name})`,
      groups: groups(["sbob-open"]),
      comment:
        "modes base on the ROUTE (record type + a quoted name), not the audit key: auditd interleaves the key only on the SYSCALL line; " +
        "workload scoping via Mode A exe-filtered audit rules",
    });
    const neg = quotedNameNegation(s.opens.exact, s.opens.patterns);
    if (neg !== null) {
      rules.push({
        id: driftId,
        level: 9,
        ifSid: baseId,
        fields: [{ name: F.path, regex: neg }],
        description: `SBoB drift: file open $(audit.directory.name) not declared in opens[] of ${name} SBoB v${ver}`,
        groups: groups(["sbob-drift", "file-access"]),
        mitre: ["T1005"],
        options: ["no_full_log"],
        comment: "quote-anchored negation — audit.directory.name decodes WITH its quotes; no CDB list (quoted keys are fragile)",
      });
      rules.push(
        sustainedRule(
          sustainedId,
          driftId,
          { name: F.path },
          `SBoB sustained drift: repeated undeclared file opens on ${name} (8 in 120s)`,
          groups(["sbob-drift", "file-access", "sustained"]),
        ),
      );
    }
  } else {
    rules.push(sectionAbsentRule(ir, alloc, "opens", "sbob-open", "file-access"));
  }

  // egress -------------------------------------------------------------------
  if (s.egress !== undefined) {
    const baseId = alloc.linux("egress", "base"); // (3,0)
    const driftId = alloc.linux("egress", "drift"); // (3,1)
    const sustainedId = alloc.linux("egress", "escalation"); // (3,2)
    const keys = egressSaddrKeys(ir);
    rules.push({
      id: baseId,
      level: 0,
      ifGroup: SHIPPED_AUDIT_GROUP,
      fields: [{ name: F.type, regex: "^SOCKADDR$" }],
      description: `SBoB base: outbound SOCKADDR observed (${name})`,
      groups: groups(["sbob-connect"]),
      comment: "SOCKADDR records decode saddr= hex into the STATIC srcip field (shipped auditd family)",
    });
    const hasDnsOnly = s.egress.entries.every((e) => e.addrEntries.length === 0 && !e.anyIp);
    if (keys.keys.length > 0 && !keys.anyIp) {
      rules.push({
        id: driftId,
        level: 9,
        ifSid: baseId,
        list: { field: "srcip", lookup: "not_match_key", src: listSrc(`sbob/${name}/egress_saddrs`) },
        fields: [],
        description: `SBoB drift: connect to $(srcip) not declared in egress[] of ${name} SBoB v${ver}`,
        groups: groups(["sbob-drift", "egress-traffic"]),
        mitre: ["T1071"],
        options: ["no_full_log"],
        comment:
          "CDB on the STATIC srcip field (PCRE2 conditions on static fields are rejected by analysisd; list lookups on static fields ARE allowed). " +
          "The list keys are the saddr hex spellings (both padded + truncated) of the declared ip:port peers. " +
          (keys.nonEvaluable
            ? "NOTE: at least one egress[] entry is not saddr-evaluable (non-/32, port-less, IPv6 or DNS-only) — honest gap, TDS 8"
            : ""),
      });
      rules.push(
        sustainedRule(
          sustainedId,
          driftId,
          { staticSrcip: true },
          `SBoB sustained drift: repeated undeclared egress on ${name} (8 in 120s)`,
          groups(["sbob-drift", "egress-traffic", "sustained"]),
        ),
      );
    }
    if (hasDnsOnly || (keys.nonEvaluable && keys.keys.length === 0)) {
      rules.push({
        id: alloc.linux("egress", "info"), // (3,3)
        level: 2,
        ifSid: baseId,
        description: `SBoB informational: egress[] of ${name} declares peers auditd SOCKADDR telemetry cannot evaluate (DNS-only / non-/32 / port-less; needs DNS capture or Windows EID 22, TDS 8)`,
        groups: groups(["sbob-info", "egress-traffic"]),
      });
    }
  } else {
    rules.push(sectionAbsentRule(ir, alloc, "egress", "sbob-connect", "egress-traffic"));
  }

  // ingress (Linux accept-path is weak; informational) --------------------------
  if (s.ingress !== undefined) {
    const infoId = alloc.linux("ingress", "info"); // (4,3)
    rules.push({
      id: infoId,
      level: 3,
      ifGroup: SHIPPED_AUDIT_GROUP,
      fields: [{ name: F.key, regex: `^sbob-accept(?:-${dotSafe(name)})?$` }],
      description: `SBoB informational: ingress[] declared for ${name} but Linux accept() telemetry cannot attribute peers; host-firewall ingestion required (TDS 8)`,
      groups: groups(["sbob-info", "ingress-traffic"]),
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
  const { lines: auditLines } = auditFragmentLines(ir);
  // M5: config-check digest over the emitted sbob audit key set (TDS 10.1)
  const configDigest = auditKeySetDigest(auditLines);
  files.push({ path: `wazuh/audit/sbob/${name}.rules`, content: auditLines.join("\n") + "\n" });

  // 2. CDB allowlists -----------------------------------------------------------
  for (const f of cdbListFiles(ir, name)) files.push(f);

  // 3. decoder file: the config-check decoder ONLY. The shipped auditd decoder
  //    family (0365-0380) preempts custom audit ROOT decoders on wazuh
  //    4.14.6 — audit lines decode through the shipped family into audit.*
  //    fields, and a custom audit root would never run (M7.3 work item
  //    RESOLVED this way; see docs and issue #42).
  {
    const decoders = [configCheckDecoder(name)];
    const xml = [
      xmlFileHeader(
        `sbob decoders for workload ${name} — config-check digest only (audit lines ride the SHIPPED auditd decoder family)`,
        name,
        labNote(alloc),
      ),
      "",
      ...decoders.map(renderDecoder).join("\n\n").split("\n"),
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
      content: renderRuleFile(
        xmlFileHeader(`sbob drift + signature + ops rules for workload ${name} — Linux / k8s-node target (wazuh 4.14 schema, issue #42)`, name, labNote(alloc)),
        ["sbob", name],
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
    const egressKeys = egressSaddrKeys(ir);
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
              "wazuh-4.14: rules ride the SHIPPED auditd decoder fields (audit.*) under the shipped 'audit' group; no custom audit decoders are emitted (the shipped family preempts custom audit roots)",
              "wazuh-4.14: frequency/timeframe are rule attributes; sustained children correlate via if_matched_sid + same_field (srcip correlation uses same_srcip)",
              "wazuh-4.14: correlation context accumulates only while the parent rule WINS the matched-rule selection — when a level-12 signature overlay wins the event (e.g. sensitive-file), the drift-parent sustained rule cannot fire; overlay repetition is escalated by the (0,9) sustained-signature child (issue #42)",
              "wazuh-4.14: CDB lists must be declared with <list> elements in the manager's ossec.conf (ossec.conf-relative 'etc/lists/…' spelling); an undeclared list is a loader warning and the rule is ignored",
              "wazuh-4.14: opens values decode WITH surrounding quotes (audit.directory.name) — the opens allowlist is a quote-anchored PCRE2 negation, not a CDB list",
              ...(egressKeys.keys.length > 0
                ? ["wazuh-4.14: egress allowlist keys are saddr hex spellings (padded 32-hex + truncated 16-hex) matched on the STATIC srcip field via a CDB list (PCRE2 on static fields is rejected; list lookups are allowed)"]
                : []),
              ...egressKeys.notes,
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
  // stable file name from the workload slot band base
  return 100000 + alloc.slot * 100;
}

function sectionAbsentRule(ir: IR, alloc: IdAllocator, section: string, key: string, group: string): XmlRule {
  const name = ir.workload.name;
  const infoId = alloc.linux(section as keyof typeof SECTION_KINDS, "info");
  return {
    id: infoId,
    level: 2,
    ifGroup: SHIPPED_AUDIT_GROUP,
    fields: [{ name: F.key, regex: `^${key}(?:-${dotSafe(name)})?$` }],
    description: `SBoB informational: section ${section}[] is absent from the ${name} SBoB; any event of this class is under-specified (spec 5.4 absent != NONE)`,
    groups: [["sbob", name, "sbob-info", group]],
  };
}

const SECTION_KINDS = { execs: 1, opens: 2, egress: 3, ingress: 4 } as const;

function CDB_HEADER(note: string): string {
  return `# ${note}\n`;
}

export function cdbEscape(s: string): string {
  // CDB lists: keys must not contain ':' — paths and IPs never do
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * rulePolicies signature rules (TDS 7.4, M4 / issue #5) — wazuh 4.14 schema
 * (issue #42 fix).
 *
 * Signature rules invert the drift model: instead of allowlist drift, they
 * fire BY DEFAULT on security-relevant primitives (module load, namespace
 * change, ptrace, memfd execution, sensitive-file watchlist, SA token reads,
 * k8s API access) and are silenced per-policy by exemptions declared in the
 * SBoB `rulePolicies` section (spec 4.8):
 *
 *   - processAllowed: comm list -> CDB sigexempts list consulted with
 *     <list field="audit.command" lookup="not_match_key"> directly on the rule
 *     (deviation from the TDS 6.2 sketch, documented there).
 *   - containerAllowed: true -> the rule (and its audit line) is not
 *     emitted at all for this workload (spec 4.8: not a deny).
 *
 * Wazuh 4.14.6 engine facts (replica-verified, issue #42): the audit-keyed
 * policies ride the SHIPPED auditd decoder family — fields audit.key /
 * audit.command / audit.exe under the shipped "audit" group. Descriptions use
 * $(audit.command)/$(audit.exe) substitution, which the manager renders at
 * alert time.
 *
 * Indirect egress (K8S_SERVICE_CIDR overlay): DELETED on 4.14. analysisd
 * rejects PCRE2 conditions on the STATIC srcip field ("Field 'srcip' is
 * static") while <list> lookups on static fields ARE allowed (that is how
 * the egress drift rule works). The manager-side k8s audit-log JSON rule
 * (6,4) carries the kubernetes-api-access policy instead
 * (signatureCoverageNotes documents the constraint).
 *
 * ID layout (TDS 6.1 M4 amendment): audit-keyed policies occupy the
 * rulePolicies section (code 6) variants 0-3 in the Linux/k8s band; overlays
 * and correlates reuse free base-section (code 0) variants:
 *   (6,0) module-load            sbob-module-load          level 12  T1547.006
 *   (6,1) namespace-change       sbob-namespace-change     level 10  T1611
 *   (6,2) process-tracing        sbob-process-tracing      level 10  T1055.008
 *   (6,3) execution-from-memory  sbob-memfd                level 10  T1620
 *   (6,4) kubernetes-api-access  manager-side JSON rule    level 12  T1552.001
 *   (0,1) sensitive-file-access       opens-drift overlay  level 12  T1552.001
 *   (0,2) service-account-token-access opens-drift overlay  level 12  T1552.001
 *   (0,4) binary-not-in-container-image lifecycle correlate level  3  (triage)
 *
 * Overlays are only emitted when their parent drift rule exists (drift rules
 * are conditional on SBoB content); parents are detected by raw-id formula,
 * never by re-allocating (the allocator throws ERR_ID_COLLISION on double
 * allocation).
 */
import type { IdAllocator } from "../ruleids.ts";
import { SECTION_CODES } from "../ruleids.ts";
import type { IR, RulePolicy } from "../types.ts";
import type { XmlRule } from "./xml.ts";
import type { BundleFile } from "./linux.ts";

// ---------------------------------------------------------------------------
// shipped-decoder field spellings (mirror src/codegen/linux.ts `F`; kept
// literal here to avoid a linux <-> signatures import cycle)
// ---------------------------------------------------------------------------

const AUDIT_KEY = "audit.key";
const AUDIT_EXE = "audit.exe";
const AUDIT_COMMAND = "audit.command";
const AUDIT_PATH = "audit.directory.name";
const SHIPPED_AUDIT_GROUP = "audit";

/** ossec.conf-relative prefix for <list> sources (wazuh 4.14 schema). */
const LIST_PREFIX = "etc/lists/";

// ---------------------------------------------------------------------------
// policy definitions
// ---------------------------------------------------------------------------

export interface SigPolicyDef {
  /** kebab-case generalized rule name (spec §4.8 / TDS 7.4). */
  name: string;
  /** node-scoped audit key (Mode B). */
  auditKey: string;
  /** auditctl -S syscall list (b64 spelling; b32 mirrors). */
  syscalls: string[];
  level: number;
  mitre: string;
  groupTag: string;
  description: (name: string) => string;
}

/** The four audit-keyed signature policies (emitted in the rulePolicies section). */
export const AUDIT_KEYED_POLICIES: SigPolicyDef[] = [
  {
    name: "module-load",
    auditKey: "sbob-module-load",
    syscalls: ["init_module", "finit_module"],
    level: 12,
    mitre: "T1547.006",
    groupTag: "sbob-sig-module-load",
    description: (name) =>
      `SBoB signature: kernel module load on ${name} scope (module-load policy, TDS 7.4) — comm $(audit.command), exe $(audit.exe)`,
  },
  {
    name: "namespace-change",
    auditKey: "sbob-namespace-change",
    syscalls: ["unshare", "setns"],
    level: 10,
    mitre: "T1611",
    groupTag: "sbob-sig-namespace-change",
    description: (name) =>
      `SBoB signature: namespace change (unshare/setns) on ${name} scope (namespace-change policy, TDS 7.4) — comm $(audit.command), exe $(audit.exe)`,
  },
  {
    name: "process-tracing",
    auditKey: "sbob-process-tracing",
    syscalls: ["ptrace"],
    level: 10,
    mitre: "T1055.008",
    groupTag: "sbob-sig-process-tracing",
    description: (name) =>
      `SBoB signature: ptrace on ${name} scope (process-tracing policy, TDS 7.4) — comm $(audit.command), exe $(audit.exe)`,
  },
  {
    name: "execution-from-memory",
    auditKey: "sbob-memfd",
    syscalls: ["memfd_create"],
    level: 10,
    mitre: "T1620",
    groupTag: "sbob-sig-execution-from-memory",
    description: (name) =>
      `SBoB signature: memfd_create (fileless execution) on ${name} scope (execution-from-memory policy, TDS 7.4) — comm $(audit.command), exe $(audit.exe)`,
  },
];

/**
 * Sensitive-path watchlist for the sensitive-file-access overlay (TDS 7.4),
 * QUOTE-ANCHORED on the shipped audit.directory.name field: PATH records
 * decode name="…" WITH the surrounding quotes on wazuh 4.14.
 */
export const SENSITIVE_PATH_REGEX =
  '^"(?:/etc/(?:shadow|gshadow|sudoers)(?:\\.d/[^"]+)?|/root/\\.ssh/[^"]+|/home/[^/]+/\\.ssh/[^"]+|/etc/ssh/[^"]*_key[^"]*|[^"]*/id_(?:rsa|ed25519|ecdsa)(?:\\.pub)?)"$';

/** k8s service-account token mount (projected volume path, TDS 7.4), quoted form. */
export const SA_TOKEN_PATH_REGEX =
  '^"/var/run/secrets/kubernetes\\.io/serviceaccount/(?:token|ca\\.crt|namespace)"$';

// ---------------------------------------------------------------------------
// rulePolicies helpers
// ---------------------------------------------------------------------------

export function policyFor(ir: IR, policy: string): RulePolicy | undefined {
  return ir.rulePolicies?.[policy];
}

/** containerAllowed=true suppresses emission entirely (spec §4.8, TDS 6.2). */
export function policySuppressed(ir: IR, policy: string): boolean {
  return policyFor(ir, policy)?.containerAllowed === true;
}

/** processAllowed exemption list entries for a policy (comms); empty = none. */
export function exemptComms(ir: IR, policy: string): string[] {
  return policyFor(ir, policy)?.processAllowed ?? [];
}

export function exemptListPath(name: string, policy: string): string {
  return `${LIST_PREFIX}sbob/${name}/sigexempts/${policy}`;
}

// ---------------------------------------------------------------------------
// audit fragment lines (node-scoped keys; shared linux + k8s-node)
// ---------------------------------------------------------------------------

export function signatureAuditLines(ir: IR): string[] {
  const lines: string[] = [
    "",
    "# signature-rule syscalls (rulePolicies, TDS 7.4) — node-scoped keys (Mode B):",
    "# every process on the host trips these; exempt legitimate actors via",
    "# rulePolicies.processAllowed (comm list) in the workload SBoBs.",
  ];
  for (const p of AUDIT_KEYED_POLICIES) {
    if (policySuppressed(ir, p.name)) {
      lines.push(`# ${p.name}: audit line omitted — containerAllowed=true suppresses this policy (spec 4.8)`);
      continue;
    }
    lines.push(`# ${p.name} (${p.syscalls.join(",")})`);
    lines.push(`-a always,exit -F arch=b64 -S ${p.syscalls.join(",")} -k ${p.auditKey}`);
    lines.push(`-a always,exit -F arch=b32 -S ${p.syscalls.join(",")} -k ${p.auditKey}`);
  }
  return lines;
}

// ---------------------------------------------------------------------------
// CDB exemption lists (per policy with processAllowed entries)
// ---------------------------------------------------------------------------

export function signatureExemptListFiles(ir: IR, name: string): BundleFile[] {
  const files: BundleFile[] = [];
  const policies = [
    ...AUDIT_KEYED_POLICIES.map((p) => p.name),
    "sensitive-file-access",
    "service-account-token-access",
  ];
  for (const policy of policies) {
    if (policySuppressed(ir, policy)) continue;
    const comms = exemptComms(ir, policy);
    if (comms.length === 0) continue;
    files.push({
      path: `wazuh/lists/sbob/${name}/sigexempts/${policy}`,
      content: [
        `# sbob signature exemption list — policy: ${policy} (rulePolicies.processAllowed)`,
        `# key = comm (evaluated on the shipped audit.command field), exact CDB match; workload: ${name}`,
        "",
        ...comms.map((c) => `${c}:1`),
        "",
      ].join("\n"),
    });
  }
  return files;
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

/** Raw id computation for already-issued ids (no allocator re-registration). */
function rawId(alloc: IdAllocator, section: number, variant: number): number {
  return 100000 + alloc.slot * 100 + section * 10 + variant;
}

/**
 * Shared signature rules for the linux and k8s-node targets: the four
 * audit-keyed policies in section 6 plus the opens overlays in the base
 * section (wazuh 4.14 schema: shipped audit fields, CDB-on-audit.command
 * exemptions, quote-anchored path overlays). `emitted` is the rule set
 * assembled so far — overlay parents must exist (section drift rules are
 * conditional on SBoB content).
 */
export function signatureRulesShared(ir: IR, alloc: IdAllocator, emitted: XmlRule[]): XmlRule[] {
  const name = ir.workload.name;
  const rules: XmlRule[] = [];
  const has = (id: number) => emitted.some((r) => r.id === id);
  const groups = (tag: string) => [["sbob", name, tag]];

  // (6,0)-(6,3): audit-keyed signature policies ----------------------------
  const kinds = ["base", "drift", "escalation", "info"] as const; // variant digits 0-3
  for (let i = 0; i < AUDIT_KEYED_POLICIES.length; i++) {
    const p = AUDIT_KEYED_POLICIES[i]!;
    if (policySuppressed(ir, p.name)) continue;
    const id = alloc.linux("rulePolicies", kinds[i]);
    const rule: XmlRule = {
      id,
      level: p.level,
      ifGroup: SHIPPED_AUDIT_GROUP,
      fields: [{ name: AUDIT_KEY, regex: `^${p.auditKey}$` }],
      description: p.description(name),
      groups: [...groups(p.groupTag), ["sbob", name, "sbob-signature"]],
      mitre: [p.mitre],
      options: ["no_full_log"],
      comment:
        "node-scoped key (Mode B): fires for any process riding the shipped auditd decoder family under the shipped 'audit' group — " +
        "k8s attribution relies on Mode A exe-scoped keys (tier 2); tier-1 cgroup attribution is INERT on wazuh 4.14.6 (the shipped auditd family preempts custom audit roots). " +
        "Fires by default — exemptions via rulePolicies.processAllowed (audit.command CDB)",
    };
    const comms = exemptComms(ir, p.name);
    if (comms.length > 0) {
      rule.list = { field: AUDIT_COMMAND, lookup: "not_match_key", src: exemptListPath(name, p.name) };
    }
    rules.push(rule);
  }

  // (0,1)/(0,2): opens-drift overlays (sensitive file / SA token) ------------
  const opensDriftId = rawId(alloc, SECTION_CODES.opens, 1);
  if (has(opensDriftId)) {
    if (!policySuppressed(ir, "sensitive-file-access")) {
      const rule: XmlRule = {
        id: alloc.linux("base", "drift"), // (0,1)
        level: 12,
        ifSid: opensDriftId,
        fields: [{ name: AUDIT_PATH, regex: SENSITIVE_PATH_REGEX }],
        description: `SBoB signature: sensitive file $(audit.directory.name) accessed (sensitive-file-access policy, TDS 7.4)`,
        groups: [...groups("sbob-sig-sensitive-file-access"), ["sbob", name, "sbob-signature", "file-access"]],
        mitre: ["T1552.001"],
        options: ["no_full_log"],
        comment: "severity-raising overlay on the opens drift rule; watchlist per TDS 7.4, quote-anchored (audit.directory.name carries its quotes)",
      };
      const comms = exemptComms(ir, "sensitive-file-access");
      if (comms.length > 0) {
        rule.list = { field: AUDIT_COMMAND, lookup: "not_match_key", src: exemptListPath(name, "sensitive-file-access") };
      }
      rules.push(rule);
      // (0,9) sustained-signature child of the OVERLAY (issue #42): on wazuh
      // 4.14 the if_matched_sid correlation context only accumulates while the
      // parent WINS the matched-rule selection, so the drift-parent sustained
      // rule ((2,2)) never fires once this level-12 overlay wins the event.
      // Repeated sensitive-file access needs its own correlation child.
      rules.push({
        id: alloc.linux("base", "sustained"), // (0,9)
        level: 13,
        ifMatchedSid: rule.id,
        sameField: { name: AUDIT_PATH },
        frequency: 8,
        timeframe: 120,
        description: `SBoB sustained signature: repeated sensitive-file access $(audit.directory.name) on ${name} (8 in 120s) — sustained exfil pattern (sensitive-file-access policy, TDS 7.4)`,
        groups: [...groups("sbob-sig-sensitive-file-access"), ["sbob", name, "sbob-signature", "file-access", "sustained"]],
        options: ["no_full_log"],
        comment:
          "chains off the overlay (0,1), not the drift parent: wazuh 4.14 correlation context accumulates only while the parent rule WINS the matched-rule selection, " +
          "and the level-12 overlay always outscores the level-9 drift rule; the drift-parent variant (2,2) covers non-sensitive repetition",
      });
    }
    if (!policySuppressed(ir, "service-account-token-access")) {
      const rule: XmlRule = {
        id: alloc.linux("base", "escalation"), // (0,2)
        level: 12,
        ifSid: opensDriftId,
        fields: [{ name: AUDIT_PATH, regex: SA_TOKEN_PATH_REGEX }],
        description: `SBoB signature: service-account token material $(audit.directory.name) read (service-account-token-access policy, TDS 7.4)`,
        groups: [...groups("sbob-sig-sa-token-access"), ["sbob", name, "sbob-signature", "credential-access"]],
        mitre: ["T1552.001"],
        options: ["no_full_log"],
        comment: "k8s projected SA volume; chain with kubernetes-api-access alerts for credential misuse (TDS 7.4)",
      };
      const comms = exemptComms(ir, "service-account-token-access");
      if (comms.length > 0) {
        rule.list = { field: AUDIT_COMMAND, lookup: "not_match_key", src: exemptListPath(name, "service-account-token-access") };
      }
      rules.push(rule);
    }
  }

  // (0,3) egress-drift overlay (kubernetes-api connect into the service CIDR):
  // DELETED on wazuh 4.14 — analysisd rejects PCRE2 conditions on the STATIC
  // srcip field ("Field 'srcip' is static") while <list> on static fields is
  // allowed. The kubernetes-api-access policy rides the manager-side k8s
  // audit-log JSON rule (6,4) instead; signatureCoverageNotes documents this.

  return rules;
}

/**
 * k8s-node-only signature rules: the manager-side kubernetes-api-access JSON
 * rule (6,4) and the binary-not-in-container-image correlate info (0,4).
 */
export function signatureRulesK8s(ir: IR, alloc: IdAllocator, lifecycleRuleId: number | null): XmlRule[] {
  const name = ir.workload.name;
  const ns = ir.workload.namespace;
  const rules: XmlRule[] = [];
  const groups = (tag: string) => [["sbob", name, tag]];

  // (6,4): manager-side kubernetes-api-access (k8s API audit log, TDS 4.4/7.4)
  if (!policySuppressed(ir, "kubernetes-api-access")) {
    rules.push({
      id: alloc.linux("rulePolicies", "exemption"), // (6,4)
      level: 12,
      fields: [
        { name: "object.user.username", regex: `^system:serviceaccount:${ns}:${name}$` },
        { name: "object.objectRef.resource", regex: "^(?:secrets|configmaps)$" },
      ],
      description: `SBoB signature: ${ns}/${name} service account read secrets/configmaps via the k8s API (kubernetes-api-access policy, TDS 7.4)`,
      groups: [...groups("sbob-sig-kubernetes-api-access"), ["sbob", name, "sbob-signature", "credential-access"]],
      mitre: ["T1552.001"],
      options: ["no_full_log"],
      comment:
        "evaluates the k8s API server audit log (wazuh/manager/sbob/k8s-api-audit.md ingestion path; TDS 4.4) " +
        "through the shipped json decoder. The node-side connect overlay (0,3) is NOT emitted on wazuh 4.14: srcip is a " +
        "STATIC field, so a PCRE2 CIDR condition on it fails analysisd (list lookups on static fields ARE allowed — " +
        "see the egress drift rule)",
    });
  }

  // (0,4): binary-not-in-container-image correlate info (child of the lifecycle rule)
  if (lifecycleRuleId !== null && !policySuppressed(ir, "binary-not-in-container-image")) {
    rules.push({
      id: alloc.linux("base", "exemption"), // (0,4)
      level: 3,
      ifSid: lifecycleRuleId,
      description: `SBoB signature: container started from the workload image — verify declared image digest, then correlate exec-drift alerts (100011-band) with image contents (binary-not-in-container-image policy, TDS 7.4)`,
      groups: [...groups("sbob-sig-binary-not-in-image"), ["sbob", name, "sbob-signature", "container-lifecycle"]],
      options: ["no_full_log"],
      comment:
        "cross-event correlation (docker lifecycle + exec drift timestamps) is a triage procedure, not a single-event " +
        "rule; image-content manifests are outside SBoB v0.0.4 (documented partial, TDS 7.4/8)",
    });
  }

  return rules;
}

// ---------------------------------------------------------------------------
// manifest coverage notes for the signature pack
// ---------------------------------------------------------------------------

export function signatureCoverageNotes(ir: IR): string[] {
  const notes: string[] = [];
  const rp = ir.rulePolicies;
  if (rp === undefined) {
    notes.push("rulePolicies: section-absent — signature pack emitted with defaults (fire-by-default, no exemptions; TDS 7.4)");
  } else {
    const suppressed = Object.entries(rp).filter(([, p]) => p.containerAllowed === true).map(([k]) => k);
    if (suppressed.length > 0) {
      notes.push(`rulePolicies: containerAllowed suppressed emission for: ${suppressed.join(", ")} (spec 4.8: not a deny)`);
    }
    const exempted = Object.entries(rp).filter(([, p]) => (p.processAllowed ?? []).length > 0).map(([k]) => k);
    if (exempted.length > 0) {
      notes.push(`rulePolicies: processAllowed comm exemptions emitted for: ${exempted.join(", ")} (CDB sigexempts lists on audit.command)`);
    }
  }
  notes.push(
    "signatures: audit keys are node-scoped (Mode B, attribution-weak) — declare processAllowed for container runtimes and node daemons (kubelet, containerd) to suppress expected noise",
    "signatures: the kubernetes-api-access node-side connect overlay (0,3) is not emitted on wazuh 4.14 — srcip is a static field and analysisd rejects PCRE2 conditions on static fields (CDB <list> on static fields IS allowed; that is how the egress drift rule works). The policy is carried by the manager-side k8s audit-log rule (6,4)",
    "signatures: sensitive-file overlay repetition escalates via the (0,9) sustained-signature child; the SA-token overlay (0,2) has no dedicated sustained child on the band — triage uses firedtimes (issue #42)",
  );
  return notes;
}

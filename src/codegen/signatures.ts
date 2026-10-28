/**
 * rulePolicies signature rules (TDS 7.4, M4 / issue #5).
 *
 * Signature rules invert the drift model: instead of allowlist drift, they
 * fire BY DEFAULT on security-relevant primitives (module load, namespace
 * change, ptrace, memfd execution, sensitive-file watchlist, SA token reads,
 * k8s API access) and are silenced per-policy by exemptions declared in the
 * SBoB `rulePolicies` section (spec 4.8):
 *
 *   - processAllowed: comm list -> CDB sigexempts list consulted with
 *     <list field="sbob.comm" lookup="not_match_key"> directly on the rule
 *     (deviation from the TDS 6.2 sketch, documented there: saves the
 *     level-0 suppressor child rules and their variant digits).
 *   - containerAllowed: true -> the rule (and its audit line) is not
 *     emitted at all for this workload (spec 4.8: not a deny).
 *
 * Absence semantics (TDS 8): a section-absent rulePolicies means the pack is
 * emitted with defaults (fire-by-default, no exemptions); an explicit empty
 * mapping requires --confirm-none rulePolicies (ERR_NONE_UNCONFIRMED).
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
 *   (0,3) kubernetes-api-access       egress-drift overlay  level 12  T1613
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
    description: (name) => `SBoB signature: kernel module load on ${name} scope (module-load policy, TDS 7.4) — comm $(sbob.comm), exe $(sbob.exe)`,
  },
  {
    name: "namespace-change",
    auditKey: "sbob-namespace-change",
    syscalls: ["unshare", "setns"],
    level: 10,
    mitre: "T1611",
    groupTag: "sbob-sig-namespace-change",
    description: (name) => `SBoB signature: namespace change (unshare/setns) on ${name} scope (namespace-change policy, TDS 7.4) — comm $(sbob.comm), exe $(sbob.exe)`,
  },
  {
    name: "process-tracing",
    auditKey: "sbob-process-tracing",
    syscalls: ["ptrace"],
    level: 10,
    mitre: "T1055.008",
    groupTag: "sbob-sig-process-tracing",
    description: (name) => `SBoB signature: ptrace on ${name} scope (process-tracing policy, TDS 7.4) — comm $(sbob.comm), exe $(sbob.exe)`,
  },
  {
    name: "execution-from-memory",
    auditKey: "sbob-memfd",
    syscalls: ["memfd_create"],
    level: 10,
    mitre: "T1620",
    groupTag: "sbob-sig-execution-from-memory",
    description: (name) => `SBoB signature: memfd_create (fileless execution) on ${name} scope (execution-from-memory policy, TDS 7.4) — comm $(sbob.comm), exe $(sbob.exe)`,
  },
];

/** Sensitive-path watchlist for the sensitive-file-access overlay (TDS 7.4). */
export const SENSITIVE_PATH_REGEX =
  "^(?:/etc/(?:shadow|gshadow|sudoers)(?:\\.d/\\S+)?|/root/\\.ssh/\\S+|/home/[^/]+/\\.ssh/\\S+|/etc/ssh/\\S+_key\\S*|\\S*/id_(?:rsa|ed25519|ecdsa)(?:\\.pub)?)$";

/** k8s service-account token mount (projected volume path, TDS 7.4). */
export const SA_TOKEN_PATH_REGEX = "^/var/run/secrets/kubernetes\\.io/serviceaccount/(?:token|ca\\.crt|namespace)$";

/**
 * Default kubeadm service CIDR 10.96.0.0/12 as a PCRE2 (the API server VIP
 * lives in it). Parameterizing the CIDR per cluster is an M5 deploy-repo knob.
 */
export const K8S_SERVICE_CIDR_REGEX = "^10\\.(?:9[6-9]|10[0-9]|11[01])\\.[0-9]{1,3}\\.[0-9]{1,3}$";

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
  return `sbob/${name}/sigexempts/${policy}`;
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
        `# key = comm, exact CDB match; workload: ${name}`,
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
 * audit-keyed policies in section 6 plus the opens/egress overlays in the
 * base section. `emitted` is the rule set assembled so far — overlay parents
 * must exist (section drift rules are conditional on SBoB content).
 */
export function signatureRulesShared(ir: IR, alloc: IdAllocator, emitted: XmlRule[]): XmlRule[] {
  const name = ir.workload.name;
  const rules: XmlRule[] = [];
  const has = (id: number) => emitted.some((r) => r.id === id);
  const groups = (tag: string) => ["sbob", name, tag];

  // (6,0)-(6,3): audit-keyed signature policies ----------------------------
  const kinds = ["base", "drift", "escalation", "info"] as const; // variant digits 0-3
  for (let i = 0; i < AUDIT_KEYED_POLICIES.length; i++) {
    const p = AUDIT_KEYED_POLICIES[i];
    if (policySuppressed(ir, p.name)) continue;
    const id = alloc.linux("rulePolicies", kinds[i]);
    const rule: XmlRule = {
      id,
      level: p.level,
      ifGroup: "auditd",
      fields: [{ name: "sbob.key", regex: `^${p.auditKey}$` }],
      description: p.description(name),
      groups: [groups(p.groupTag), ["sbob", name, "sbob-signature"]],
      mitre: [p.mitre],
      options: ["no_full_log"],
      comment:
        "node-scoped key (Mode B): fires for any process; on k8s nodes the cgroup decoders stamp sbob.pod_uid " +
        "for attribution. Fires by default — exemptions via rulePolicies.processAllowed (TDS 6.2)",
    };
    const comms = exemptComms(ir, p.name);
    if (comms.length > 0) {
      rule.list = { field: "sbob.comm", lookup: "not_match_key", src: exemptListPath(name, p.name) };
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
        fields: [{ name: "sbob.path", regex: SENSITIVE_PATH_REGEX }],
        description: `SBoB signature: sensitive file $(sbob.path) accessed (sensitive-file-access policy, TDS 7.4)`,
        groups: [groups("sbob-sig-sensitive-file-access"), ["sbob", name, "sbob-signature", "file-access"]],
        mitre: ["T1552.001"],
        options: ["no_full_log"],
        comment: "severity-raising overlay on the opens drift rule; watchlist per TDS 7.4",
      };
      const comms = exemptComms(ir, "sensitive-file-access");
      if (comms.length > 0) {
        rule.list = { field: "sbob.comm", lookup: "not_match_key", src: exemptListPath(name, "sensitive-file-access") };
      }
      rules.push(rule);
    }
    if (!policySuppressed(ir, "service-account-token-access")) {
      const rule: XmlRule = {
        id: alloc.linux("base", "escalation"), // (0,2)
        level: 12,
        ifSid: opensDriftId,
        fields: [{ name: "sbob.path", regex: SA_TOKEN_PATH_REGEX }],
        description: `SBoB signature: service-account token material $(sbob.path) read (service-account-token-access policy, TDS 7.4)`,
        groups: [groups("sbob-sig-sa-token-access"), ["sbob", name, "sbob-signature", "credential-access"]],
        mitre: ["T1552.001"],
        options: ["no_full_log"],
        comment: "k8s projected SA volume; chain with kubernetes-api-access alerts for credential misuse (TDS 7.4)",
      };
      const comms = exemptComms(ir, "service-account-token-access");
      if (comms.length > 0) {
        rule.list = { field: "sbob.comm", lookup: "not_match_key", src: exemptListPath(name, "service-account-token-access") };
      }
      rules.push(rule);
    }
  }

  // (0,3): egress-drift overlay (kubernetes API connect) ----------------------
  const egressDriftId = rawId(alloc, SECTION_CODES.egress, 1);
  if (has(egressDriftId) && !policySuppressed(ir, "kubernetes-api-access")) {
    rules.push({
      id: alloc.linux("base", "info"), // (0,3)
      level: 12,
      ifSid: egressDriftId,
      fields: [{ name: "sbob.dst_ip", regex: K8S_SERVICE_CIDR_REGEX }],
      description: `SBoB signature: undeclared connect into the k8s service CIDR $(sbob.dst_ip) (kubernetes-api-access policy, TDS 7.4)`,
      groups: [groups("sbob-sig-kubernetes-api-access"), ["sbob", name, "sbob-signature", "egress-traffic"]],
      mitre: ["T1613"],
      options: ["no_full_log"],
      comment:
        "default kubeadm service CIDR 10.96.0.0/12 (API server VIP); cluster-specific CIDR is an M5 deploy-repo knob. " +
        "Manager-side k8s audit-log rule for this policy lands with the k8s-node target (TDS 4.4)",
    });
  }

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
  const groups = (tag: string) => ["sbob", name, tag];

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
      groups: [groups("sbob-sig-kubernetes-api-access"), ["sbob", name, "sbob-signature", "credential-access"]],
      mitre: ["T1552.001"],
      options: ["no_full_log"],
      comment:
        "evaluates the k8s API server audit log (wazuh/manager/sbob/k8s-api-audit.md ingestion path; TDS 4.4) " +
        "through the shipped json decoder; the connect-side overlay (0,3) covers the node egress footprint",
    });
  }

  // (0,4): binary-not-in-container-image correlate info (child of the lifecycle rule)
  if (lifecycleRuleId !== null && !policySuppressed(ir, "binary-not-in-container-image")) {
    rules.push({
      id: alloc.linux("base", "exemption"), // (0,4)
      level: 3,
      ifSid: lifecycleRuleId,
      description: `SBoB signature: container started from the workload image — verify declared image digest, then correlate exec-drift alerts (100011-band) with image contents (binary-not-in-container-image policy, TDS 7.4)`,
      groups: [groups("sbob-sig-binary-not-in-image"), ["sbob", name, "sbob-signature", "container-lifecycle"]],
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
      notes.push(`rulePolicies: processAllowed comm exemptions emitted for: ${exempted.join(", ")} (CDB sigexempts lists)`);
    }
  }
  notes.push("signatures: audit keys are node-scoped (Mode B, attribution-weak) — declare processAllowed for container runtimes and node daemons (kubelet, containerd) to suppress expected noise");
  return notes;
}

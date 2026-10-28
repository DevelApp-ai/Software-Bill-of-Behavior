/**
 * Kubernetes-node codegen (TDS sections 4.4, 6.3, 7.3.2) — node agents.
 *
 * K8s nodes run the Linux agent and share the Linux variant band (TDS 6.1),
 * so this bundle composes the shared Linux building blocks and adds the
 * attribution layer:
 *
 *   - wazuh/audit/sbob/<name>.rules        Mode A exe-scoped audit keys
 *                                          (attribution tier 2, TDS 6.3)
 *   - wazuh/agent-conf/sbob/<name>-k8s.xml  docker-listener wodle (TDS 4.4)
 *   - wazuh/decoders/sbob/<name>-k8s.xml    audit chain + cgroup decoder
 *                                          (attribution tier 1, auditd >= 3.0)
 *   - wazuh/lists/sbob/<name>/*            CDB allowlists (shared design)
 *   - wazuh/lists/sbob/k8s/podmap         pod uid -> namespace/pod seed;
 *                                          runtime data, refreshed by
 *                                          scripts/sbob-podmap-refresh.sh
 *   - wazuh/rules/sbob/<base>_<name>_k8s-node.xml  drift rules (shared)
 *                                          + attribution section (7x)
 *                                          + signature pack (rulePolicies, M4)
 *   - wazuh/manager/sbob/k8s-api-audit.md  API-server audit ingestion path
 *   - wazuh/manager/sbob/<name>-envoy.md   Envoy JSON access-log contract for
 *                                          endpoints[] drift (M6, TDS 13)
 *                                          (evaluated by the manager-side
 *                                          kubernetes-api-access rule)
 *   - wazuh/agent-conf/sbob/<name>-audit-digest.sh   node-side digest script (M5)
 *   - <name>.manifest.json                 manifest + coverage matrix (TDS 8)
 *
 * Attribution rules (TDS 6.3, section code 7):
 *   (7,0) base          — cgroup-derived sbob.pod_uid present (level 0)
 *   (7,1) unresolved     — pod uid NOT in the node podmap (level 3; stale map)
 *   (7,2) reserved        — escalation digit, unused in M3
 *   (7,3) weak fallback  — node-scoped Mode B keys: attribution=weak (level 3)
 *   (7,4) lifecycle      — docker-listener container start for the workload
 *                          image (level 3; chains off shipped rule 87900)
 *
 * Deviation from the TDS 7.3.2 sketch, documented there: the Wazuh rule engine
 * cannot inject CDB values into alert fields, so pod/namespace stamping is
 * delivered as decoder fields (sbob.pod_uid travels on every alert) plus the
 * podmap value column (`namespace/pod`) for triage; the rules assert podmap
 * membership (match_key / not_match_key) rather than "stamping".
 */
import { escapeRegExp } from "../wildcards.ts";
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { Decoder, XmlRule } from "./xml.ts";
import { renderDecoder, renderRule, xmlFileHeader } from "./xml.ts";
import type { BundleFile } from "./linux.ts";
import { auditDecoders, auditFragmentLines, cdbListFiles, linuxSectionRules } from "./linux.ts";
import { envoyIngestionDoc, envoyListFiles, envoyRules } from "./envoy.ts";
import { signatureRulesK8s, signatureRulesShared, signatureCoverageNotes } from "./signatures.ts";
import {
  auditKeySetDigest,
  auditDigestScriptContent,
  bundleVersion,
  cadenceNote,
  cadenceRule,
  configCheckDecoder,
  configCheckRule,
  configCheckWodleBlock,
} from "./opshealth.ts";
import { buildCoverageMatrix, assertCoverageComplete } from "../coverage.ts";

const LAB_NOTE =
  "LAB VALIDATION PENDING (M3 exit criteria): replay scripts/logtest-corpus.sh k8s corpus on a lab k8s node with a live wazuh manager";

/** Shipped docker-integration base rule (0560-docker_integration_rules.xml). */
export const DOCKER_PARENT_RULE = 87900;

export function generateK8sNodeBundle(ir: IR, alloc: IdAllocator): BundleFile[] {
  const name = ir.workload.name;
  const files: BundleFile[] = [];

  // M5 ops section (TDS 10): config-check digest + sbob-cadence rule
  const configDigest = auditKeySetDigest(auditFragmentLines(ir).lines);
  const cadence = cadenceRule(ir, alloc);

  // --------------------------------------------------------------------------
  // 1. auditctl fragment (Mode A exe-scoped keys = attribution tier 2)
  // --------------------------------------------------------------------------
  {
    const { lines, modeA } = auditFragmentLines(ir);
    lines.push(
      "# k8s-node: container exes resolve inside the pod mount namespace (overlayfs),",
      "# so Mode A keys carry the workload identity implicitly (TDS 6.3 tier 2).",
      modeA
        ? "# cgroup field: keep auditd >= 3.0 defaults — SYSCALL records then carry cgroup=, enabling tier-1 pod attribution."
        : "# Mode B: attribution falls back to tier 3 (weak) unless cgroup emission is enabled.",
      "",
    );
    files.push({ path: `wazuh/audit/sbob/${name}.rules`, content: lines.join("\n") + "\n" });
  }

  // --------------------------------------------------------------------------
  // 2. CDB allowlists + podmap seed
  // --------------------------------------------------------------------------
  for (const f of cdbListFiles(ir, name)) files.push(f);
  // M6 endpoints[]: per-direction CDB path allowlists (section present only)
  for (const f of envoyListFiles(ir, name)) files.push(f);
  files.push({
    path: "wazuh/lists/sbob/k8s/podmap",
    content: [
      "# sbob k8s podmap — node runtime data (NOT derived from the SBoB; do not edit by hand).",
      "# key   = pod uid as it appears in cgroup paths (hex UUID); the refresh script",
      "#         emits BOTH forms — pod<uid-underscores>.scope (cgroup v2/systemd,",
      "#         kubelet escapes dashes) and pod<uid-dashes> (cgroup v2 dash-variant + v1)",
      "#         — because CDB lookups are exact-match; keep both lines per pod.",
      "# value = namespace/podname (carried for triage; TDS 6.3 tier 1)",
      "# maintained by scripts/sbob-podmap-refresh.sh (crictl or docker backend);",
      "# the manager loads it as a CDB list — restart the manager after refresh.",
    ].join("\n"),
  });

  // --------------------------------------------------------------------------
  // 3. decoder chain: audit family + cgroup attribution decoder
  // --------------------------------------------------------------------------
  {
    const { auditKeys } = auditFragmentLines(ir);
    const cgroupDecoderComment =
      "auditd >= 3.0 emits cgroup= on SYSCALL records; the decoders extract the kubepods pod uid " +
      "(TDS 6.3 tier 1). Real pod uids are hex UUIDs, not decimal; the three real-world cgroup forms are " +
      "covered by sibling decoders: cgroup v2/systemd with underscores (pod<uid>.scope), cgroup v2/systemd " +
      "with dashes (pod<uid>.scope), and cgroup v1 (pod<uid>/). OS_Regex-safe on purpose (decoders default " +
      "to OS_Regex): no lookaheads, no character classes, no bounded quantifiers";
    const decoders: Decoder[] = [
      ...auditDecoders(name, auditKeys),
      configCheckDecoder(name),
      {
        // cgroup v2/systemd — kubelet escapes uid dashes as underscores: pod<uid_underscores>.scope
        name: `sbob-${name}-audit-cgroup`,
        parent: `sbob-${name}-audit-key`,
        regex: "cgroup=\\S*kubepods\\S*pod(\\w+)\\.scope\\S*",
        order: "sbob.pod_uid",
        comment: cgroupDecoderComment,
      },
      {
        // cgroup v2/systemd — dashes preserved: pod<uid_dashes>.scope
        name: `sbob-${name}-audit-cgroup-dash`,
        parent: `sbob-${name}-audit-key`,
        regex: "cgroup=\\S*kubepods\\S*pod(\\w+-\\w+-\\w+-\\w+-\\w+)\\.scope\\S*",
        order: "sbob.pod_uid",
        comment: cgroupDecoderComment,
      },
      {
        // cgroup v1 — /kubepods/<qos>/pod<uid_dashes>/<container-id> (no .scope)
        name: `sbob-${name}-audit-cgroup-v1`,
        parent: `sbob-${name}-audit-key`,
        regex: "cgroup=\\S*kubepods\\S*pod(\\w+-\\w+-\\w+-\\w+-\\w+)/\\S*",
        order: "sbob.pod_uid",
        comment: cgroupDecoderComment,
      },
    ];
    const xml = [
      xmlFileHeader(`sbob decoders for workload ${name} — k8s-node target (audit + cgroup attribution)`, name, LAB_NOTE),
      "",
      ...decoders.map(renderDecoder).join("\n\n").split("\n"),
      "",
    ].join("\n");
    files.push({ path: `wazuh/decoders/sbob/${name}-k8s.xml`, content: xml });
  }

  // --------------------------------------------------------------------------
  // 4. agent configuration fragment: docker-listener wodle (TDS 4.4)
  // --------------------------------------------------------------------------
  {
    const xml = [
      xmlFileHeader(
        `sbobctl generated agent configuration fragment — merge into the k8s node agent's ossec.conf`,
        name,
        "requires the shipped docker integration (decoder json + rules 87900-87999) on the manager for lifecycle correlation",
      ),
      "",
      "<wodle name=\"docker-listener\">",
      "  <interval>600</interval>",
      "  <attempts>3</attempts>",
      "  <run_on_start>yes</run_on_start>",
      "  <disable_on_start>no</disable_on_start>",
      "</wodle>",
      "",
      ...configCheckWodleBlock(name),
      "",
    ].join("\n");
    files.push({ path: `wazuh/agent-conf/sbob/${name}-k8s.xml`, content: xml });
    files.push({ path: `wazuh/agent-conf/sbob/${name}-audit-digest.sh`, content: auditDigestScriptContent() });
  }

  // --------------------------------------------------------------------------
  // 5. rules XML: shared drift rules + attribution section (code 7)
  // --------------------------------------------------------------------------
  {
    const rules: XmlRule[] = linuxSectionRules(ir, alloc);
    const groups = (extra: string[]) => ["sbob", name, ...extra];

    // (7,0) attribution base — cgroup-derived pod uid present (tier 1)
    const attrBaseId = alloc.linux("attribution", "base");
    rules.push({
      id: attrBaseId,
      level: 0,
      ifGroup: "auditd",
      fields: [{ name: "sbob.pod_uid", regex: "^[0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}$" }],
      description: `SBoB attribution base: audit event carries a cgroup-derived pod uid (k8s node, ${name} scope)`,
      groups: [groups(["sbob-attribution"])],
      comment: "drift alerts already carry sbob.pod_uid via the decoder; this chain asserts podmap resolution (TDS 6.3 tier 1)",
    });

    // (7,1) podmap unresolved — uid not in podmap (stale refresh)
    rules.push({
      id: alloc.linux("attribution", "drift"),
      level: 3,
      ifSid: attrBaseId,
      list: { field: "sbob.pod_uid", lookup: "not_match_key", src: "sbob/k8s/podmap" },
      fields: [],
      description: `SBoB attribution: pod uid $(sbob.pod_uid) NOT in the node podmap — run scripts/sbob-podmap-refresh.sh on the node (TDS 6.3 tier 1, stale map)`,
      groups: [groups(["sbob-attribution", "attribution-stale"])],
      options: ["no_full_log"],
    });

    // (7,3) weak fallback — node-scoped Mode B keys (tier 3)
    rules.push({
      id: alloc.linux("attribution", "info"),
      level: 3,
      ifGroup: "auditd",
      fields: [{ name: "sbob.key", regex: "^sbob-(?:exec|open|connect)$" }],
      description: `SBoB attribution: weak — node-scoped audit key (Mode B fallback); sbob.workload=unknown-node-scope, host-process collision possible (TDS 6.3 tier 3)`,
      groups: [groups(["sbob-attribution", "attribution-weak"])],
      comment: "only fires when the workload runs Mode B (no literal exes); Mode A keys carry identity implicitly",
      options: ["no_full_log"],
    });

    // (7,4) container lifecycle — docker-listener start event for the workload image
    const lifecycleRuleId = alloc.linux("attribution", "exemption");
    rules.push({
      id: lifecycleRuleId,
      level: 3,
      ifSid: DOCKER_PARENT_RULE,
      fields: [
        { name: "docker.status", regex: "^start$" },
        { name: "docker.Actor.Attributes.image", regex: imageRepoRegex(ir.workload.imageID) },
      ],
      description: `SBoB lifecycle: container started from the workload image — $(docker.Actor.Attributes.name); correlate exec drift timestamps for binary-not-in-image investigation (TDS 4.4)`,
      groups: [groups(["sbob-attribution", "container-lifecycle"])],
      comment: `chains off shipped docker integration rule ${DOCKER_PARENT_RULE} (0560-docker_integration_rules.xml); image matched by repo name — docker events carry the image reference, not the digest`,
      options: ["no_full_log"],
    });

    // M4 signature pack (rulePolicies, TDS 7.4): shared audit-keyed rules and
    // drift overlays, then k8s-only manager-side + correlate rules
    rules.push(...signatureRulesShared(ir, alloc, rules));
    rules.push(...signatureRulesK8s(ir, alloc, lifecycleRuleId));

    // M5 ops section (TDS 10): config-check (8,3) + sbob-cadence (8,1)
    rules.push(configCheckRule(ir, alloc, configDigest));
    if (cadence !== undefined) rules.push(cadence);

    // M6 endpoints[] section (TDS 13): L7 endpoint drift via envoy JSON (9,1)/(9,2)
    rules.push(...envoyRules(ir, alloc, name));

    const xml = [
      xmlFileHeader(`sbob drift + attribution + signature + ops rules for workload ${name} — k8s-node target`, name, LAB_NOTE),
      "",
      ...rules.map(renderRule).join("\n\n").split("\n"),
      "",
    ].join("\n");
    files.push({
      path: `wazuh/rules/sbob/${100000 + alloc.slot * 100}_${name}_k8s-node.xml`,
      content: xml,
    });
  }

  // --------------------------------------------------------------------------
  // 6. manager-side ingestion path: k8s API server audit log (TDS 4.4)
  // --------------------------------------------------------------------------
  files.push({
    path: "wazuh/manager/sbob/k8s-api-audit.md",
    content: k8sApiAuditDoc(name),
  });
  // M6: envoy access-log ingestion contract (emitted when endpoints[] present)
  if ((ir.sections.endpoints ?? []).length > 0) {
    files.push(envoyIngestionDoc(ir, name));
  }

  // --------------------------------------------------------------------------
  // 7. bundle manifest (machine-generated coverage matrix: TDS 8, M4)
  // --------------------------------------------------------------------------
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
            target: "k8s-node",
            sbobVersion: ir.workload.sbobVersion,
            imageID: ir.workload.imageID,
            bundleVersion: bundleVersion(ir),
            files: files.map((f) => f.path),
            coverage,
            coverageNotes: [
              ...ir.coverageNotes,
              ...signatureCoverageNotes(ir),
              "k8s: attribution tiers per TDS 6.3 — 1 cgroup+podmap (auditd >= 3.0), 2 Mode A exe-scoped keys (default), 3 weak fallback (attribution=weak)",
              "k8s: podmap (sbob/k8s/podmap) is node runtime data maintained by scripts/sbob-podmap-refresh.sh; not derived from the SBoB",
              "k8s: docker-listener lifecycle rule requires the shipped integration ruleset (parent rule 87900)",
              "k8s: DNS-name egress entries are not observable from node auditd telemetry — Windows agents detect them via Sysmon EID 22 (TDS 8)",
              "k8s: manager-side kubernetes-api-access rule (rulePolicies signature) evaluates the API audit log ingested per wazuh/manager/sbob/k8s-api-audit.md",
              ...(cadenceNote(ir) !== undefined ? [cadenceNote(ir)] : []),
              "ops: config-check rule (8,3) compares the node digest from the command-wodle script against this bundle; multi-workload nodes see it fire on key-set differences (TDS 10.1)",
              ...(cadence !== undefined
                ? ["ops: sbob-cadence rule (8,1) alerts on digest mismatches between running containers and the pinned imageID; tag-only image references are not verifiable from docker events (TDS 10.3)"]
                : []),
            ],
            labValidation: "pending",
          },
          null,
          2,
        ) + "\n",
    });
  }

  return files;
}

/**
 * Match the docker event image reference for the workload's imageID.
 * The SBoB pins a digest (docker.io/library/redis@sha256:…); docker events
 * carry the image reference (redis, library/redis, docker.io/library/redis,
 * optionally with a tag) — match the repo name at a path boundary.
 */
export function imageRepoRegex(imageID: string): string {
  const repo = imageID.split("@")[0]!.split("/").pop()!.split(":")[0]!;
  return `(?:^|/)${escapeRegExp(repo)}(?=@|:|$)`;
}

function k8sApiAuditDoc(name: string): string {
  return `# k8s API server audit ingestion — ${name} scope

The manager-side \`kubernetes-api-access\` signature rule (rulePolicies, TDS 7.4)
evaluates events ingested through this path (TDS 4.4).

## API server: emit audit events

\`\`\`yaml
# /etc/kubernetes/audit-policy.yaml (apiserver --audit-policy-file=...)
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    users: ["system:kube-proxy"]     # reduce noise
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Metadata                  # everything else, cheap
\`\`\`

## Ship to the manager (two supported options)

1. **Syslog** — a log shipper on a control-plane node (fluent-bit/vector
   reading \`/var/log/kubernetes/audit.log\`) forwards to the manager's syslog
   listener:

\`\`\`xml
<!-- /var/ossec/etc/ossec.conf on the manager -->
<remote>
  <connection>syslog</connection>
  <port>5140</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.96.0.0/12</allowed-ips>
</remote>
\`\`\`

2. **Agent-side localfile** — a Wazuh agent on a control-plane node:

\`\`\`xml
<localfile>
  <location>/var/log/kubernetes/audit.log</location>
  <log_format>json</log_format>
</localfile>
\`\`\`

Both paths land the audit JSON at the manager where the M4
\`kubernetes-api-access\` rule (json decoder, \`kind: Event\`,
\`userAgent\`/\`verb\`/\`resource\` fields) evaluates it.
`;
}

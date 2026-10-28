/**
 * Falco codegen (TDS 13, M6 / issue #7): IR sections → Falco rules with
 * `not in` list semantics, a DaemonSet deployment, and the Wazuh-side
 * correlation rule so falco alerts land in the one pane of glass.
 *
 *   falco/sbob/<name>_rules.yaml           lists + drift rules
 *   falco/sbob/<name>-daemonset.yaml       DaemonSet (falco + sidekick + configmap)
 *   wazuh/decoders/sbob/<name>-falco.md?   — no custom decoder: falco JSON is
 *                                           ingested natively (log_format json)
 *   wazuh/manager/sbob/<name>-falco.md     manager-side ingestion path doc
 *   wazuh/rules/sbob/<base>_<name>_falco.xml  (10,3) falco alert correlation
 *
 * Semantics: falco alerts on `spawned_process` / `open_*` / `connect` events
 * whose subject is NOT in the generated lists:
 *   - exact paths → `in` lists (constant-time)
 *   - wildcarded paths → `pmatch` pattern lists
 *   - egress pairs → per-peer `(fd.rip=… and fd.rport=…)` conditions
 *
 * Falcosidekick ships alerts to the Wazuh manager (webhook/syslog); the
 * manager ingests the JSON natively and the (10,3) correlation rule ties the
 * alert to the workload by its `output_fields.container.name` field.
 *
 * Documented v1 limitations (docs/engine-matrix.md):
 *   - egress DNS names are not evaluable at the syscall layer (DNS-NAME blind);
 *   - execs[] args are not enforced (path-level);
 *   - signature-class behaviors (rulePolicies) are not translated — the
 *     auditd-keyed Wazuh signature pack stays the detector, with the falco
 *     module-load observation as the partial exception;
 *   - opens[] flags are approximated: write opens via open_write, read opens
 *     via open_read (the O_CREAT/O_TRUNC distinction is falco-internal).
 */
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { BundleFile } from "./linux.ts";
import { engineManifest, pathGlob } from "./engines.ts";
import type { XmlRule } from "./xml.ts";
import { renderRule, xmlFileHeader } from "./xml.ts";

export function generateFalcoBundle(ir: IR, alloc: IdAllocator): BundleFile[] {
  const files: BundleFile[] = [];
  const name = ir.workload.name;
  const list = (s: string) => `sbob_${name}_${s}`;
  const notes: string[] = [];
  const listsYaml: string[] = [];
  const rulesYaml: string[] = [];

  // execs ---------------------------------------------------------------------
  if (ir.sections.execs) {
    const exact: string[] = [];
    const patterns: string[] = [];
    for (const e of ir.sections.execs.entries) {
      const g = pathGlob(e.pathSegs);
      (e.isExact ? exact : patterns).push(g);
    }
    listsYaml.push(`- list: ${list("execs")}`, `  items: [${exact.join(", ")}]`);
    listsYaml.push(`- list: ${list("execs_patterns")}`, `  items: [${patterns.join(", ")}]`);
    rulesYaml.push(
      `- rule: SBoB drift — ${name} undeclared process execution`,
      `  desc: spawned process whose executable path is not in the ${name} SBoB execs[] allowlist`,
      `  condition: spawned_process and container and not proc.exepath in (${list("execs")}) and not proc.exepath pmatch (${list("execs_patterns")})`,
      `  output: "SBoB drift: ${name} undeclared process (user=%user.name proc.exepath=%proc.exepath parent=%proc.pname container=%container.name)"`,
      `  priority: WARNING`,
      `  tags: [sbob, sbob_${name}, sbob_drift]`,
    );
  } else {
    notes.push("falco: execs[] section absent — no exec drift rule emitted");
  }

  // opens ---------------------------------------------------------------------
  if (ir.sections.opens) {
    const exact: string[] = [];
    const patterns: string[] = [];
    for (const e of ir.sections.opens.entries) {
      const g = pathGlob(e.pathSegs);
      (e.isExact ? exact : patterns).push(g);
    }
    listsYaml.push(`- list: ${list("opens")}`, `  items: [${exact.join(", ")}]`);
    listsYaml.push(`- list: ${list("opens_patterns")}`, `  items: [${patterns.join(", ")}]`);
    rulesYaml.push(
      `- rule: SBoB drift — ${name} undeclared file open`,
      `  desc: file open whose path is not in the ${name} SBoB opens[] allowlist`,
      `  condition: (open_read or open_write) and container and not fd.name in (${list("opens")}) and not fd.name pmatch (${list("opens_patterns")})`,
      `  output: "SBoB drift: ${name} undeclared file open (user=%user.name fd.name=%fd.name proc=%proc.exepath container=%container.name)"`,
      `  priority: WARNING`,
      `  tags: [sbob, sbob_${name}, sbob_drift]`,
    );
    notes.push("falco: opens flags are approximated by open_read/open_write — the O_CREAT vs O_WRONLY distinction is falco-internal (documented partial)");
  } else {
    notes.push("falco: opens[] section absent — no open drift rule emitted");
  }

  // egress ---------------------------------------------------------------------
  if (ir.sections.egress) {
    const peers = ir.sections.egress.entries.filter((e) => e.addrEntries.length > 0);
    if (peers.length > 0) {
      const ips = [...new Set(peers.flatMap((p) => p.addrEntries.map((a) => a.split("/")[0]!)))];
      listsYaml.push(`- list: ${list("egress_ips")}`, `  items: [${ips.join(", ")}]`);
      const pairConds = peers.map((peer) => {
        const ports = peer.ports.filter((p): p is number => p !== null);
        if (ports.length === 0) return `fd.rip in (${list("egress_ips")})`;
        return `(fd.rip in (${list("egress_ips")}) and (${ports.map((p) => `fd.rport=${p}`).join(" or ")}))`;
      });
      rulesYaml.push(
        `- rule: SBoB drift — ${name} undeclared outbound connect`,
        `  desc: outbound connect whose remote ip/port pair is not in the ${name} SBoB egress[] allowlist`,
        `  condition: evt.type in (connect) and evt.dir=< and fd.typechar=4 and container and not (${pairConds.join(" or ")})`,
        `  output: "SBoB drift: ${name} undeclared connect (proc=%proc.exepath fd.rip=%fd.rip fd.rport=%fd.rport container=%container.name)"`,
        `  priority: WARNING`,
        `  tags: [sbob, sbob_${name}, sbob_drift]`,
      );
    }
    if (ir.sections.egress.entries.some((e) => e.dnsPatterns.length > 0 || e.dnsExact.length > 0)) {
      notes.push("falco: egress DNS names are not evaluable at the syscall layer (DNS-NAME documented blind — Sigma EID 22 / Wazuh cover it)");
    }
  } else {
    notes.push("falco: egress[] section absent — no connect drift rule emitted");
  }

  // signature-class note ---------------------------------------------------------
  notes.push(
    "falco: rulePolicies signature behaviors are not translated (the auditd-keyed Wazuh signature pack stays the detector); falco's own syscall observation covers kernel-module load partially (init_module/finit_module) — documented per-row in docs/engine-matrix.md",
    "falco: pmatch globs may match a broader path set than the SBoB single-segment wildcard (engine broadening, TDS 13)",
  );

  if (listsYaml.length > 0) {
    files.push({
      path: `falco/sbob/${name}_rules.yaml`,
      content: [
        `# sbobctl generated falco rules — workload: ${name} (TDS 13, M6)`,
        `# deploy via the ${name}-daemonset.yaml configmap (or drop into /etc/falco/rules.d)`,
        ``,
        ...listsYaml,
        ``,
        ...rulesYaml,
      ].join("\n") + "\n",
    });
  }

  // DaemonSet -------------------------------------------------------------------
  files.push({
    path: `falco/sbob/${name}-daemonset.yaml`,
    content: [
      `# sbobctl generated falco DaemonSet — workload: ${name} (TDS 13, M6)`,
      `# falco + falcosidekick; the rules configmap embeds ${name}_rules.yaml.`,
      `# Replace the FALCOSIDEKICK_WAZUH_* placeholders with the manager endpoint`,
      `# (see docs/runbook.md §1 for the wazuh/ bundle parts this deploys beside).`,
      `---`,
      `apiVersion: v1`,
      `kind: ConfigMap`,
      `metadata:`,
      `  name: sbob-${name}-falco-rules`,
      `  namespace: ${ir.workload.namespace}`,
      `data:`,
      `  ${name}_rules.yaml: |`,
      ...(files.find((f) => f.path === `falco/sbob/${name}_rules.yaml`)?.content ?? `# (no rules emitted — SBoB declares no falco-sweepable sections)\n`)
        .split("\n").map((l) => `    ${l}`),
      `---`,
      `apiVersion: apps/v1`,
      `kind: DaemonSet`,
      `metadata:`,
      `  name: sbob-${name}-falco`,
      `  namespace: ${ir.workload.namespace}`,
      `spec:`,
      `  selector:`,
      `    matchLabels: {app: sbob-${name}-falco}`,
      `  template:`,
      `    metadata:`,
      `      labels: {app: sbob-${name}-falco}`,
      `    spec:`,
      `      serviceAccountName: falco`,
      `      containers:`,
      `      - name: falco`,
      `        image: falcosecurity/falco:0.37.1   # pin by digest in production`,
      `        securityContext: {privileged: true}`,
      `        volumeMounts:`,
      `        - {name: rules, mountPath: /etc/falco/rules.d}`,
      `        - {name: boot, mountPath: /boot, readOnly: true}`,
      `        - {name: modules, mountPath: /host/lib/modules, readOnly: true}`,
      `        - {name: dev, mountPath: /dev}`,
      `        - {name: proc, mountPath: /host/proc, readOnly: true}`,
      `        env:`,
      `        - {name: FALCO_RULES_CONF, value: /etc/falco/rules.d}`,
      `      - name: falcosidekick`,
      `        image: falcosecurity/falcosidekick:2.31.0`,
      `        args: ["-l", ":2801"]`,
      `        env:`,
      `        - {name: WAZUH_WEBHOOK_URL, value: "FALCOSIDEKICK_WAZUH_URL"}`,
      `        - {name: WAZUH_WEBHOOK_MINIMUMPRIORITY, value: "info"}`,
      `        ports:`,
      `        - {containerPort: 2801}`,
      `      volumes:`,
      `      - name: rules`,
      `        configMap: {name: sbob-${name}-falco-rules}`,
      `      - {name: boot, hostPath: {path: /boot}}`,
      `      - {name: modules, hostPath: {path: /lib/modules}}`,
      `      - {name: dev, hostPath: {path: /dev}}`,
      `      - {name: proc, hostPath: {path: /proc}}`,
    ].join("\n") + "\n",
  });

  // Wazuh-side: manager ingestion doc + (10,3) falco correlation rule -----------
  files.push({
    path: `wazuh/manager/sbob/${name}-falco.md`,
    content: [
      `# falco → Wazuh ingestion for workload ${name} (TDS 13, M6)`,
      ``,
      `Falcosidekick (deployed by \`${name}-daemonset.yaml\`) forwards falco JSON`,
      `alerts to the manager webhook. Ingest them as a JSON log stream:`,
      ``,
      `\`\`\`xml`,
      `<localfile>`,
      `  <location>/var/ossec/logs/sbob/${name}-falco.json</location>`,
      `  <log_format>json</log_format>`,
      `</localfile>`,
      `\`\`\``,
      ``,
      `Falco JSON carries \`output_fields.container.name\` (the pod/workload`,
      `container name) and \`rule\` — the (10,3) correlation rule in this bundle`,
      `ties alerts to workload ${name} by matching the container name, so falco`,
      `drift shows up in the same pane of glass as the auditd bundle. No custom`,
      `decoder is needed: Wazuh parses the JSON natively (TDS 4.4 pattern).`,
    ].join("\n") + "\n",
  });

  {
    const ruleId = alloc.linux("engines", "info");
    const rule: XmlRule = {
      id: ruleId,
      level: 3,
      groups: [["sbob", name, "sbob-engines"]],
      description:
        `SBoB engines: falco drift alert for workload ${name} (correlated via output_fields.container.name; the falco bundle raised the event — see falco/sbob/${name}_rules.yaml, TDS 13)`,
      fields: [
        { name: "output_fields.container.name", regex: `^${name}$` },
      ],
      comment: "engines (10,3) falco alert correlation — hunt-time falco drift surfaced beside the auditd bundle",
    };
    files.push({
      path: `wazuh/rules/sbob/${100000 + alloc.slot * 100}_${name}_falco.xml`,
      content: [
        xmlFileHeader(
          `sbobctl generated falco correlation rule — workload: ${name}`,
          name,
          `requires the falco JSON ingestion path (wazuh/manager/sbob/${name}-falco.md)`,
        ),
        "",
        renderRule(rule),
        "",
      ].join("\n"),
    });
  }

  engineManifest(ir, "falco", files, notes);
  return files;
}

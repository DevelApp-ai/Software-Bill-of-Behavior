/**
 * Enforcement bundle orchestration (TDS 14, M7 / issue #8) — active
 * responses, enforcement telemetry and the per-target enforcement artifact
 * set, driven by the Monitor→Audit→Enforce state file (src/enforce.ts).
 *
 * `sbobctl enforce` emits, per target:
 *
 *   k8s-node: seccomp profile, NetworkPolicy (+ np-diff when --enforced-np),
 *             active responses, telemetry rule, manifest
 *   linux:     seccomp systemd drop-in, AppArmor profile, active responses,
 *             telemetry rule, manifest
 *   windows:   AppLocker policy, active responses (agent-conf only — custom
 *             AR scripts are linux-plane in v1), telemetry rule, manifest
 *
 * Wazuh-side artifacts live under wazuh/ so the M5 sync-manager flow maps
 * them unchanged; enforcement/ artifacts are applied via GitOps/kubectl/apparmor_parser
 * (runbook §9).
 */
import type { IR } from "../types.ts";
import type { EnforceStateFile, EnforceSectionKey } from "../enforce.ts";
import { effectiveState, sectionsInState } from "../enforce.ts";
import type { BundleFile } from "./linux.ts";
import { renderRule, xmlFileHeader } from "./xml.ts";
import type { IdAllocator } from "../ruleids.ts";
import { apparmorProfile, apparmorApplicable } from "./apparmor.ts";
import { seccompProfile, seccompSystemdDropin } from "./seccomp.ts";
import { networkPolicy, npRuleModel, npDiff } from "./networkpolicy.ts";
import { applockerPolicy } from "./applocker.ts";

export type EnforceTarget = "linux" | "windows" | "k8s-node";

export interface EnforceOptions {
  target: EnforceTarget;
  /** Peers JSON of the live enforced NetworkPolicy (np-diff input), if any. */
  enforcedNp?: { egress: Array<Record<string, unknown>>; ingress: Array<Record<string, unknown>> };
}

// ---------------------------------------------------------------------------
// active responses (TDS 14.1)
// ---------------------------------------------------------------------------

/**
 * Agent-side active-response blocks: firewall-drop bound to egress drift
 * (and ingress escalation where present), process-kill bound to exec drift.
 * Disabled by default: <disabled> is flipped to "no" ONLY for sections in
 * enforce state (TDS 14.6 — the alerting-clean window precedes enforcement).
 */
export function activeResponseConf(ir: IR, state: EnforceStateFile, alloc: IdAllocator): BundleFile {
  const name = ir.workload.name;
  const lines: string[] = [];
  lines.push(`<!-- sbobctl generated active responses — workload: ${name} (TDS 14.1, M7)`);
  lines.push(`     state file default: ${state.state}; disabled flags flip per-section (enforce only) -->`);

  const blocks: Array<{ section: EnforceSectionKey; command: string; ruleId: number }> = [];
  if (ir.sections.execs !== undefined) {
    blocks.push({ section: "execs", command: `sbob-${name}-process-kill`, ruleId: alloc.linux("execs", "drift") });
  }
  if (ir.sections.egress !== undefined) {
    blocks.push({ section: "egress", command: "firewall-drop", ruleId: alloc.linux("egress", "drift") });
  }
  if (ir.sections.ingress !== undefined) {
    blocks.push({ section: "ingress", command: "firewall-drop", ruleId: alloc.linux("ingress", "drift") });
  }

  for (const b of blocks) {
    const st = effectiveState(state, b.section);
    const disabled = st === "enforce" ? "no" : "yes";
    lines.push(`<active-response>`);
    lines.push(`  <!-- section ${b.section}: ${st} state — ${
      st === "enforce" ? "ACTIVE (kill-switch: flip this to yes without regenerating)" : "disabled (Monitor/Audit — detection only)"
    } -->`);
    lines.push(`  <command>${b.command}</command>`);
    lines.push(`  <location>local</location>`);
    lines.push(`  <rules_id>${b.ruleId}</rules_id>`);
    lines.push(`  <timeout>60</timeout>`);
    lines.push(`  <disabled>${disabled}</disabled>`);
    lines.push(`</active-response>`);
  }
  lines.push(``);
  return {
    path: `wazuh/agent-conf/sbob/${name}-ar.xml`,
    content: lines.join("\n"),
  };
}

/** Agent-side process-kill AR script (linux/k8s plane; windows uses AppLocker). */
export function processKillScript(ir: IR): BundleFile {
  const name = ir.workload.name;
  const content = `#!/bin/sh
# sbobctl generated process-kill active response — workload: ${name} (TDS 14.1, M7)
# Deploy to the agent's /var/ossec/active-response/bin/ (runbook §9).
# Invoked by Wazuh with: <script> <action> <user> <ip> <alert-id> <rule-id> <agent-id> <filename>
ACTION=$1
ALERT=$(echo "$9" | sed 's/^ *//;s/ *$//')   # JSON alert payload

# telemetry first: every enforcement event is itself a Wazuh alert (TDS 14.6)
pid=$(printf '%s' "$ALERT" | grep -o '"syscall.process.id":"[0-9]*"' | head -1 | grep -o '[0-9]*')
exe=$(printf '%s' "$ALERT" | grep -o '"syscall.exe":"[^"]*"' | head -1 | sed 's/"syscall.exe":"//;s/"$//')
if [ "\${ACTION}" = "delete" ]; then
  echo '{"sbob_workload":"${name}","action":"process-kill-revert","pid":'\${pid}'}' >> /var/ossec/logs/sbob-enforce.log
  exit 0
fi
if [ -n "\${pid}" ] && kill -9 "\${pid}" 2>/dev/null; then
  echo '{"sbob_workload":"${name}","action":"process-kill","pid":'\${pid}',"exe":"'\${exe}'"}' >> /var/ossec/logs/sbob-enforce.log
  exit 0
fi
echo '{"sbob_workload":"${name}","action":"process-kill-failed","pid":'\${pid:-null}'}' >> /var/ossec/logs/sbob-enforce.log
exit 1
`;
  return {
    path: `wazuh/active-response/bin/sbob-${name}-process-kill.sh`,
    content,
  };
}

/** Agent localfile for the enforcement telemetry log (fed to rule (11,1)). */
export function enforceTelemetryLocalfile(ir: IR): BundleFile {
  const name = ir.workload.name;
  return {
    path: `wazuh/agent-conf/sbob/${name}-enforce-localfile.xml`,
    content: [
      `<!-- sbobctl generated — enforcement telemetry ingestion (TDS 14.6, M7) -->`,
      `<localfile>`,
      `  <location>/var/ossec/logs/sbob-enforce.log</location>`,
      `  <log_format>json</log_format>`,
      `</localfile>`,
      ``,
    ].join("\n"),
  };
}

/**
 * Enforcement-telemetry rule (section code 11): fires on the AR script's
 * JSON telemetry lines (level 10 — enforcement events are always visible,
 * TDS 14.6 "every block event is itself a Wazuh alert").
 */
export function enforceTelemetryRule(ir: IR, alloc: IdAllocator): BundleFile {
  const name = ir.workload.name;
  const ruleId = alloc.linux("enforcement", "drift"); // (11,1)
  const rule = {
    id: ruleId,
    level: 10,
    fields: [
      { name: "sbob_workload", regex: `^${name}$` },
      { name: "action", regex: `^process-kill(?:-revert|-failed)?$|^firewall-drop$` },
    ],
    description:
      `SBoB enforcement: active response executed for workload ${name} (process-kill / firewall-drop telemetry — the block event itself, TDS 14.6)`,
    groups: [["sbob", name, "sbob-enforce"]],
    comment: `enforcement (11,1) — requires the ${name}-enforce-localfile.xml ingestion (json format, TDS 14.6)`,
  };
  return {
    path: `wazuh/rules/sbob/${100000 + alloc.slot * 100}_${name}_enforce.xml`,
    content: [
      xmlFileHeader(
        `sbobctl generated enforcement-telemetry rule — workload: ${name}`,
        name,
        `fires on /var/ossec/logs/sbob-enforce.log (json localfile, ${name}-enforce-localfile.xml)`,
      ),
      "",
      renderRule(rule),
      "",
    ].join("\n"),
  };
}

/** Manager-side enforcement doc — AR command definitions + rollback notes. */
export function enforceManagerDoc(ir: IR, state: EnforceStateFile): BundleFile {
  const name = ir.workload.name;
  const enforcing = sectionsInState(state, "enforce");
  return {
    path: `wazuh/manager/sbob/${name}-enforce.md`,
    content: [
      `# Enforcement setup for workload ${name} (TDS 14, M7)`,
      ``,
      `State file default: **${state.state}**${enforcing.length > 0 ? `; enforcing sections: ${enforcing.join(", ")}` : ""}.`,
      ``,
      `## Manager ossec.conf — AR command definition`,
      ``,
      `The shipped \`firewall-drop\` command is predefined. The custom process-kill`,
      `command must be defined once on the manager:`,
      ``,
      "```xml",
      `<command>`,
      `  <name>sbob-${name}-process-kill</name>`,
      `  <executable>sbob-${name}-process-kill.sh</executable>`,
      `  <timeout_allowed>yes</timeout_allowed>`,
      `</command>`,
      "```",
      ``,
      `Deploy \`sbob-${name}-process-kill.sh\` to the agent's`,
      `\`/var/ossec/active-response/bin/\` (config management; runbook §9).`,
      ``,
      `## Telemetry`,
      ``,
      `The script writes JSON lines to \`/var/ossec/logs/sbob-enforce.log\`,`,
      `ingested by the \`${name}-enforce-localfile.xml\` agent-conf block and`,
      `alerted by rule (11,1). Every block/revert/failure event is visible`,
      `(TDS 14.6).`,
      ``,
      `## Kill-switch`,
      ``,
      `Per agent group: flip \`<disabled>\` to \`yes\` in the group's agent.conf`,
      `AR block (or remove the \`${name}-ar.xml\` fragment and re-sync).`,
      `The detection bundle stays active — the kill-switch only disables`,
      `active responses.`,
      ``,
    ].join("\n"),
  };
}

// ---------------------------------------------------------------------------
// bundle assembly
// ---------------------------------------------------------------------------

export interface EnforceResult {
  files: BundleFile[];
  notes: string[];
  /** Sections currently enforcing (manifest + summary). */
  enforcing: EnforceSectionKey[];
}

export function generateEnforceBundle(
  ir: IR,
  state: EnforceStateFile,
  alloc: IdAllocator,
  opts: EnforceOptions,
): EnforceResult {
  const name = ir.workload.name;
  const files: BundleFile[] = [];
  const notes: string[] = [];
  const enforcing = sectionsInState(state, "enforce");
  const globalState = state.state;

  // active responses + telemetry (all targets; windows gets conf/doc only)
  files.push(activeResponseConf(ir, state, alloc));
  files.push(enforceTelemetryLocalfile(ir));
  files.push(enforceTelemetryRule(ir, alloc));
  files.push(enforceManagerDoc(ir, state));
  if (opts.target !== "windows") {
    files.push(processKillScript(ir));
  }
  notes.push(`active responses: disabled by default; enabled per section in enforce state only (TDS 14.6)`);

  if (opts.target === "k8s-node") {
    if (globalState === "monitor") {
      notes.push(`seccomp: not emitted — global state monitor (TDS 14.2)`);
    } else {
      files.push(seccompProfile(ir, globalState === "enforce" ? "enforce" : "audit"));
      notes.push(`seccomp: ${globalState} mode (${globalState === "enforce" ? "SCMP_ACT_ERRNO" : "SCMP_ACT_LOG"} on the M4 signature syscall surface)`);
    }
    const npActive =
      (ir.sections.egress !== undefined && effectiveState(state, "egress") !== "monitor") ||
      (ir.sections.ingress !== undefined && effectiveState(state, "ingress") !== "monitor");
    if (npActive) {
      files.push(networkPolicy(ir, state));
      const npMode =
        effectiveState(state, "egress") === "enforce" && effectiveState(state, "ingress") === "enforce"
          ? "enforce"
          : "audit";
      notes.push(`networkpolicy: ${npMode} — ${
        npMode === "enforce"
          ? "apply live (undeclared traffic blocked)"
          : "Calico staged policy or --dry-run=server only while not enforcing (TDS 14.4)"
      }`);
      if (opts.enforcedNp !== undefined) {
        const declared = npRuleModel(ir, state);
        const drift = npDiff(declared, opts.enforcedNp);
        files.push({
          path: `enforcement/sbob/${name}/networkpolicy/${name}-np-diff.json`,
          content: JSON.stringify(
            { workload: name, declared: npRuleModel(ir, state), enforced: opts.enforcedNp, drift },
            null,
            2,
          ) + "\n",
        });
        notes.push(`np-diff: ${drift.length} drifted rule(s) between declared SBoB and enforced NetworkPolicy`);
      }
    } else {
      notes.push(`networkpolicy: not emitted — egress/ingress both monitor or absent`);
    }
  }

  if (opts.target === "linux") {
    if (globalState === "monitor") {
      notes.push(`seccomp (systemd): not emitted — global state monitor`);
    } else {
      files.push(seccompSystemdDropin(ir, globalState === "enforce" ? "enforce" : "audit"));
      notes.push(`seccomp (systemd): ${globalState} SystemCallFilter deny-list drop-in`);
    }
    if (apparmorApplicable(state)) {
      files.push(apparmorProfile(ir, state));
      notes.push(`apparmor: execs=${effectiveState(state, "execs")} opens=${effectiveState(state, "opens")} — ${
        enforcing.includes("execs") || enforcing.includes("opens") ? "enforce (blocking)" : "complain (audit)"
      }`);
    } else {
      notes.push(`apparmor: not emitted — execs and opens both monitor`);
    }
  }

  if (opts.target === "windows") {
    files.push(applockerPolicy(ir, state));
    notes.push(`applocker: execs=${effectiveState(state, "execs")} (EnforcementMode mirrors the state machine; WDAC audit-mode is the same transition, TDS 14.5)`);
  }

  // manifest
  const manifest = {
    workload: name,
    namespace: ir.workload.namespace,
    sbobVersion: ir.workload.sbobVersion,
    imageID: ir.workload.imageID,
    target: opts.target,
    state: { default: globalState, sections: state.sections, enforcing },
    auditRecords: state.auditRecords,
    artifacts: files.map((f) => f.path),
    notes,
    labValidation: "pending",
  };
  files.push({
    path: `${name}-enforce.manifest.json`,
    content: JSON.stringify(manifest, null, 2) + "\n",
  });

  return { files, notes, enforcing };
}

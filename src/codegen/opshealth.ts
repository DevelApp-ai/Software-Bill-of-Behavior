/**
 * Ops-health rules (M5, TDS 10) — the "drift of the drift system" layer.
 *
 * New section code 8 (`ops`, Linux/k8s variant band; amendment to TDS 6.1):
 *   (8,1) sbob-cadence    — container started from the workload's image repo
 *                          with a digest that does not match the SBoB-pinned
 *                          imageID (level 9; k8s target only, chains off the
 *                          shipped docker-integration parent rule 87900)
 *   (8,3) config-check   — the node's installed sbob audit key set does not
 *                          hash to the bundle's expected digest (level 5;
 *                          linux + k8s targets) ⇒ audit.rules rollout required
 *
 * The config-check digest is computed at transpile time over the workload's
 * audit fragment key set and re-computed on the node by the command-wodle
 * script emitted alongside (wazuh/agent-conf/sbob/<name>-audit-digest.sh):
 * sha256 over the sorted unique `-k sbob…` keys, one per line. The rule fires
 * when the node-reported digest differs, which is exactly "the node's audit
 * rules are stale relative to the bundle" (TDS 10.1: audit rules are not
 * hot-reloadable; node rollout is coordinated via this rule).
 *
 * Limitations (documented in TDS 10.1/10.3 and docs/runbook.md):
 *   - the digest is exact for single-workload nodes (the agent-group model of
 *     TDS 6.3); multi-workload nodes see the rule fire and triage compares
 *     `auditctl -l | grep sbob` manually
 *   - docker events carry the image reference; only digest-bearing references
 *     are verifiable, so tag-only starts are not alerted by the cadence rule
 */
import { createHash } from "node:crypto";
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { Decoder, XmlRule } from "./xml.ts";
import { escapeRegExp } from "../wildcards.ts";

/** Shipped docker-integration base rule (0560-docker_integration_rules.xml);
 * same value as DOCKER_PARENT_RULE in k8s.ts — kept local to avoid a module
 * cycle (linux -> opshealth -> k8s -> linux). */
const DOCKER_PARENT_RULE = 87900;

// ---------------------------------------------------------------------------
// config-check digest
// ---------------------------------------------------------------------------

/** Extract the `-k sbob…` audit keys from generated audit fragment lines. */
export function auditFragmentKeys(lines: string[]): string[] {
  const keys = new Set<string>();
  for (const line of lines) {
    const m = /-k (sbob[a-zA-Z0-9_.-]*)/.exec(line);
    if (m) keys.add(m[1]!);
  }
  return [...keys].sort();
}

/**
 * sha256 over the sorted unique sbob audit keys, one per line — byte-identical
 * to `auditctl -l | grep -oE -- '-k sbob…' | sort -u | sha256sum` as emitted by
 * the node-side digest script.
 */
export function auditKeySetDigest(lines: string[]): string {
  const keys = auditFragmentKeys(lines);
  const payload = keys.length === 0 ? "" : keys.join("\n") + "\n";
  return createHash("sha256").update(payload).digest("hex");
}

/** Decoder for the command-wodle digest line (`sbob-audit-digest: <hex>`). */
export function configCheckDecoder(name: string): Decoder {
  return {
    name: `sbob-${name}-config-check`,
    prematch: "^sbob-audit-digest: [0-9a-f]{64}",
    regex: "^sbob-audit-digest: ([0-9a-f]{64})",
    order: "sbob.audit_digest",
    comment:
      "command-wodle output from sbob-audit-digest.sh: sha256 of the node's installed sbob audit key set (TDS 10.1)",
  };
}

/** (8,3) config-check rule: fires when the node digest != bundle digest. */
export function configCheckRule(ir: IR, alloc: IdAllocator, digest: string): XmlRule {
  const name = ir.workload.name;
  return {
    id: alloc.linux("ops", "info"),
    level: 5,
    fields: [{ name: "sbob.audit_digest", regex: `^(?!${digest}$)` }],
    description: `SBoB ops: node sbob audit key set does not match the ${name} bundle (config-check, TDS 10.1) — audit.rules rollout required on this node; expected key-set digest ${digest.slice(0, 12)}…`,
    groups: [["sbob", name, "sbob-ops"]],
    comment:
      "fires from the command-wodle digest line when the node's installed sbob audit keys differ from the bundle (audit rules are not hot-reloadable; node rollout required)",
  };
}

/** Node-side script emitted into the bundle (copied to the agent-group shared dir). */
export function auditDigestScriptContent(): string {
  return [
    "#!/bin/sh",
    "# sbob-audit-digest.sh — emit the sbob audit key-set digest for the config-check rule (M5, TDS 10.1).",
    "# Output: 'sbob-audit-digest: <sha256>' consumed by the sbob-*-config-check decoder.",
    "# The digest covers the sorted unique '-k sbob…' keys installed on this node;",
    "# it is compared against the bundle's expected digest by rule (8,3) on the manager.",
    "# Lab-validation caveat: confirm the auditctl -l key rendering (quoted vs bare)",
    "# on the target OS during the pilot — see docs/runbook.md.",
    "set -u",
    "auditctl -l 2>/dev/null \\",
    "  | grep -oE -- '-k sbob[a-zA-Z0-9_.-]+' \\",
    "  | sed 's/^-k //' \\",
    "  | sort -u \\",
    "  | sha256sum \\",
    "  | awk '{print \"sbob-audit-digest: \" $1}'",
    "",
  ].join("\n");
}

/** Agent-conf fragment block: command wodle running the digest script. */
export function configCheckWodleBlock(name: string): string[] {
  return [
    "<!-- M5 config-check (TDS 10.1): report the node's installed sbob audit key set digest;",
    "     the manager-side rule (8,3) compares it against the bundle and alerts when the",
    "     node needs an audit.rules rollout. The script ships in the group's shared dir;",
    "     confirm the agent-side shared path on the pilot node (see docs/runbook.md). -->",
    "<wodle name=\"command\">",
    "  <disabled>no</disabled>",
    "  <tag>sbob-config-check</tag>",
    "  <command>bash /var/ossec/etc/shared/sbob-" + name + "/sbob-audit-digest.sh</command>",
    "  <interval>30m</interval>",
    "  <ignore_output>no</ignore_output>",
    "</wodle>",
  ];
}

// ---------------------------------------------------------------------------
// sbob-cadence rule (k8s target only)
// ---------------------------------------------------------------------------

/** Digest hex of a digest-pinned imageID, or undefined when tag-pinned only. */
export function pinnedImageDigest(imageID: string): string | undefined {
  const m = /^.+@sha256:([0-9a-f]{64})$/.exec(imageID);
  return m ? m[1] : undefined;
}

/**
 * (8,1) sbob-cadence rule: container started from the workload's image repo
 * with a digest that differs from the SBoB-pinned imageID (TDS 10.3). Only
 * digest-bearing image references are verifiable from docker events, so
 * tag-only starts are not alerted (documented limitation).
 * Returns undefined when the SBoB imageID is not digest-pinned.
 */
export function cadenceRule(ir: IR, alloc: IdAllocator): XmlRule | undefined {
  const name = ir.workload.name;
  const imageID = ir.workload.imageID;
  const digest = pinnedImageDigest(imageID);
  if (digest === undefined) return undefined;
  const repo = imageID.split("@")[0]!.split("/").pop()!.split(":")[0]!;
  const mismatchRegex = `(?:^|/)${escapeRegExp(repo)}@sha256:(?!${digest}$)`;
  return {
    id: alloc.linux("ops", "drift"),
    level: 9,
    ifSid: DOCKER_PARENT_RULE,
    fields: [
      { name: "docker.status", regex: "^start$" },
      { name: "docker.Actor.Attributes.image", regex: mismatchRegex },
    ],
    description: `SBoB ops: container started from the ${name} image repo with a digest that does not match the SBoB-pinned image (${imageID}) — update the SBoB or roll back the image (TDS 10.3)`,
    groups: [["sbob", name, "sbob-ops"]],
    comment:
      "chains off the shipped docker integration rule 87900; only digest-bearing image references are verifiable from docker events (tag-only starts are not alerted — TDS 10.3 limitation)",
  };
}

/** Coverage note when the cadence rule cannot be emitted (tag-pinned imageID). */
export function cadenceNote(ir: IR): string | undefined {
  if (pinnedImageDigest(ir.workload.imageID) === undefined) {
    return `ops: sbob-cadence rule not emitted — imageID "${ir.workload.imageID}" is not digest-pinned; container starts from this image cannot be verified against the SBoB (TDS 10.3)`;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// bundle versioning (TDS 10.2)
// ---------------------------------------------------------------------------

/** Bundle version string embedding SBoB version + image digest (TDS 10.2). */
export function bundleVersion(ir: IR): string {
  const digest = pinnedImageDigest(ir.workload.imageID);
  const short = digest !== undefined ? digest.slice(0, 12) : "untagged";
  return `sbob-v${ir.workload.sbobVersion}-${short}`;
}

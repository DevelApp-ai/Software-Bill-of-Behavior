/**
 * Kubernetes NetworkPolicy codegen (TDS 14.4, M7 / issue #8) — from the
 * ingress[]/egress[] sections, plus the declared-SBoB vs enforced-NP diff
 * that finally evaluates podSelector/namespaceSelector peers (the §8
 * k8sPeer gap).
 *
 *   enforcement/sbob/<name>/networkpolicy/<name>.yaml    NetworkPolicy
 *   enforcement/sbob/<name>/networkpolicy/<name>-np-diff.json
 *     (when --enforced-np is provided: machine-readable report of declared
 *      vs enforced drift; non-empty drift exits 1 from the CLI)
 *
 * State semantics (TDS 14): NetworkPolicy has no native audit mode. Sections
 * in enforce → the NP is emitted with annotation mode: enforce. Sections in
 * audit → the NP carries annotation mode: audit and MUST NOT be applied as a
 * live policy: on Calico apply as a staged (audit) policy; on vanilla
 * Kubernetes use --dry-run=server (validate only). Monitor sections
 * contribute commented-out rule blocks.
 *
 * Documented v1 limitations:
 *   - dnsNames are not evaluable (NetworkPolicy has no FQDN syntax; the
 *     DNS-NAME documented blind persists — declare the resolver IP:port);
 *   - the workload podSelector uses the sbob.k8sstormcenter.io/workload
 *     label convention — workload pods MUST carry it (manifest note);
 *   - ipBlock except clauses and port ranges are not emitted (SBoB has
 *     neither construct).
 */
import type { IR, NetCompiled, PortEntry } from "../types.ts";
import type { EnforceStateFile, EnforceSectionKey } from "../enforce.ts";
import { effectiveState } from "../enforce.ts";
import type { BundleFile } from "./linux.ts";

/** NP peer JSON for one SBoB net entry (ipBlock and/or label selectors). */
function npPeers(entry: NetCompiled): Array<Record<string, unknown>> {
  const peers: Array<Record<string, unknown>> = [];
  for (const addr of entry.addrEntries) {
    peers.push({ ipBlock: { cidr: addr } });
  }
  const src = entry.source;
  if (src.podSelector !== undefined || src.namespaceSelector !== undefined) {
    const peer: Record<string, unknown> = {};
    if (src.namespaceSelector !== undefined) {
      peer.namespaceSelector = src.namespaceSelector;
    }
    if (src.podSelector !== undefined) {
      peer.podSelector = src.podSelector;
    }
    peers.push(peer);
  }
  return peers;
}

function npPorts(ports: PortEntry[]): Array<Record<string, unknown>> | undefined {
  if (ports.length === 0) return undefined;
  return ports.map((p) =>
    p.port === null ? { protocol: p.protocol ?? "TCP" } : { protocol: p.protocol ?? "TCP", port: p.port },
  );
}

/** Canonical JSON of the NetworkPolicy rules derived from the SBoB (diff base). */
export function npRuleModel(ir: IR, state: EnforceStateFile): Record<string, unknown> {
  const model: Record<string, unknown> = {
    workload: ir.workload.name,
    namespace: ir.workload.namespace,
    podSelector: { matchLabels: { "sbob.k8sstormcenter.io/workload": ir.workload.name } },
    egress: [],
    ingress: [],
  };
  const egress: Array<Record<string, unknown>> = [];
  for (const entry of ir.sections.egress?.entries ?? []) {
    const st = effectiveState(state, "egress");
    if (st === "monitor") continue;
    const peers = npPeers(entry);
    const ports = npPorts(entry.source.ports);
    if (peers.length === 0 && ports === undefined) continue;
    const rule: Record<string, unknown> = { peers, ports: ports ?? [] };
    if (st === "audit") (rule as Record<string, unknown>)["mode"] = "audit";
    egress.push(rule);
  }
  const ingress: Array<Record<string, unknown>> = [];
  for (const entry of ir.sections.ingress?.entries ?? []) {
    const st = effectiveState(state, "ingress");
    if (st === "monitor") continue;
    const peers = npPeers(entry);
    const ports = npPorts(entry.source.ports);
    if (peers.length === 0 && ports === undefined) continue;
    const rule: Record<string, unknown> = { peers, ports: ports ?? [] };
    if (st === "audit") (rule as Record<string, unknown>)["mode"] = "audit";
    ingress.push(rule);
  }
  model.egress = egress;
  model.ingress = ingress;
  return model;
}

export function networkPolicy(ir: IR, state: EnforceStateFile): BundleFile {
  const name = ir.workload.name;
  const egressState = effectiveState(state, "egress");
  const ingressState = effectiveState(state, "ingress");
  const mode = egressState === "enforce" && ingressState === "enforce" ? "enforce" : "audit";

  const lines: string[] = [];
  lines.push(`# sbobctl generated NetworkPolicy — workload: ${name} (TDS 14.4, M7)`);
  lines.push(`# states: egress=${egressState} ingress=${ingressState}`);
  lines.push(`# ${mode === "enforce"
    ? "ENFORCE: apply as a live policy — undeclared traffic is blocked"
    : "AUDIT: do NOT apply live — Calico staged policy or --dry-run=server only (TDS 14)"}`);
  lines.push(`apiVersion: networking.k8s.io/v1`);
  lines.push(`kind: NetworkPolicy`);
  lines.push(`metadata:`);
  lines.push(`  name: sbob-${name}`);
  lines.push(`  namespace: ${ir.workload.namespace}`);
  lines.push(`  annotations:`);
  lines.push(`    sbob.k8sstormcenter.io/mode: "${mode}"`);
  lines.push(`    sbob.k8sstormcenter.io/workload: "${name}"`);
  lines.push(`spec:`);
  lines.push(`  podSelector:`);
  lines.push(`    matchLabels:`);
  lines.push(`      sbob.k8sstormcenter.io/workload: ${name}`);
  lines.push(`  policyTypes: [Egress${(ir.sections.ingress?.entries.length ?? 0) > 0 ? ", Ingress" : ""}]`);

  // egress -------------------------------------------------------------------
  if (egressState === "monitor" || (ir.sections.egress?.entries.length ?? 0) === 0) {
    lines.push(`  # egress: ${egressState === "monitor" ? "section in Monitor state — no egress rules emitted" : "section absent"}`);
  } else {
    lines.push(`  egress:`);
    for (const entry of ir.sections.egress!.entries) {
      const peers = npPeers(entry);
      const ports = npPorts(entry.source.ports);
      if (peers.length === 0 && ports === undefined) continue;
      lines.push(`    - to:`);
      for (const peer of peers) {
        if ("ipBlock" in peer) {
          lines.push(`        - ipBlock:`);
          lines.push(`            cidr: ${(peer.ipBlock as { cidr: string }).cidr}`);
        } else {
          lines.push(`        - podSelector:      # label-selector peer (k8sPeer evaluated, TDS 14.4)`);
          const ps = (peer as { podSelector?: { matchLabels?: Record<string, string> } }).podSelector?.matchLabels ?? {};
          for (const [k, v] of Object.entries(ps)) {
            lines.push(`            matchLabels:`);
            lines.push(`              ${k}: ${v}`);
          }
          const ns = (peer as { namespaceSelector?: { matchLabels?: Record<string, string> } }).namespaceSelector;
          if (ns !== undefined) {
            lines.push(`          namespaceSelector:`);
            for (const [k, v] of Object.entries(ns.matchLabels ?? {})) {
              lines.push(`            matchLabels:`);
              lines.push(`              ${k}: ${v}`);
            }
          }
        }
      }
      if (ports !== undefined) {
        lines.push(`      ports:`);
        for (const p of ports) {
          lines.push(`        - protocol: ${p.protocol}`);
          if ("port" in p) lines.push(`          port: ${p.port}`);
        }
      }
      if (entry.source.dnsNames !== undefined && entry.source.dnsNames.length > 0) {
        lines.push(`      # dnsNames not evaluable in NetworkPolicy (DNS-NAME blind, TDS 13/14):`);
        lines.push(`      #   ${entry.source.dnsNames.join(", ")}`);
      }
    }
  }

  // ingress ------------------------------------------------------------------
  if (ingressState === "monitor" || (ir.sections.ingress?.entries.length ?? 0) === 0) {
    lines.push(`  # ingress: ${ingressState === "monitor" ? "section in Monitor state — no ingress rules emitted" : "section absent"}`);
  } else {
    lines.push(`  ingress:`);
    for (const entry of ir.sections.ingress!.entries) {
      const peers = npPeers(entry);
      const ports = npPorts(entry.source.ports);
      if (peers.length === 0 && ports === undefined) continue;
      lines.push(`    - from:`);
      for (const peer of peers) {
        if ("ipBlock" in peer) {
          lines.push(`        - ipBlock:`);
          lines.push(`            cidr: ${(peer.ipBlock as { cidr: string }).cidr}`);
        } else {
          lines.push(`        - podSelector:      # label-selector peer (k8sPeer evaluated, TDS 14.4)`);
          const ps = (peer as { podSelector?: { matchLabels?: Record<string, string> } }).podSelector?.matchLabels ?? {};
          for (const [k, v] of Object.entries(ps)) {
            lines.push(`            matchLabels:`);
            lines.push(`              ${k}: ${v}`);
          }
          const ns = (peer as { namespaceSelector?: { matchLabels?: Record<string, string> } }).namespaceSelector;
          if (ns !== undefined) {
            lines.push(`          namespaceSelector:`);
            for (const [k, v] of Object.entries(ns.matchLabels ?? {})) {
              lines.push(`            matchLabels:`);
              lines.push(`              ${k}: ${v}`);
            }
          }
        }
      }
      if (ports !== undefined) {
        lines.push(`      ports:`);
        for (const p of ports) {
          lines.push(`        - protocol: ${p.protocol}`);
          if ("port" in p) lines.push(`          port: ${p.port}`);
        }
      }
    }
  }
  lines.push(``);

  return {
    path: `enforcement/sbob/${name}/networkpolicy/${name}.yaml`,
    content: lines.join("\n"),
  };
}

export interface NpDiffEntry {
  /** declared in the SBoB but absent from the enforced policy (or vice versa) */
  kind: "missing-rule" | "extra-rule";
  direction: "egress" | "ingress";
  /** canonical JSON of the rule (peers + ports) */
  detail: string;
}

/**
 * Declared-SBoB vs enforced-NP diff. `enforcedPeers` is the JSON extracted
 * from the cluster's live NetworkPolicy (the operator provides the file);
 * the report lists declared-but-not-enforced (missing) and
 * enforced-but-not-declared (extra) peers/ports.
 */
export function npDiff(
  declared: Record<string, unknown>,
  enforcedPeers: { egress: Array<Record<string, unknown>>; ingress: Array<Record<string, unknown>> },
): NpDiffEntry[] {
  const entries: NpDiffEntry[] = [];
  const canon = (x: unknown) => JSON.stringify(sortKeys(x));
  const sortKeys = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sortKeys);
    if (x !== null && typeof x === "object") {
      return Object.fromEntries(Object.entries(x as Record<string, unknown>).map(([k, v]) => [k, sortKeys(v)] as [string, unknown]).sort((e1, e2) => (e1[0] < e2[0] ? -1 : 1)));
    }
    return x;
  };

  for (const direction of ["egress", "ingress"] as const) {
    const declaredRules = (declared[direction] as Array<Record<string, unknown>>) ?? [];
    const enforced = enforcedPeers[direction] ?? [];
    const declaredCanon = new Set(declaredRules.map((r) => canon({ peers: r.peers, ports: r.ports })));
    const enforcedCanon = new Set(enforced.map((r) => canon({ peers: r.peers, ports: r.ports })));
    for (const r of declaredRules) {
      const c = canon({ peers: r.peers, ports: r.ports });
      if (!enforcedCanon.has(c)) {
        entries.push({ kind: "missing-rule", direction, detail: c });
      }
    }
    for (const r of enforced) {
      const c = canon({ peers: r.peers, ports: r.ports });
      if (!declaredCanon.has(c)) {
        entries.push({ kind: "extra-rule", direction, detail: c });
      }
    }
  }
  return entries;
}

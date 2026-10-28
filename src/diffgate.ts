/**
 * SBoB semantic diff gate (M8, TDS §16): section-aware diff of two validated
 * SBoB documents with a scored delta ladder.
 *
 * Compares parsed, validated structures — never raw YAML text — so a
 * reformatted file diffs to zero. Output is deterministic: same inputs ⇒
 * byte-identical report.
 *
 * Scoring ladder (proposal-grade defaults; field-guide chapter "Behavior
 * Deltas at the Release Gate", §2 — calibrate against a real estate's
 * release history before enforcing):
 *   +5  new Linux capability · new rulePolicies exemption
 *   +4  new exec path outside the package's own namespace
 *   +3  new egress DNS name outside internal suffixes
 *   +2  new egress IP/port · new write-flag open path · widened wildcard ·
 *       new ingress peer
 *   +1  removed entries (all sections) · new exec path inside the namespace ·
 *       new read-only open path
 *
 * Thresholds: advisory Δ ≥ 10 · mandatory review Δ ≥ 25 · any single +5
 * class ⇒ immediate mandatory review regardless of total.
 *
 * `endpoints[]` changes are reported but unweighted in v1 (HTTP-level
 * sections are not observable from the Phase 1 telemetry plane; revisit at
 * Phase 2 L7 ingestion).
 */
import type { NetEntryLike, SbobDocumentLike } from "./schema.ts";
import { parsePathPattern, compilePathSegs } from "./wildcards.ts";

export const ADVISORY_THRESHOLD_DEFAULT = 10;
export const MANDATORY_THRESHOLD_DEFAULT = 25;
export const DEFAULT_INTERNAL_SUFFIXES = ["svc", "cluster.local", "internal", "local"];

export const WRITE_FLAGS: ReadonlySet<string> = new Set(["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"]);

export interface DeltaItem {
  section: string;
  change: "added" | "removed" | "modified" | "widened" | "covered";
  entry: string;
  weight: number;
  note?: string;
}

export type GateVerdict = "clean" | "advisory" | "mandatory";

export interface DiffOptions {
  /** Explicit package-namespace directories (e.g. ["/usr/bin", "/app"]); overrides inference. */
  namespaces?: string[];
  /** Extra DNS suffixes treated as internal (on top of the defaults). */
  internalSuffixes?: string[];
  advisoryThreshold?: number;
  mandatoryThreshold?: number;
}

export interface DiffResult {
  workload: { name: string; namespace: string };
  oldImageID: string;
  newImageID: string;
  delta: DeltaItem[];
  score: number;
  verdict: GateVerdict;
  immediateReview: boolean;
  /** Behavior changes the ladder does not score in v1 (reported, weight 0). */
  unweighted: string[];
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function literalPrefix(path: string): string {
  const i = path.search(/[*\u22EF]/); // first wildcard: `*` or `⋯`
  return i === -1 ? path : path.slice(0, i);
}

function isPattern(path: string): boolean {
  return /[*\u22EF]/.test(path);
}

function pathRegexOf(path: string): RegExp {
  // compilePathSegs returns an unanchored fragment (TDS 5.2); anchor for full match
  const frag = compilePathSegs(parsePathPattern(path, "path (" + path + ")"));
  return new RegExp("^" + frag + "$");
}

function normalizeDns(name: string): string {
  return name.replace(/\.$/, "").toLowerCase();
}

function isInternalDns(name: string, suffixes: string[]): boolean {
  const n = normalizeDns(name);
  return suffixes.some((s) => n === s || n.endsWith("." + s));
}

function netEntryKey(e: NetEntryLike): string {
  if (e.identifier !== undefined && e.identifier !== "") return "id:" + e.identifier;
  const ips = [...(e.ipAddresses ?? [])].sort().join(",");
  const dns = [...(e.dnsNames ?? [])].sort().join(",");
  const ports = e.ports.map((p) => (p.protocol ?? "ANY") + "/" + (p.port ?? "any")).sort().join(",");
  return "content:" + ips + "|" + dns + "|" + ports;
}

function netSubItems(e: NetEntryLike): { ip: string[]; dns: string[]; port: string[]; selector: boolean } {
  return {
    ip: [...(e.ipAddresses ?? [])].sort(),
    dns: [...(e.dnsNames ?? [])].sort(),
    port: e.ports.map((p) => (p.protocol ?? "ANY") + "/" + (p.port ?? "any")).sort(),
    selector: e.podSelector !== undefined || e.namespaceSelector !== undefined,
  };
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)];
}

function diffSets(oldSet: string[], newSet: string[]): { added: string[]; removed: string[] } {
  const o = new Set(oldSet);
  const n = new Set(newSet);
  return {
    added: newSet.filter((x) => !o.has(x)),
    removed: oldSet.filter((x) => !n.has(x)),
  };
}

// ---------------------------------------------------------------------------
// section diffing
// ---------------------------------------------------------------------------

interface SectionDiff {
  delta: DeltaItem[];
  unweighted: string[];
}

function diffExecs(oldDoc: SbobDocumentLike, newDoc: SbobDocumentLike, namespacesOpt: string[]): SectionDiff {
  const delta: DeltaItem[] = [];
  const unweighted: string[] = [];
  const oldExecs = oldDoc.spec.execs ?? [];
  const newExecs = newDoc.spec.execs ?? [];
  const oldPaths = uniq(oldExecs.map((e) => e.path));
  const newPaths = uniq(newExecs.map((e) => e.path));

  // package namespace: explicit override, else inferred as the set of parent
  // directories of prior exact execs. Conservative fallback: namespace
  // unknown (no prior exact execs) ⇒ every new exec path scores outside.
  const namespaces = namespacesOpt.length > 0
    ? namespacesOpt
    : uniq(oldExecs.filter((e) => !isPattern(e.path)).map((e) => e.path.replace(/\/[^/]*$/, "")));
  const oldPatterns = oldPaths.filter(isPattern).map(pathRegexOf);

  const { added, removed } = diffSets(oldPaths, newPaths);

  for (const p of removed) {
    delta.push({ section: "execs", change: "removed", entry: p, weight: 1 });
  }
  for (const p of added) {
    if (!isPattern(p) && oldPatterns.some((r) => r.test(p))) {
      delta.push({ section: "execs", change: "covered", entry: p, weight: 0, note: "exact entry already covered by a prior pattern" });
      continue;
    }
    if (isPattern(p) && oldPaths.some((o) => isPattern(o) && literalPrefix(o).startsWith(literalPrefix(p)) && literalPrefix(p).length < literalPrefix(o).length)) {
      delta.push({ section: "execs", change: "widened", entry: p, weight: 2, note: "widens a prior pattern" });
      continue;
    }
    const inside = namespaces.some((ns) => p === ns || p.startsWith(ns + "/"));
    if (inside) {
      delta.push({ section: "execs", change: "added", entry: p, weight: 1, note: "inside the package namespace" });
    } else {
      delta.push({ section: "execs", change: "added", entry: p, weight: 4, note: namespaces.length === 0 ? "package namespace unknown (no prior exact execs)" : "outside the package namespace" });
    }
  }

  // args-only changes on existing paths: reported, unweighted in v1
  const oldArgs = new Map(oldExecs.map((e) => [e.path, e.args ?? null] as const));
  for (const e of newExecs) {
    const prev = oldArgs.get(e.path);
    if (prev !== undefined && JSON.stringify(prev) !== JSON.stringify(e.args ?? null)) {
      unweighted.push("execs: args vector changed for " + e.path);
    }
  }
  return { delta, unweighted };
}

function diffOpens(oldDoc: SbobDocumentLike, newDoc: SbobDocumentLike): SectionDiff {
  const delta: DeltaItem[] = [];
  const oldOpens = oldDoc.spec.opens ?? [];
  const newOpens = newDoc.spec.opens ?? [];
  const oldMap = new Map(oldOpens.map((e) => [e.path, e.flags] as const));
  const newMap = new Map(newOpens.map((e) => [e.path, e.flags] as const));
  const oldPatternKeys = [...oldMap.keys()].filter(isPattern);
  const oldPatterns = oldPatternKeys.map(pathRegexOf);

  for (const [path, flags] of oldMap) {
    const now = newMap.get(path);
    if (now === undefined) {
      delta.push({ section: "opens", change: "removed", entry: path, weight: 1 });
      continue;
    }
    const { added } = diffSets(flags, now);
    if (added.length > 0) {
      const writes = added.filter((f) => WRITE_FLAGS.has(f));
      if (writes.length > 0) {
        delta.push({ section: "opens", change: "modified", entry: path, weight: 2, note: "write flags added: " + writes.join(", ") });
      } else {
        delta.push({ section: "opens", change: "modified", entry: path, weight: 1, note: "flags added: " + added.join(", ") });
      }
    }
  }
  for (const [path, flags] of newMap) {
    if (oldMap.has(path)) continue;
    if (!isPattern(path) && oldPatterns.some((r) => r.test(path))) {
      delta.push({ section: "opens", change: "covered", entry: path, weight: 0, note: "exact entry already covered by a prior pattern" });
      continue;
    }
    if (isPattern(path) && oldPatternKeys.some((o) => literalPrefix(o).startsWith(literalPrefix(path)) && literalPrefix(path).length < literalPrefix(o).length)) {
      delta.push({ section: "opens", change: "widened", entry: path, weight: 2, note: "widens a prior pattern" });
      continue;
    }
    const writes = flags.filter((f) => WRITE_FLAGS.has(f));
    if (writes.length > 0) {
      delta.push({ section: "opens", change: "added", entry: path, weight: 2, note: "write-flag open path" });
    } else {
      delta.push({ section: "opens", change: "added", entry: path, weight: 1, note: "read-only open path" });
    }
  }
  return { delta, unweighted: [] };
}

function diffNet(oldDoc: SbobDocumentLike, newDoc: SbobDocumentLike, section: "egress" | "ingress", internalSuffixes: string[]): SectionDiff {
  const delta: DeltaItem[] = [];
  const oldEntries = (section === "egress" ? oldDoc.spec.egress : oldDoc.spec.ingress) ?? [];
  const newEntries = (section === "egress" ? newDoc.spec.egress : newDoc.spec.ingress) ?? [];
  const oldByKey = new Map(oldEntries.map((e) => [netEntryKey(e), e] as const));
  const newByKey = new Map(newEntries.map((e) => [netEntryKey(e), e] as const));

  for (const [key] of oldByKey) {
    if (!newByKey.has(key)) {
      delta.push({ section, change: "removed", entry: "peer " + key, weight: 1 });
    }
  }
  for (const [key, newE] of newByKey) {
    const oldE = oldByKey.get(key);
    if (oldE === undefined) {
      const s = netSubItems(newE);
      for (const dns of s.dns) {
        const internal = isInternalDns(dns, internalSuffixes);
        const w = section === "egress" ? (internal ? 2 : 3) : 2;
        delta.push({ section, change: "added", entry: "peer " + key + ": dns " + dns, weight: w, note: internal ? "internal DNS name" : "external DNS name" });
      }
      for (const ip of s.ip) {
        delta.push({ section, change: "added", entry: "peer " + key + ": ip " + ip, weight: 2 });
      }
      for (const port of s.port) {
        delta.push({ section, change: "added", entry: "peer " + key + ": port " + port, weight: 2 });
      }
      if (s.selector && s.ip.length === 0 && s.dns.length === 0) {
        delta.push({ section, change: "added", entry: "peer " + key + ": k8s selector", weight: 2, note: "podSelector/namespaceSelector peer" });
      }
      continue;
    }
    // existing peer: compare sub-items
    const o = netSubItems(oldE);
    const s = netSubItems(newE);
    const ipDiff = diffSets(o.ip, s.ip);
    const dnsDiff = diffSets(o.dns, s.dns);
    const portDiff = diffSets(o.port, s.port);
    for (const ip of ipDiff.added) delta.push({ section, change: "added", entry: "peer " + key + ": ip " + ip, weight: 2 });
    for (const ip of ipDiff.removed) delta.push({ section, change: "removed", entry: "peer " + key + ": ip " + ip, weight: 1 });
    for (const dns of dnsDiff.added) {
      const internal = isInternalDns(dns, internalSuffixes);
      const w = section === "egress" ? (internal ? 2 : 3) : 2;
      delta.push({ section, change: "added", entry: "peer " + key + ": dns " + dns, weight: w, note: internal ? "internal DNS name" : "external DNS name" });
    }
    for (const dns of dnsDiff.removed) delta.push({ section, change: "removed", entry: "peer " + key + ": dns " + dns, weight: 1 });
    for (const port of portDiff.added) delta.push({ section, change: "added", entry: "peer " + key + ": port " + port, weight: 2 });
    for (const port of portDiff.removed) delta.push({ section, change: "removed", entry: "peer " + key + ": port " + port, weight: 1 });
  }
  return { delta, unweighted: [] };
}

function diffCapabilities(oldDoc: SbobDocumentLike, newDoc: SbobDocumentLike): SectionDiff {
  const delta: DeltaItem[] = [];
  const { added, removed } = diffSets(oldDoc.spec.capabilities ?? [], newDoc.spec.capabilities ?? []);
  for (const c of added) {
    delta.push({ section: "capabilities", change: "added", entry: c, weight: 5, note: "new Linux capability" });
  }
  for (const c of removed) {
    delta.push({ section: "capabilities", change: "removed", entry: c, weight: 1 });
  }
  return { delta, unweighted: [] };
}

function diffRulePolicies(oldDoc: SbobDocumentLike, newDoc: SbobDocumentLike): SectionDiff {
  const delta: DeltaItem[] = [];
  const oldRp = oldDoc.spec.rulePolicies ?? {};
  const newRp = newDoc.spec.rulePolicies ?? {};

  // explicit-NONE regression: old protected, new is {} (NONE = no signature
  // protection; the transpile side requires --confirm-none rulePolicies)
  const newIsNone = newDoc.spec.rulePolicies !== undefined && Object.keys(newRp).length === 0;
  const oldProtected = Object.keys(oldRp).length > 0;
  if (newIsNone && oldProtected) {
    delta.push({ section: "rulePolicies", change: "removed", entry: "rulePolicies → explicit NONE", weight: 5, note: "all signature protection removed" });
  }

  for (const [name, oldP] of Object.entries(oldRp)) {
    const newP = newRp[name];
    if (newP === undefined) {
      // policy gone; if the whole section became absent the default pack
      // fires (tighter) — still recorded as a removed entry
      delta.push({ section: "rulePolicies", change: "removed", entry: name, weight: 1 });
      continue;
    }
    const procDiff = diffSets(oldP.processAllowed ?? [], newP.processAllowed ?? []);
    for (const comm of procDiff.added) {
      delta.push({ section: "rulePolicies", change: "added", entry: name + ": processAllowed " + comm, weight: 5, note: "new signature-rule exemption" });
    }
    for (const comm of procDiff.removed) {
      delta.push({ section: "rulePolicies", change: "removed", entry: name + ": processAllowed " + comm, weight: 1 });
    }
    if (oldP.containerAllowed !== true && newP.containerAllowed === true) {
      delta.push({ section: "rulePolicies", change: "added", entry: name + ": containerAllowed: true", weight: 5, note: "rule suppressed entirely" });
    }
    if (oldP.containerAllowed === true && newP.containerAllowed !== true) {
      delta.push({ section: "rulePolicies", change: "removed", entry: name + ": containerAllowed", weight: 1 });
    }
  }
  for (const [name, newP] of Object.entries(newRp)) {
    if (oldRp[name] !== undefined) continue;
    for (const comm of newP.processAllowed ?? []) {
      delta.push({ section: "rulePolicies", change: "added", entry: name + ": processAllowed " + comm, weight: 5, note: "new signature-rule exemption (new policy)" });
    }
    if (newP.containerAllowed === true) {
      delta.push({ section: "rulePolicies", change: "added", entry: name + ": containerAllowed: true", weight: 5, note: "rule suppressed entirely (new policy)" });
    }
  }
  return { delta, unweighted: [] };
}

function diffEndpoints(oldDoc: SbobDocumentLike, newDoc: SbobDocumentLike): SectionDiff {
  const unweighted: string[] = [];
  const oldEps = oldDoc.spec.endpoints ?? [];
  const newEps = newDoc.spec.endpoints ?? [];
  const oldSet = new Set(oldEps.map((e) => e.direction + " " + e.endpoint));
  const newSet = new Set(newEps.map((e) => e.direction + " " + e.endpoint));
  for (const k of newSet) if (!oldSet.has(k)) unweighted.push("endpoints: added " + k + " (unweighted in v1 — not observable from Phase 1 telemetry)");
  for (const k of oldSet) if (!newSet.has(k)) unweighted.push("endpoints: removed " + k + " (unweighted in v1)");
  return { delta: [], unweighted };
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

export function diffSbobs(oldDoc: SbobDocumentLike, newDoc: SbobDocumentLike, opts: DiffOptions = {}): DiffResult {
  if (oldDoc.metadata.name !== newDoc.metadata.name) {
    throw new Error(
      "ERR_WORKLOAD_MISMATCH: old SBoB is workload \"" + oldDoc.metadata.name +
      "\", new SBoB is workload \"" + newDoc.metadata.name + "\" — diff compares releases of the same workload",
    );
  }
  const internalSuffixes = uniq([...DEFAULT_INTERNAL_SUFFIXES, ...(opts.internalSuffixes ?? [])]);
  const sections: SectionDiff[] = [
    diffExecs(oldDoc, newDoc, opts.namespaces ?? []),
    diffOpens(oldDoc, newDoc),
    diffNet(oldDoc, newDoc, "egress", internalSuffixes),
    diffNet(oldDoc, newDoc, "ingress", internalSuffixes),
    diffCapabilities(oldDoc, newDoc),
    diffRulePolicies(oldDoc, newDoc),
    diffEndpoints(oldDoc, newDoc),
  ];
  const delta = sections.flatMap((s) => s.delta).sort((a, b) => {
    if (a.section !== b.section) return a.section < b.section ? -1 : 1;
    if (a.weight !== b.weight) return b.weight - a.weight;
    if (a.change !== b.change) return a.change < b.change ? -1 : 1;
    return a.entry < b.entry ? -1 : a.entry > b.entry ? 1 : 0;
  });
  const unweighted = uniq(sections.flatMap((s) => s.unweighted)).sort();
  const score = delta.reduce((acc, d) => acc + d.weight, 0);
  const immediateReview = delta.some((d) => d.weight >= 5);
  const advisoryAt = opts.advisoryThreshold ?? ADVISORY_THRESHOLD_DEFAULT;
  const mandatoryAt = opts.mandatoryThreshold ?? MANDATORY_THRESHOLD_DEFAULT;
  const verdict: GateVerdict = score >= mandatoryAt || immediateReview ? "mandatory" : score >= advisoryAt ? "advisory" : "clean";
  return {
    workload: { name: oldDoc.metadata.name, namespace: oldDoc.metadata.namespace },
    oldImageID: oldDoc.spec.imageID,
    newImageID: newDoc.spec.imageID,
    delta,
    score,
    verdict,
    immediateReview,
    unweighted,
  };
}

export function formatDiffReport(result: DiffResult): string {
  const lines: string[] = [];
  const w = result.workload;
  lines.push("# SBoB diff gate — " + w.name + " (" + w.namespace + ")");
  lines.push("");
  lines.push("- old: " + result.oldImageID);
  lines.push("- new: " + result.newImageID);
  lines.push("");
  if (result.delta.length === 0) {
    lines.push("No scored behavior changes.");
  } else {
    lines.push("| section | change | entry | weight | note |");
    lines.push("|---|---|---|---|---|");
    for (const d of result.delta) {
      lines.push("| " + d.section + " | " + d.change + " | " + d.entry + " | " + d.weight + " | " + (d.note ?? "") + " |");
    }
  }
  lines.push("");
  lines.push("**Δ = " + result.score + "** — verdict: **" + result.verdict.toUpperCase() + "**" + (result.immediateReview ? " (immediate review: +5 class present)" : ""));
  if (result.verdict === "advisory") lines.push("_Advisory threshold reached: attach this delta to the promotion record and notify the owning team._");
  if (result.verdict === "mandatory") lines.push("_Mandatory review: promotion blocks until a human signs this delta._");
  if (result.unweighted.length > 0) {
    lines.push("");
    lines.push("Reported but unweighted (v1):");
    for (const u of result.unweighted) lines.push("- " + u);
  }
  return lines.join("\n") + "\n";
}

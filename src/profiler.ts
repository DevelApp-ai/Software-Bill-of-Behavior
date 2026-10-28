/**
 * SBoB observability bootstrap profiler (M9, TDS §17): derive a *candidate*
 * SBoB with provenance from a window of normalized `sbob.*` telemetry, so a
 * human reviews and signs a draft contract instead of hand-writing behavioral
 * contracts for vendor-less workloads.
 *
 * Grounded in the field-guide chapter "Observed Behavior to Declared Intent —
 * Bootstrapping an SBoB from Telemetry". The pipeline is deliberately boring,
 * which is what makes it auditable:
 *
 *   event window (≥ slowest legitimate cadence + 1 drill)
 *     → normalize (already done: events carry the SAME sbob.* fields the
 *        drift decoders emit — sbob.exe, sbob.path, sbob.dst_ip, …)
 *     → cluster per workload × section
 *     → frequency classification: steady · periodic · sporadic · one-off
 *     → disposition (mandatory, no "no decision" state):
 *        declare · hold · exempt-with-expiry · investigate
 *     → candidate SBoB + provenance sidecar → human review → signature
 *
 * Honesty rules the profiler enforces by construction (chapter §1–§8):
 *   - Kernel/runtime telemetry (auditd, sysmon, ebpf) is the only confirming
 *     source; entries never seen by a confirming source are marked unverified
 *     and excluded from the candidate.
 *   - No unexplained entry enters the contract as a plain allow: overriding a
 *     proposed hold/investigate disposition to declare requires a written
 *     reason, or the run fails loudly.
 *   - Every candidate entry carries provenance: source, counts, first/last
 *     seen, frequency class.
 *   - A periodic entry is declared only after one full period was observed
 *     inside the window; otherwise it is held.
 *   - A workload with an open incident label is quarantined: no candidate is
 *     emitted, the report says why, and the exit code is non-zero.
 *   - An SBoB derived from an N-day window is exactly what that workload did
 *     for N days, no more — the drift loop (M1–M7) catches the rest.
 *
 * Output is deterministic: identical inputs produce byte-identical candidate
 * YAML, provenance JSON and review markdown (org decision #26).
 */
import { SbobError } from "./errors.ts";
import { parseYaml } from "./yaml.ts";
import { validateSbob, type NetEntryLike, type SbobDocumentLike } from "./schema.ts";
import { OPEN_FLAGS, SBOB_API_VERSION, SBOB_KIND, type OpenFlag } from "./types.ts";
import { diffSbobs, formatDiffReport, type DiffResult } from "./diffgate.ts";

// ---------------------------------------------------------------------------
// defaults (calibratable; chapter §7: "thresholds are defaults, not constants")
// ---------------------------------------------------------------------------

export const DEFAULT_WINDOW_DAYS = 30;
/** steady: seen on at least this fraction of the window's days. */
export const STEADY_CUTOFF_DEFAULT = 0.5;
/** sporadic cutoff: recurs on fewer than this fraction of the window's days. */
export const SPORADIC_CUTOFF_DEFAULT = 0.05;
/** periodic: day gaps are "regular" within ±this fraction of the median gap. */
export const CADENCE_TOLERANCE_DEFAULT = 0.25;

/** Sources on the verification floor (chapter §1 fidelity ladder). */
export const CONFIRMING_SOURCES: ReadonlySet<string> = new Set(["auditd", "sysmon", "ebpf"]);
/** Partial sources: may suggest an entry, never confirm one. */
export const PARTIAL_SOURCES: ReadonlySet<string> = new Set(["dns", "flow", "tracemap"]);
/** Annotation-only sources: collected for the review, never enter the contract. */
export const ANNOTATION_SOURCES: ReadonlySet<string> = new Set(["applog", "metric"]);

export type EventKind = "exec" | "open" | "connect" | "accept" | "cap" | "note";

export const SECTION_OF_KIND: Record<Exclude<EventKind, "note">, string> = {
  exec: "execs",
  open: "opens",
  connect: "egress",
  accept: "ingress",
  cap: "capabilities",
};

export interface ProfileEvent {
  /** ISO 8601 UTC timestamp (…Z; day boundaries are UTC by construction). */
  ts: string;
  workload: string;
  source: string;
  kind: EventKind;
  /** Normalized sbob.* fields; required keys depend on kind. */
  sbob: Record<string, unknown>;
}

export type FrequencyClass = "steady" | "periodic" | "sporadic" | "one-off";
export type Disposition = "declare" | "hold" | "exempt-with-expiry" | "investigate";

export interface DispositionOverride {
  disposition: Disposition;
  /** Written reason; required for every reviewer override (no plain allows). */
  reason?: string;
  /** ISO date; required for exempt-with-expiry. */
  expiry?: string;
}

export interface DispositionFile {
  entries: Record<string, DispositionOverride>;
}

export interface ProfileOptions {
  workload: string;
  imageID: string;
  k8sNamespace: string;
  windowDays: number;
  /** Workloads with an open incident label — quarantined from review. */
  incidents: string[];
  /** Reviewer dispositions (the human half of the pipeline). */
  dispositions?: DispositionFile;
  /** Prior-release SBoB: run the M8 diff gate baseline → candidate. */
  baseline?: SbobDocumentLike;
  steadyCutoff?: number;
  sporadicCutoff?: number;
  cadenceTolerance?: number;
}

export interface EntryProvenance {
  section: string;
  /** Cluster key: path / ip:x / dns:x / capability token. */
  key: string;
  /** Telemetry sources that observed the entry. */
  sources: string[];
  /** True when at least one source is on the verification floor. */
  confirmed: boolean;
  count: number;
  firstSeen: string;
  lastSeen: string;
  daysSeen: number;
  /** daysSeen / windowDays. */
  dayRatio: number;
  class: FrequencyClass;
  /** Median day gap for periodic entries; the entry carries its period. */
  periodDays?: number;
  disposition: Disposition;
  dispositionOrigin: "taxonomy-default" | "reviewer";
  reason?: string;
  expiry?: string;
  /** Whether the entry is emitted into the candidate SBoB. */
  included: boolean;
  /** Section-specific evidence (flags union, ports, args variance). */
  detail?: string;
}

export interface ProfileResult {
  status: "candidate" | "quarantined" | "nothing-declarable";
  workload: { name: string; namespace: string; imageID: string };
  window: { days: number; from: string; to: string };
  /** All clustered entries, included or not, sorted by (section, key). */
  entries: EntryProvenance[];
  /** Non-confirming observations collected for the review report. */
  annotations: Array<{ source: string; kind: EventKind; ts: string; text: string }>;
  quarantined: boolean;
  /** Candidate SBoB YAML; absent when quarantined or nothing is declarable. */
  candidateYaml?: string;
  candidate?: SbobDocumentLike;
  /** Deterministic provenance sidecar (JSON text). */
  provenanceJson: string;
  /** Review markdown: odd behaviors first, candidate summary after. */
  reviewReport: string;
  /** M8 gate result when a baseline was supplied. */
  gate?: DiffResult;
}

// ---------------------------------------------------------------------------
// event stream ingestion
// ---------------------------------------------------------------------------

const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function ev(line: number, msg: string): never {
  throw new SbobError("ERR_PROFILE_EVENT", `event line ${line}: ${msg}`);
}

function reqStr(m: Record<string, unknown>, field: string, line: number): string {
  const v = m[field];
  if (typeof v !== "string" || v === "") ev(line, `sbob.${field} must be a non-empty string`);
  return v;
}

function optStrArray(m: Record<string, unknown>, field: string, line: number): string[] | undefined {
  const v = m[field];
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    ev(line, `sbob.${field} must be an array of strings`);
  }
  return v as string[];
}

function optPort(m: Record<string, unknown>, field: string, line: number): number | null {
  const v = m[field];
  if (v === undefined || v === null) return null;
  const n = typeof v === "number" ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : NaN;
  if (!Number.isInteger(n) || n < 1 || n > 65535) ev(line, `sbob.${field} must be a port 1-65535`);
  return n;
}

/**
 * Parse a normalized `sbob.*` event stream (JSONL, one event per line).
 * Raw logs are rejected by construction: each line must already carry the
 * normalized field contract the drift decoders emit.
 */
export function parseEventStream(text: string): ProfileEvent[] {
  const events: ProfileEvent[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (raw === "" || raw.startsWith("#")) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      ev(i + 1, "not valid JSON (the recorder emits one normalized event object per line)");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      ev(i + 1, "event must be a JSON object");
    }
    const m = parsed as Record<string, unknown>;
    const ts = m["ts"];
    if (typeof ts !== "string" || !TS_RE.test(ts)) {
      ev(i + 1, `ts must be an ISO 8601 UTC timestamp (got ${JSON.stringify(ts)})`);
    }
    const workload = m["workload"];
    if (typeof workload !== "string" || workload === "") ev(i + 1, "workload must be a non-empty string");
    const source = m["source"];
    if (typeof source !== "string" || source === "") ev(i + 1, "source must be a non-empty string");
    const kind = m["kind"];
    if (typeof kind !== "string" || !["exec", "open", "connect", "accept", "cap", "note"].includes(kind)) {
      ev(i + 1, `kind must be one of exec|open|connect|accept|cap|note (got ${JSON.stringify(kind)})`);
    }
    const sbobV = m["sbob"];
    if (typeof sbobV !== "object" || sbobV === null || Array.isArray(sbobV)) {
      ev(i + 1, "sbob must be a mapping of normalized sbob.* fields");
    }
    const sbob = sbobV as Record<string, unknown>;

    switch (kind as EventKind) {
      case "exec":
        reqStr(sbob, "exe", i + 1);
        optStrArray(sbob, "args", i + 1);
        break;
      case "open": {
        reqStr(sbob, "path", i + 1);
        const flags = optStrArray(sbob, "flags", i + 1) ?? [];
        for (const f of flags) {
          if (!(OPEN_FLAGS as readonly string[]).includes(f)) {
            ev(i + 1, `sbob.flags contains unknown open flag "${f}"`);
          }
        }
        break;
      }
      case "connect": {
        const hasIp = typeof sbob["dst_ip"] === "string" && sbob["dst_ip"] !== "";
        const hasDns = typeof sbob["dns"] === "string" && sbob["dns"] !== "";
        if (!hasIp && !hasDns) ev(i + 1, "connect needs sbob.dst_ip or sbob.dns");
        optPort(sbob, "dst_port", i + 1);
        break;
      }
      case "accept": {
        reqStr(sbob, "src_ip", i + 1);
        optPort(sbob, "local_port", i + 1);
        break;
      }
      case "cap":
        if (!/^CAP_[A-Z_]+$/.test(reqStr(sbob, "cap", i + 1))) {
          ev(i + 1, "sbob.cap must be an upper-case capabilities(7) token");
        }
        break;
      case "note":
        reqStr(sbob, "text", i + 1);
        if (!ANNOTATION_SOURCES.has(source)) {
          ev(i + 1, `note events are annotation-only (source must be one of ${[...ANNOTATION_SOURCES].join("|")}, got "${source}")`);
        }
        break;
    }
    events.push({ ts, workload: workload as string, source: source as string, kind: kind as EventKind, sbob });
  }
  return events;
}

// ---------------------------------------------------------------------------
// clustering
// ---------------------------------------------------------------------------

interface Cluster {
  section: string;
  key: string;
  sources: Set<string>;
  count: number;
  days: Set<string>;
  firstSeen: string;
  lastSeen: string;
  /** section-specific evidence */
  argsVariants: Set<string>;        // execs: canonical arg vectors seen
  argsStable: string[] | null;      // execs: the single stable arg vector, if any
  flagUnion: string[];              // opens: union of observed flags (spec order)
  sawFlaglessOpen: boolean;        // opens: events without normalized flags
  ports: Set<number>;              // egress/ingress: distinct ports
  sawAnyPort: boolean;            // egress/ingress: at least one portless event
}

function newCluster(section: string, key: string, ts: string): Cluster {
  return {
    section, key, sources: new Set(), count: 0, days: new Set([ts.slice(0, 10)]),
    firstSeen: ts, lastSeen: ts,
    argsVariants: new Set(), argsStable: null,
    flagUnion: [], sawFlaglessOpen: false, ports: new Set(), sawAnyPort: false,
  };
}

function pushEvent(c: Cluster, e: ProfileEvent): void {
  c.sources.add(e.source);
  c.count++;
  const day = e.ts.slice(0, 10);
  c.days.add(day);
  if (e.ts < c.firstSeen) c.firstSeen = e.ts;
  if (e.ts > c.lastSeen) c.lastSeen = e.ts;
}

function clusterKeyOf(e: ProfileEvent): { section: string; key: string } | null {
  const sbob = e.sbob;
  switch (e.kind) {
    case "exec":
      return { section: "execs", key: sbob["exe"] as string };
    case "open":
      return { section: "opens", key: sbob["path"] as string };
    case "connect": {
      const ip = sbob["dst_ip"];
      return typeof ip === "string" && ip !== ""
        ? { section: "egress", key: "ip:" + ip }
        : { section: "egress", key: "dns:" + (sbob["dns"] as string) };
    }
    case "accept":
      return { section: "ingress", key: "ip:" + (sbob["src_ip"] as string) };
    case "cap":
      return { section: "capabilities", key: sbob["cap"] as string };
    case "note":
      return null; // annotations are collected separately
  }
}

// ---------------------------------------------------------------------------
// frequency classification
// ---------------------------------------------------------------------------

function dayIndex(day: string): number {
  return Math.floor(Date.parse(day + "T00:00:00Z") / 86_400_000);
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * Frequency classification (chapter §3). Deterministic ladder:
 *   1. count === 1                      → one-off
 *   2. dayRatio < sporadicCutoff (0.05)  → sporadic (below the sporadic cutoff)
 *   3. regular day cadence (≥ 3 days on
 *      ≥ 2 regular gaps)                → periodic (carries its period)
 *   4. dayRatio ≥ steadyCutoff (0.5)     → steady
 *   5. otherwise                        → sporadic (recurs, no cadence)
 */
export function classifyFrequency(
  count: number,
  days: Iterable<string>,
  windowDays: number,
  opts: { steadyCutoff: number; sporadicCutoff: number; cadenceTolerance: number },
): { class: FrequencyClass; dayRatio: number; daysSeen: number; periodDays?: number } {
  const dayList = [...days];
  const daysSeen = dayList.length;
  const dayRatio = daysSeen / windowDays;
  if (count === 1) return { class: "one-off", dayRatio, daysSeen };
  if (dayRatio < opts.sporadicCutoff) {
    return { class: "sporadic", dayRatio, daysSeen };
  }
  if (daysSeen >= 3) {
    const idx = [...new Set(dayList)].sort().map(dayIndex);
    const gaps: number[] = [];
    for (let i = 1; i < idx.length; i++) gaps.push(idx[i] - idx[i - 1]);
    const med = median(gaps);
    // a 1-day median gap means "every day" — that is steady, not periodic;
    // periodic is reserved for a cadence longer than daily
    if (med >= 2 && gaps.every((g) => g >= med * (1 - opts.cadenceTolerance) && g <= med * (1 + opts.cadenceTolerance))) {
      return { class: "periodic", dayRatio, daysSeen, periodDays: med };
    }
  }
  if (dayRatio >= opts.steadyCutoff) return { class: "steady", dayRatio, daysSeen };
  return { class: "sporadic", dayRatio, daysSeen };
}

/** Taxonomy-default disposition (chapter §3 table). */
export function defaultDisposition(c: FrequencyClass): Disposition {
  switch (c) {
    case "steady":
      return "declare";
    case "periodic":
      return "declare"; // after one full period — enforced separately (window honesty)
    case "sporadic":
      return "hold"; // hold the window one more cycle; exempt-with-expiry if drift fires meanwhile
    case "one-off":
      return "investigate"; // exclude-and-document, or declare with a written reason
  }
}

// ---------------------------------------------------------------------------
// dispositions
// ---------------------------------------------------------------------------

const EXPIRY_RE = /^\d{4}-\d{2}-\d{2}$/;

function applyDispositions(
  entries: EntryProvenance[],
  overrides: DispositionFile | undefined,
  windowTo: string,
): void {
  if (overrides === undefined) return;
  const byKey = new Map(entries.map((e) => [e.section + ":" + e.key, e]));
  for (const [key, ov] of Object.entries(overrides.entries)) {
    const entry = byKey.get(key);
    if (entry === undefined) {
      throw new SbobError("ERR_PROFILE_DISPOSITION", `dispositions file references unknown entry "${key}" (not observed in this window — check the spelling)`);
    }
    if (ov.disposition !== "declare" && ov.disposition !== "hold" && ov.disposition !== "exempt-with-expiry" && ov.disposition !== "investigate") {
      throw new SbobError("ERR_PROFILE_DISPOSITION", `entry "${key}": disposition must be declare|hold|exempt-with-expiry|investigate`);
    }
    const reason = ov.reason?.trim() ?? "";
    if (reason === "") {
      // the chapter's core rule: no unexplained entry enters the contract,
      // and no reviewer decision is unexplained
      throw new SbobError("ERR_PROFILE_DISPOSITION", `entry "${key}": reviewer disposition "${ov.disposition}" requires a written reason`);
    }
    if (ov.disposition === "exempt-with-expiry") {
      if (ov.expiry === undefined || !EXPIRY_RE.test(ov.expiry)) {
        throw new SbobError("ERR_PROFILE_DISPOSITION", `entry "${key}": exempt-with-expiry requires an expiry date (YYYY-MM-DD)`);
      }
      if (ov.expiry + "T23:59:59Z" <= windowTo) {
        throw new SbobError("ERR_PROFILE_DISPOSITION", `entry "${key}": expiry ${ov.expiry} is not in the future relative to the window (window ends ${windowTo})`);
      }
      entry.expiry = ov.expiry;
    }
    entry.disposition = ov.disposition;
    entry.dispositionOrigin = "reviewer";
    entry.reason = reason;
  }
}

// ---------------------------------------------------------------------------
// YAML emission (deterministic; parser-compatible subset)
// ---------------------------------------------------------------------------

function yScalar(s: string): string {
  // quote anything that would not round-trip as a string through the parser:
  // plain scalars that look like numbers, booleans or YAML keywords
  if (
    /^[A-Za-z0-9/][A-Za-z0-9/._@:+~=-]*$/.test(s) &&
    !/^-?\d+(\.\d+)?$/.test(s) &&
    !["null", "true", "false", "~", "yes", "no"].includes(s)
  ) {
    return s;
  }
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t") + '"';
}

function yList(items: string[], indent: number): string[] {
  return items.map((x) => " ".repeat(indent) + "- " + x);
}

// ---------------------------------------------------------------------------
// profiling
// ---------------------------------------------------------------------------

export function profileEvents(events: ProfileEvent[], opts: ProfileOptions): ProfileResult {
  const workload = opts.workload;
  const scoped = events.filter((e) => e.workload === workload);
  if (scoped.length === 0) {
    throw new SbobError("ERR_PROFILE_SCOPE", `no events in the stream for workload "${workload}"`);
  }
  for (const e of scoped) {
    if (e.kind === "note") continue;
    if (!CONFIRMING_SOURCES.has(e.source) && !PARTIAL_SOURCES.has(e.source) && !ANNOTATION_SOURCES.has(e.source)) {
      throw new SbobError("ERR_PROFILE_EVENT", `unknown telemetry source "${e.source}" (confirming: ${[...CONFIRMING_SOURCES].join(", ")}; partial: ${[...PARTIAL_SOURCES].join(", ")}; annotation: ${[...ANNOTATION_SOURCES].join(", ")})`);
    }
  }

  const quarantined = opts.incidents.includes(workload);

  // cluster -------------------------------------------------------------------
  const clusters = new Map<string, Cluster>();
  const annotations: ProfileResult["annotations"] = [];
  for (const e of scoped) {
    if (e.kind === "note") {
      annotations.push({ source: e.source, kind: e.kind, ts: e.ts, text: e.sbob["text"] as string });
      continue;
    }
    const ck = clusterKeyOf(e);
    if (ck === null) continue;
    const id = ck.section + ":" + ck.key;
    let c = clusters.get(id);
    if (c === undefined) {
      c = newCluster(ck.section, ck.key, e.ts);
      clusters.set(id, c);
    }
    pushEvent(c, e);
    // section-specific evidence
    if (e.kind === "exec") {
      const args = e.sbob["args"] as string[] | undefined;
      c.argsVariants.add(JSON.stringify(args ?? null));
    } else if (e.kind === "open") {
      const flags = (e.sbob["flags"] as string[] | undefined) ?? null;
      if (flags === null) {
        c.sawFlaglessOpen = true;
      } else {
        for (const f of OPEN_FLAGS) {
          if (flags.includes(f) && !c.flagUnion.includes(f)) c.flagUnion.push(f);
        }
      }
    } else if (e.kind === "connect") {
      const p = e.sbob["dst_port"] as number | null | undefined;
      if (p === null || p === undefined) c.sawAnyPort = true;
      else c.ports.add(p);
    } else if (e.kind === "accept") {
      const p = e.sbob["local_port"] as number | null | undefined;
      if (p === null || p === undefined) c.sawAnyPort = true;
      else c.ports.add(p);
    }
  }

  // classify + provenance -------------------------------------------------------
  const thresholds = {
    steadyCutoff: opts.steadyCutoff ?? STEADY_CUTOFF_DEFAULT,
    sporadicCutoff: opts.sporadicCutoff ?? SPORADIC_CUTOFF_DEFAULT,
    cadenceTolerance: opts.cadenceTolerance ?? CADENCE_TOLERANCE_DEFAULT,
  };
  const windowDays = opts.windowDays;
  const windowFrom = scoped.reduce((m, e) => (e.ts < m ? e.ts : m), scoped[0].ts);
  const windowTo = scoped.reduce((m, e) => (e.ts > m ? e.ts : m), scoped[0].ts);

  const entries: EntryProvenance[] = [];
  for (const c of clusters.values()) {
    const freq = classifyFrequency(c.count, c.days, windowDays, thresholds);
    const confirmed = [...c.sources].some((s) => CONFIRMING_SOURCES.has(s));
    const ep: EntryProvenance = {
      section: c.section,
      key: c.key,
      sources: [...c.sources].sort(),
      confirmed,
      count: c.count,
      firstSeen: c.firstSeen,
      lastSeen: c.lastSeen,
      daysSeen: freq.daysSeen,
      dayRatio: freq.dayRatio,
      class: freq.class,
      periodDays: freq.periodDays,
      disposition: defaultDisposition(freq.class),
      dispositionOrigin: "taxonomy-default",
      included: false,
    };
    // section-specific provenance detail
    if (c.section === "execs") {
      if (c.argsVariants.size === 1) {
        const v = JSON.parse([...c.argsVariants][0]) as string[] | null;
        if (v !== null) {
          ep.detail = "args stable: [" + v.join(", ") + "]";
          c.argsStable = v;
        }
      } else if (c.argsVariants.size > 1) {
        ep.detail = `args vary across observations (${c.argsVariants.size} variants); entry emitted path-only`;
      }
    } else if (c.section === "opens") {
      const flags = c.flagUnion.length > 0 ? c.flagUnion : ["O_RDONLY"];
      ep.detail = "flags union: " + flags.join("|") + (c.sawFlaglessOpen ? " (some events carried no normalized flags)" : "");
    } else if (c.section === "egress" || c.section === "ingress") {
      const ports = [...c.ports].sort((a, b) => a - b);
      ep.detail = "ports: " + (c.sawAnyPort ? "any" : ports.length > 0 ? ports.join(",") : "any");
    }
    // window honesty: declare a periodic entry only after one full period
    if (ep.class === "periodic" && ep.periodDays !== undefined && windowDays < 2 * ep.periodDays) {
      ep.disposition = "hold";
      ep.reason = "period (" + ep.periodDays + "d) not fully observed inside the " + windowDays + "d window — hold until one full period elapses";
      ep.dispositionOrigin = "taxonomy-default";
    }
    entries.push(ep);
  }
  entries.sort((a, b) => (a.section !== b.section ? (a.section < b.section ? -1 : 1) : a.key < b.key ? -1 : 1));

  // dispositions (reviewer half) -------------------------------------------------
  applyDispositions(entries, opts.dispositions, windowTo);

  // verification floor + inclusion -----------------------------------------------
  for (const ep of entries) {
    if (!ep.confirmed) {
      ep.included = false;
      continue; // unverified: marked and excluded from enforcement (chapter §1)
    }
    ep.included = ep.disposition === "declare" || ep.disposition === "exempt-with-expiry";
  }

  // candidate construction ---------------------------------------------------------
  const included = entries.filter((e) => e.included);
  const status: ProfileResult["status"] = quarantined
    ? "quarantined"
    : included.length === 0
      ? "nothing-declarable"
      : "candidate";

  let candidate: SbobDocumentLike | undefined;
  let candidateYaml: string | undefined;
  if (!quarantined && included.length > 0) {
    candidate = buildCandidate(workload, opts, windowFrom, windowTo, included, clusters);
    candidateYaml = emitCandidateYaml(candidate);
    // self-check: the emitted artifact must survive the repo's own parser and
    // schema — a candidate the toolchain cannot load is a bug, not a draft
    const round = validateSbob(parseYaml(candidateYaml));
    // canonical (key-sorted) compare: the validator rebuilds maps in its own
    // section order, which is structurally identical but not insertion-ordered
    const canon = (v: unknown): string => {
      if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
      if (v !== null && typeof v === "object") {
        return "{" + Object.entries(v as Record<string, unknown>)
          .filter(([, val]) => val !== undefined)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, val]) => JSON.stringify(k) + ":" + canon(val)).join(",") + "}";
      }
      return JSON.stringify(v);
    };
    if (canon(candidate) !== canon(round)) {
      throw new SbobError("ERR_PROFILE_EVENT", "internal error: emitted candidate YAML does not round-trip through the schema validator");
    }
  }

  // M8 gate integration ------------------------------------------------------------
  let gate: DiffResult | undefined;
  if (candidate !== undefined && opts.baseline !== undefined) {
    gate = diffSbobs(opts.baseline, candidate);
  }

  const result: ProfileResult = {
    status,
    workload: { name: workload, namespace: opts.k8sNamespace, imageID: opts.imageID },
    window: { days: windowDays, from: windowFrom, to: windowTo },
    entries,
    annotations: annotations.sort((a, b) => (a.ts !== b.ts ? (a.ts < b.ts ? -1 : 1) : a.text < b.text ? -1 : 1)),
    quarantined,
    candidateYaml,
    candidate,
    provenanceJson: "",
    reviewReport: "",
    gate,
  };
  result.provenanceJson = buildProvenanceJson(result);
  result.reviewReport = formatReviewReport(result);
  return result;
}

function buildCandidate(
  workload: string,
  opts: ProfileOptions,
  windowFrom: string,
  windowTo: string,
  included: EntryProvenance[],
  clusters: Map<string, Cluster>,
): SbobDocumentLike {
  const doc: SbobDocumentLike = {
    apiVersion: SBOB_API_VERSION,
    kind: SBOB_KIND,
    metadata: {
      name: workload,
      namespace: opts.k8sNamespace,
      annotations: {
        "sbob.develapp.io/derived": "sbobctl-profile-v1",
        "sbob.develapp.io/provenance": workload + ".provenance.json",
        "sbob.develapp.io/window-days": String(opts.windowDays),
        "sbob.develapp.io/window-from": windowFrom,
        "sbob.develapp.io/window-to": windowTo,
      },
    },
    spec: { imageID: opts.imageID },
  };

  const bySection = (s: string) => included.filter((e) => e.section === s);

  const execs = bySection("execs");
  if (execs.length > 0) {
    doc.spec.execs = execs.map((e) => {
      const c = clusters.get("execs:" + e.key)!;
      const entry: { path: string; args?: string[] } = { path: e.key };
      if (c.argsStable !== null && c.argsStable.length > 0) entry.args = c.argsStable;
      return entry;
    });
  }

  const opens = bySection("opens");
  if (opens.length > 0) {
    doc.spec.opens = opens.map((e) => {
      const c = clusters.get("opens:" + e.key)!;
      const flags = c.flagUnion.length > 0 ? c.flagUnion : ["O_RDONLY"];
      return { path: e.key, flags: flags as OpenFlag[] };
    });
  }

  for (const [section, specKey] of [["egress", "egress"], ["ingress", "ingress"]] as const) {
    const peers = bySection(section);
    if (peers.length === 0) continue;
    const netEntries: NetEntryLike[] = peers.map((e) => {
      const c = clusters.get(section + ":" + e.key)!;
      const ne: NetEntryLike = { ports: [] };
      if (c.sawAnyPort || c.ports.size === 0) {
        ne.ports = [{ protocol: "TCP", port: null }]; // ANY covers every observed port
      } else {
        ne.ports = [...c.ports].sort((a, b) => a - b).map((p) => ({ protocol: "TCP" as const, port: p }));
      }
      if (e.key.startsWith("ip:")) ne.ipAddresses = [e.key.slice(3)];
      else ne.dnsNames = [e.key.slice(4)];
      return ne;
    });
    doc.spec[specKey] = netEntries;
  }

  const caps = bySection("capabilities");
  if (caps.length > 0) {
    doc.spec.capabilities = caps.map((e) => e.key);
  }

  return doc;
}

function emitCandidateYaml(doc: SbobDocumentLike): string {
  const L: string[] = [];
  L.push("# Candidate SBoB derived by sbobctl profile (M9) — OBSERVATION, NOT INTENT.");
  L.push("# Every derived entry carries provenance in " + doc.metadata.name + ".provenance.json.");
  L.push("# The contract becomes declaration only when a human reviews and signs this draft.");
  L.push("apiVersion: " + yScalar(doc.apiVersion));
  L.push("kind: " + yScalar(doc.kind));
  L.push("metadata:");
  L.push("  name: " + yScalar(doc.metadata.name));
  L.push("  namespace: " + yScalar(doc.metadata.namespace));
  const ann = doc.metadata.annotations ?? {};
  const annKeys = Object.keys(ann).sort();
  if (annKeys.length > 0) {
    L.push("  annotations:");
    for (const k of annKeys) L.push("    " + yScalar(k) + ": " + yScalar(ann[k]));
  }
  L.push("spec:");
  L.push("  imageID: " + yScalar(doc.spec.imageID));
  if (doc.spec.architectures !== undefined && doc.spec.architectures.length > 0) {
    L.push("  architectures:");
    L.push(...yList(doc.spec.architectures.map(yScalar), 4));
  }
  if (doc.spec.execs !== undefined && doc.spec.execs.length > 0) {
    L.push("  execs:");
    for (const e of doc.spec.execs) {
      L.push("  - path: " + yScalar(e.path));
      if (e.args !== undefined) {
        L.push("    args:");
        L.push(...yList(e.args.map(yScalar), 6));
      }
    }
  }
  if (doc.spec.opens !== undefined && doc.spec.opens.length > 0) {
    L.push("  opens:");
    for (const e of doc.spec.opens) {
      L.push("  - path: " + yScalar(e.path));
      L.push("    flags:");
      L.push(...yList(e.flags.map(yScalar), 6));
    }
  }
  for (const section of ["egress", "ingress"] as const) {
    const net = doc.spec[section];
    if (net === undefined || net.length === 0) continue;
    L.push("  " + section + ":");
    for (const e of net) {
      L.push("  - ports:");
      for (const p of e.ports) {
        if (p.protocol !== undefined) L.push("    - protocol: " + yScalar(p.protocol));
        L.push("      port: " + (p.port === null ? "null" : String(p.port)));
      }
      if (e.identifier !== undefined) L.push("    identifier: " + yScalar(e.identifier));
      if (e.ipAddresses !== undefined) {
        L.push("    ipAddresses:");
        L.push(...yList(e.ipAddresses.map(yScalar), 6));
      }
      if (e.dnsNames !== undefined) {
        L.push("    dnsNames:");
        L.push(...yList(e.dnsNames.map(yScalar), 6));
      }
    }
  }
  if (doc.spec.capabilities !== undefined && doc.spec.capabilities.length > 0) {
    L.push("  capabilities:");
    L.push(...yList(doc.spec.capabilities.map(yScalar), 4));
  }
  return L.join("\n") + "\n";
}

function buildProvenanceJson(result: ProfileResult): string {
  const doc = {
    workload: result.workload,
    window: result.window,
    derivedBy: "sbobctl profile v1 (M9)",
    honesty: "An SBoB derived from an N-day window is exactly what that workload did for N days, no more. The drift loop catches the rest.",
    status: result.status,
    quarantined: result.quarantined,
    frequencyThresholds: {
      steadyCutoff: STEADY_CUTOFF_DEFAULT + " (dayRatio at or above -> steady)",
      sporadicCutoff: SPORADIC_CUTOFF_DEFAULT + " (dayRatio below -> sporadic)",
      cadenceTolerance: CADENCE_TOLERANCE_DEFAULT + " (day-gap regularity band for periodic)",
    },
    entries: result.entries.map((e) => {
      const out: Record<string, unknown> = {
        section: e.section,
        key: e.key,
        sources: e.sources,
        confirmed: e.confirmed,
        count: e.count,
        firstSeen: e.firstSeen,
        lastSeen: e.lastSeen,
        daysSeen: e.daysSeen,
        dayRatio: Number(e.dayRatio.toFixed(4)),
        class: e.class,
      };
      if (e.periodDays !== undefined) out.periodDays = e.periodDays;
      out.disposition = e.disposition;
      out.dispositionOrigin = e.dispositionOrigin;
      if (e.reason !== undefined) out.reason = e.reason;
      if (e.expiry !== undefined) out.expiry = e.expiry;
      out.included = e.included;
      if (e.detail !== undefined) out.detail = e.detail;
      return out;
    }),
    annotations: result.annotations,
    gate: result.gate === undefined ? undefined : {
      score: result.gate.score,
      verdict: result.gate.verdict,
      immediateReview: result.gate.immediateReview,
    },
  };
  return JSON.stringify(doc, null, 2) + "\n";
}

export function formatReviewReport(result: ProfileResult): string {
  const L: string[] = [];
  const w = result.workload;
  L.push("# SBoB profiler — " + w.name + " (" + w.namespace + ")");
  L.push("");
  L.push("- window: " + result.window.days + " days (" + result.window.from + " → " + result.window.to + ")");
  L.push("- image: " + w.imageID);
  L.push("- status: **" + result.status.toUpperCase() + "**");
  L.push("");

  if (result.quarantined) {
    L.push("## Quarantined — open incident (taint)");
    L.push("");
    L.push("This workload carries an open incident label. A window over a compromised");
    L.push("workload is a crime-scene photo, not a portrait: no candidate is emitted, and");
    L.push("the observation is out of the review queue until the incident is remediated.");
    L.push("When the investigation closes, exclude the behavior it found by name, then");
    L.push("start a clean window.");
    L.push("");
  }

  // odd behaviors FIRST (chapter §2: "a PR that shows the odd behaviors first")
  const odd = result.entries.filter((e) => e.disposition === "hold" || e.disposition === "investigate" || !e.confirmed);
  if (odd.length > 0) {
    L.push("## Odd behaviors — dispositions required before signature");
    L.push("");
    L.push("| section | entry | class | count | days | first → last | confirmed | disposition | note |");
    L.push("|---|---|---|---|---|---|---|---|---|");
    for (const e of odd) {
      const note = [e.reason ?? "", e.confirmed ? "" : "unverified — no confirming source (excluded)", e.expiry !== undefined ? "expires " + e.expiry : ""]
        .filter(Boolean).join("; ");
      L.push("| " + e.section + " | " + e.key + " | " + e.class + " | " + e.count + " | " + e.daysSeen + " | " + e.firstSeen + " → " + e.lastSeen + " | " + (e.confirmed ? "yes" : "NO") + " | " + e.disposition + " | " + note + " |");
    }
    L.push("");
  }

  const included = result.entries.filter((e) => e.included);
  if (included.length > 0) {
    L.push("## Candidate entries (included in the draft contract)");
    L.push("");
    L.push("| section | entry | class | count | days | sources | disposition | detail |");
    L.push("|---|---|---|---|---|---|---|---|");
    for (const e of included) {
      L.push("| " + e.section + " | " + e.key + " | " + e.class + " | " + e.count + " | " + e.daysSeen + " | " + e.sources.join(", ") + " | " + e.disposition + (e.expiry !== undefined ? " (expires " + e.expiry + ")" : "") + " | " + (e.detail ?? "") + " |");
    }
    L.push("");
  } else if (!result.quarantined) {
    L.push("## Nothing declarable");
    L.push("");
    L.push("No entry survived the fidelity ladder and disposition taxonomy. No candidate");
    L.push("is emitted; the odd-behavior table above is the review queue.");
    L.push("");
  }

  if (result.annotations.length > 0) {
    L.push("## Annotations (non-confirming sources — for the review, never the contract)");
    L.push("");
    for (const a of result.annotations) L.push("- " + a.ts + " (" + a.source + "): " + a.text);
    L.push("");
  }

  L.push("## Window honesty");
  L.push("");
  L.push("An SBoB derived from a " + result.window.days + "-day window is exactly what this");
  L.push("workload did for " + result.window.days + " days, no more. The contract will be wrong;");
  L.push("the drift loop catches the ways it is wrong — that is the designed fallback.");
  L.push("");

  if (result.gate !== undefined) {
    L.push("## Release-gate delta (M8, baseline → candidate)");
    L.push("");
    L.push(formatDiffReport(result.gate).trim());
    L.push("");
  }

  return L.join("\n") + "\n";
}

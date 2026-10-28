/**
 * Type model for SBoB v0.0.4 (source) and the sbobctl IR v1.
 * Mirrors docs/TDS.md sections 2.1 (source model), 5.1 (IR schema).
 */
import type { YamlValue } from "./yaml.ts";

// ---------------------------------------------------------------------------
// SBoB source document (spec v0.0.4)
// ---------------------------------------------------------------------------

export const SBOB_API_VERSION = "sbob.k8sstormcenter.io/v1";
export const SBOB_KIND = "SoftwareBillOfBehavior";
export const SBOB_SPEC_VERSION = "0.0.4";

export type OpenFlag =
  | "O_RDONLY" | "O_WRONLY" | "O_RDWR" | "O_CREAT" | "O_TRUNC"
  | "O_APPEND" | "O_CLOEXEC" | "O_NONBLOCK" | "O_DIRECTORY" | "O_NOFOLLOW" | "O_PATH";

export const OPEN_FLAGS: readonly OpenFlag[] = [
  "O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC",
  "O_APPEND", "O_CLOEXEC", "O_NONBLOCK", "O_DIRECTORY", "O_NOFOLLOW", "O_PATH",
];

export interface ExecsEntry {
  path: string;
  args?: string[];
}

export interface OpensEntry {
  path: string;
  flags: OpenFlag[];
}

export type NetProtocol = "TCP" | "UDP" | "SCTP";

export interface PortEntry {
  name?: string;
  protocol?: NetProtocol;
  port: number | null;
}

export interface LabelSelector {
  matchLabels?: Record<string, string>;
}

export interface NetEntry {
  identifier?: string;
  type?: "external" | "internal";
  ipAddresses?: string[];
  dnsNames?: string[];
  podSelector?: LabelSelector;
  namespaceSelector?: LabelSelector;
  ports: PortEntry[];
}

export interface EndpointEntry {
  endpoint: string;
  methods?: string[];
  headers?: Record<string, string> | null;
  direction: "inbound" | "outbound";
}

export interface RulePolicy {
  processAllowed?: string[];
  containerAllowed?: boolean;
}

export interface SbobDocument {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    namespace: string;
    annotations?: Record<string, string>;
  };
  spec: {
    architectures?: string[];
    imageID: string;
    capabilities?: string[];
    endpoints?: EndpointEntry[];
    execs?: ExecsEntry[];
    opens?: OpensEntry[];
    ingress?: NetEntry[];
    egress?: NetEntry[];
    rulePolicies?: Record<string, RulePolicy>;
  };
}

// ---------------------------------------------------------------------------
// Wildcard ASTs (spec section 5)
// ---------------------------------------------------------------------------

/** U+22EF MIDLINE HORIZONTAL ELLIPSIS — exactly one path segment / argument label. */
export const ONE_SEGMENT = "\u22EF";
/** Zero-or-more consecutive exec arguments. */
export const ARGS_TAIL = "\u22EF\u22EF";

export type PathSeg =
  | { kind: "literal"; text: string }
  | { kind: "one" }        // ⋯ — exactly one segment
  | { kind: "starMid" }   // * mid-path — zero or more segments
  | { kind: "starTail" }; // trailing * — one or more remaining segments

// ---------------------------------------------------------------------------
// IR v1 (TDS 5.1)
// ---------------------------------------------------------------------------

export interface CompiledSection<T> {
  /** Entries in original order, with compiled artifacts attached. */
  entries: T[];
  /** Entries whose pattern contains no wildcard tokens (CDB-compatible exact keys). */
  exact: string[];
  /** Compiled full-match PCRE2 fragments for entries that contain wildcards. */
  patterns: string[];
}

export interface ExecCompiled {
  pathSegs: PathSeg[];
  pathRegex: string;
  argsRegex: string | null;
  isExact: boolean;
  source: ExecsEntry;
}

export interface OpenCompiled {
  pathSegs: PathSeg[];
  pathRegex: string;
  flagMask: number;
  isExact: boolean;
  source: OpensEntry;
}

export interface NetCompiled {
  /** Canonical CDB address entries (ip/mask), or empty. */
  addrEntries: string[];
  anyIp: boolean;
  dnsPatterns: string[];
  dnsExact: string[];
  /** null port = ANY. Empty array = any port on that peer. */
  ports: Array<number | null>;
  k8sPeer: boolean; // podSelector/namespaceSelector present (Phase 3 NetworkPolicy diff)
  source: NetEntry;
}

export interface WorkloadScope {
  linuxGroups: string[];
  windowsGroups: string[];
  k8s: { namespace: string; imageID: string } | null;
}

export interface IR {
  irVersion: 1;
  workload: {
    name: string;
    namespace: string;
    imageID: string;
    sbobVersion: string;
    scope: WorkloadScope;
  };
  sections: {
    execs?: CompiledSection<ExecCompiled>;
    opens?: CompiledSection<OpenCompiled>;
    egress?: CompiledSection<NetCompiled>;
    ingress?: CompiledSection<NetCompiled>;
    capabilities?: string[];
    endpoints?: EndpointEntry[];
  };
  rulePolicies: Record<string, RulePolicy>;
  coverageNotes: string[];
}

/** Convenient coercion of an unknown YamlValue to Record<string, YamlValue>. */
export function asMap(v: YamlValue): Record<string, YamlValue> {
  if (v === null || v === undefined) return {};
  if (typeof v !== "object" || Array.isArray(v)) {
    throw new Error("expected mapping, got " + describeYaml(v));
  }
  return v as Record<string, YamlValue>;
}

export function asArray(v: YamlValue): YamlValue[] {
  if (v === null || v === undefined) return [];
  if (!Array.isArray(v)) throw new Error("expected sequence, got " + describeYaml(v));
  return v;
}

export function asString(v: YamlValue): string {
  if (typeof v !== "string") throw new Error("expected string, got " + describeYaml(v));
  return v;
}

export function describeYaml(v: YamlValue): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "sequence";
  return typeof v;
}

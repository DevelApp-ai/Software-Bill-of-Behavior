/**
 * SBoB wildcard semantics (spec section 5) → PCRE2 compilation (TDS 5.2).
 *
 * The compiled fragments use only constructs with identical semantics in
 * PCRE2 and JavaScript RegExp (escaped literals, char classes, non-capturing
 * groups, alternation, lookahead), so tests can verify semantics directly.
 * PCRE2's \Q...\E quoting is deliberately NOT used.
 */
import { SbobError } from "./errors.ts";
import { ARGS_TAIL, ONE_SEGMENT, type PathSeg } from "./types.ts";

export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ---------------------------------------------------------------------------
// Path patterns (spec 5.1)
// ---------------------------------------------------------------------------

export function parsePathPattern(pattern: string, context: string): PathSeg[] {
  if (!pattern.startsWith("/")) {
    throw new SbobError("ERR_SCHEMA_INVALID", `${context}: path pattern must be absolute (start with /): "${pattern}"`);
  }
  if (pattern.includes("//")) {
    throw new SbobError("ERR_SCHEMA_INVALID", `${context}: empty path segment in "${pattern}"`);
  }
  const parts = pattern.split("/").slice(1); // drop leading ""
  if (pattern.endsWith("/")) {
    // trailing slash: keep an explicit empty marker so "/etc/" is not silently
    // identical to "/etc/*"; spec tables show bare dirs are matched by ⋯/* forms
    parts.push("");
  }
  const segs: PathSeg[] = parts.map((text, i) => {
    const isLast = i === parts.length - 1;
    if (text === ONE_SEGMENT) return { kind: "one" } as const;
    if (text === "*") return { kind: isLast ? "starTail" : "starMid" } as const;
    if (text.includes(ONE_SEGMENT)) {
      // spec 4.5: a token containing ⋯ MUST equal a whole segment;
      // a prefix that stops mid-segment matches nothing and is rejected
      throw new SbobError(
        "ERR_SCHEMA_INVALID",
        `${context}: segment "${text}" contains ${ONE_SEGMENT} but is not exactly one ${ONE_SEGMENT} token (mid-segment use is rejected by bobctl validate)`,
      );
    }
    if (text === "") {
      throw new SbobError("ERR_SCHEMA_INVALID", `${context}: trailing slash without wildcard is ambiguous; use "${pattern}${ONE_SEGMENT}" or "${pattern}*"`);
    }
    return { kind: "literal", text } as const;
  });
  return segs;
}

/** Compile parsed segments to an unanchored full-match PCRE2 fragment. */
export function compilePathSegs(segs: PathSeg[]): string {
  // patterns are absolute (parsePathPattern enforces the leading "/")
  let re = "/";
  const n = segs.length;
  for (let i = 0; i < n; i++) {
    const seg = segs[i];
    const isLast = i === n - 1;
    switch (seg.kind) {
      case "literal":
        re += escapeRegExp(seg.text);
        break;
      case "one":
        re += "[^/]+";
        break;
      case "starMid":
        // zero or more whole segments, each consumed with its trailing slash
        re += "(?:[^/]+/)*";
        break;
      case "starTail":
        // one or more remaining segments — never zero
        re += "[^/]+(?:/[^/]+)*";
        break;
    }
    if (!isLast && seg.kind !== "starMid") re += "/";
    // starMid already accounts for the slash between it and the next segment
  }
  return re;
}

// ---------------------------------------------------------------------------
// Exec argument vectors (spec 4.5 / 5.3)
// ---------------------------------------------------------------------------

export function compileArgsPattern(args: string[], context: string): string {
  // A token containing ⋯ MUST equal a whole argument (spec 5.3 rejections).
  for (const a of args) {
    if (a !== ARGS_TAIL && a !== ONE_SEGMENT && a.includes(ONE_SEGMENT)) {
      throw new SbobError(
        "ERR_SCHEMA_INVALID",
        `${context}: argument "${a}" contains ${ONE_SEGMENT} but is not exactly one wildcard token (mid-token use is rejected)`,
      );
    }
  }
  let re = "";
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let piece: string;
    if (a === ARGS_TAIL) piece = "(?: \\S+)*";       // zero or more trailing arguments
    else if (a === ONE_SEGMENT) piece = " \\S+";      // exactly one argument
    else piece = " " + escapeRegExp(a);               // '*' is a literal in args
    re += piece;
  }
  // first token is anchored at string start; no leading space for it
  return re.replace(/^ /, "");
}

// ---------------------------------------------------------------------------
// DNS patterns (spec 4.7 / 5.8)
// ---------------------------------------------------------------------------

export function compileDnsPattern(pattern: string, context: string): string {
  const p = pattern.toLowerCase();
  if (p === "*" || p === "*.") {
    throw new SbobError("ERR_SCHEMA_INVALID", `${context}: bare "*" DNS pattern is not a valid wildcard form (use "*.suffix.")`);
  }
  if (p.startsWith("*.")) {
    // RFC 4592: exactly one label
    const rest = p.slice(2);
    if (rest.includes("*") || rest.includes(ONE_SEGMENT)) {
      throw new SbobError("ERR_SCHEMA_INVALID", `${context}: multiple wildcard tokens in DNS pattern "${pattern}"`);
    }
    return `[^.]+\\.${escapeRegExp(rest)}`;
  }
  if (p.endsWith(".*")) {
    // one or more trailing labels
    const prefix = p.slice(0, -2);
    if (prefix.includes("*") || prefix.includes(ONE_SEGMENT)) {
      throw new SbobError("ERR_SCHEMA_INVALID", `${context}: multiple wildcard tokens in DNS pattern "${pattern}"`);
    }
    return `${escapeRegExp(prefix)}\\.(?:[^.]+\\.?)+`;
  }
  if (p.includes(ONE_SEGMENT)) {
    // mid DynamicIdentifier: exactly one label between two fixed labels
    const parts = p.split(ONE_SEGMENT);
    if (parts.length !== 2 || parts[0] === "" || parts[1] === "") {
      throw new SbobError("ERR_SCHEMA_INVALID", `${context}: ${ONE_SEGMENT} in DNS patterns must sit between two labels ("a.${ONE_SEGMENT}.b.")`);
    }
    // well-formed split halves keep the boundary dots: "a." and ".b."
    if (!parts[0].endsWith(".") || !parts[1].startsWith(".")) {
      throw new SbobError("ERR_SCHEMA_INVALID", `${context}: malformed wildcard DNS pattern "${pattern}" (expected "a.${ONE_SEGMENT}.b.")`);
    }
    if (parts[0].includes("*") || parts[1].includes("*")) {
      throw new SbobError("ERR_SCHEMA_INVALID", `${context}: multiple wildcard tokens in DNS pattern "${pattern}"`);
    }
    return `${escapeRegExp(parts[0])}[^.]+${escapeRegExp(parts[1])}`;
  }
  if (p.includes("*")) {
    throw new SbobError("ERR_SCHEMA_INVALID", `${context}: "*" in DNS patterns is only valid as a leading "*.suffix" or trailing "prefix.*" form: "${pattern}"`);
  }
  return escapeRegExp(p); // byte-equality
}

// ---------------------------------------------------------------------------
// IP addresses (spec 5.7) — canonicalized for CDB address lists
// ---------------------------------------------------------------------------

export interface IpEntry {
  /** Canonical "a.b.c.d/mask" or "x:x::y/mask" form for a CDB address list. */
  cdb: string;
  any: boolean; // "*" sentinel
}

export function parseIpEntry(raw: string, context: string): IpEntry {
  if (raw === "*") return { cdb: "", any: true };
  const [ipPart, maskPart] = raw.includes("/") ? raw.split("/", 2) : [raw, null];
  if (ipPart.includes(":")) {
    const expanded = expandIPv6(ipPart, context);
    const mask = maskPart === null || maskPart === undefined ? 128 : parseMask(maskPart, 128, context);
    return { cdb: `${expanded}/${mask}`, any: false };
  }
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ipPart)) {
    throw new SbobError("ERR_SCHEMA_INVALID", `${context}: invalid IP address "${raw}"`);
  }
  const octets = ipPart.split(".").map((o) => {
    const n = Number(o);
    if (n > 255) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: invalid octet in "${raw}"`);
    return n;
  });
  const mask = maskPart === null || maskPart === undefined ? 32 : parseMask(maskPart, 32, context);
  return { cdb: `${octets.join(".")}/${mask}`, any: false };
}

function parseMask(mask: string, max: number, context: string): number {
  if (!/^\d+$/.test(mask)) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: invalid netmask "${mask}"`);
  const n = Number(mask);
  if (n > max) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: netmask ${mask} exceeds ${max}`);
  return n;
}

/** Expand an IPv6 literal to canonical lowercase full form (spec 5.7). */
export function expandIPv6(ip: string, context: string): string {
  if (!ip.includes(":")) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: "${ip}" is not an IPv6 literal`);
  let head = ip;
  let tail = "";
  if (ip.includes("::")) {
    const chunks = ip.split("::");
    if (chunks.length > 2) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: multiple "::" in "${ip}"`);
    head = chunks[0];
    tail = chunks[1];
  }
  // Empty groups are only legal as the boundary halves of "::" (head === "" /
  // tail === ""). A group that is empty INSIDE a half (e.g. ":::") is invalid
  // and must be rejected rather than silently dropped.
  const headGroups = head === "" ? [] : head.split(":");
  if (headGroups.includes("")) {
    throw new SbobError("ERR_SCHEMA_INVALID", `${context}: empty group in IPv6 head "${head}"`);
  }
  const tailGroups = tail === "" ? [] : tail.split(":");
  if (tailGroups.includes("")) {
    throw new SbobError("ERR_SCHEMA_INVALID", `${context}: empty group in IPv6 tail "${tail}"`);
  }
  let groups: string[];
  if (ip.includes("::")) {
    const missing = 8 - headGroups.length - tailGroups.length;
    if (missing < 1) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: "${ip}" expands beyond 8 groups`);
    groups = [...headGroups, ...Array(missing).fill("0"), ...tailGroups];
  } else {
    groups = headGroups;
    if (groups.length !== 8) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: "${ip}" has ${groups.length} groups, expected 8`);
  }
  const hex = groups.map((g) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) throw new SbobError("ERR_SCHEMA_INVALID", `${context}: invalid IPv6 group "${g}"`);
    return g.toLowerCase();
  });
  return hex.join(":");
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/** Compile a negated port-alternation regex body for the given allowed ports. */
export function portAlternation(ports: Array<number | null>): string | null {
  const specific = ports.filter((p): p is number => typeof p === "number");
  if (specific.length === 0) return null; // ANY port: omit the condition entirely
  return specific.map((p) => String(p)).join("|");
}

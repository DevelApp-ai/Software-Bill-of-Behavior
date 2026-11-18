/**
 * XML emission helpers for Wazuh artifacts.
 */

/**
 * Shipped Wazuh auditd root rule (0365-auditd_rules.xml id 80700, "Audit:
 * Messages grouped.", decoded_as auditd, level 0). Every auditd-decoded event
 * matches it and Wazuh stops evaluating further ROOT rules once an earlier
 * root has matched, so a user rule that is itself a `decoded_as auditd` root
 * loading after the shipped ruleset NEVER fires (verified live on
 * wazuh-manager 4.14.6: a root with identical conditions after 80700 never
 * fires, the same rule as an <if_sid>80700</if_sid> child does). All sbob
 * auditd-keyed rules must chain as its children — the root-preemption defect
 * behind the vacuously green lab-validate run (issue #42). A manager
 * stripped of the shipped ruleset rejects the dangling parent at
 * ruleset-load time (loud, not silent).
 */
export const AUDITD_ROOT_SID = 80700;

/**
 * Lowest rule id the sbob band uses (slot * 100000). Ids below this in an
 * <if_sid> reference are shipped parents (80700 auditd root, 87900 docker
 * lifecycle, 61600 sysmon, ...) that are always present in the loader's
 * tree before any user file is parsed.
 */
export const FIRST_INTERNAL_SID = 100000;

export interface XmlRule {
  id: number;
  level: number;
  ifSid?: number;
  /** Wazuh correlation tag: fires when <if_matched_sid> fired within timeframe. */
  ifMatchedSid?: number;
  ifGroup?: string;
  /** Require the event to be decoded by this decoder (shipped or custom). */
  decodedAs?: string;
  match?: string;
  fields?: Array<{ name: string; regex: string }>;
  list?: { field: string; lookup: string; src: string };
  /** Correlation counter — a <rule> ATTRIBUTE in Wazuh (child elements were silently ignored by the loader; defect 3, issue #42). */
  frequency?: number;
  timeframe?: number;
  description: string;
  /**
   * Each element renders one <group> line, its names joined with commas
   * (Wazuh group semantics: comma-separated within one <group> tag).
   */
  groups: string[][];
  mitre?: string[];
  options?: string[];
  comment?: string;
}

/**
 * Element-text escaping. Wazuh's rule loader does NOT decode XML entities in
 * element text: an emitted `&quot;` inside a <match>/<field> body is treated
 * as the literal 7 characters "amp;..."-style garbage and never matches a
 * double quote in the log — proven live on wazuh-manager 4.14.6 (logtest
 * bisect: the identical opens-drift pattern with &quot; never fired; with a
 * raw `"` it fires — defect 10, issue #42). Quotes must therefore be emitted
 * RAW (a raw `"` in element text is valid XML). `&` and `<` are still escaped
 * because a raw one would break the XML parse; no sbob pattern or
 * description legitimately contains them.
 */
function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
}

/**
 * Attribute-value escaping. Attribute values are double-quoted, so a `"`
 * inside one must be escaped to keep the file well-formed (sbob attribute
 * values are internal identifiers and never contain quotes today, but be
 * correct anyway).
 */
function escAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
}

export function renderRule(rule: XmlRule): string {
  const lines: string[] = [];
  if (rule.comment) lines.push(`  <!-- ${rule.comment} -->`);
  // frequency/timeframe are <rule> attributes in Wazuh (the OSSEC-era child
  // elements are silently dropped by the rule loader — rules with child
  // <frequency> never armed; defect 3, issue #42; see rules-config.c /
  // _read_attributes).
  const attrs =
    rule.frequency !== undefined || rule.timeframe !== undefined
      ? ` frequency="${rule.frequency ?? 0}" timeframe="${rule.timeframe ?? 0}"`
      : "";
  lines.push(`  <rule id="${rule.id}" level="${rule.level}"${attrs}>`);
  if (rule.ifSid !== undefined) lines.push(`    <if_sid>${rule.ifSid}</if_sid>`);
  if (rule.ifMatchedSid !== undefined) lines.push(`    <if_matched_sid>${rule.ifMatchedSid}</if_matched_sid>`);
  if (rule.decodedAs !== undefined) lines.push(`    <decoded_as>${esc(rule.decodedAs)}</decoded_as>`);
  if (rule.ifGroup !== undefined) lines.push(`    <if_group>${esc(rule.ifGroup)}</if_group>`);
  // Every sbobctl match condition uses PCRE2 constructs (negative lookaheads
  // for allow-listing), so the attribute is explicit rather than inherited
  // from the loader default (OS_Match would silently misparse them).
  if (rule.match !== undefined) lines.push(`    <match type="pcre2">${esc(rule.match)}</match>`);
  for (const f of rule.fields ?? []) {
    // Wazuh analysisd compiles <field> conditions with OS_Regex unless the
    // element carries type="pcre2" (wazuh/src/analysisd/rules.c, Rules_OP_ReadRules
    // -> w_check_attr_type; default EXP_TYPE_OSREGEX). Every sbobctl field
    // condition uses PCRE2 constructs (character classes, lookaheads), so the
    // attribute is mandatory: without it the ruleset fails to load.
    lines.push(`    <field name="${escAttr(f.name)}" type="pcre2">${esc(f.regex)}</field>`);
  }
  if (rule.list !== undefined) {
    lines.push(`    <list field="${escAttr(rule.list.field)}" lookup="${escAttr(rule.list.lookup)}">${esc(rule.list.src)}</list>`);
  }
  for (const g of rule.groups) lines.push(`    <group>${esc(g.join(","))}</group>`);
  for (const m of rule.mitre ?? []) lines.push(`    <mitre><id>${m}</id></mitre>`);
  for (const o of rule.options ?? []) lines.push(`    <options>${esc(o)}</options>`);
  lines.push(`    <description>${esc(rule.description)}</description>`);
  lines.push(`  </rule>`);
  return lines.join("\n");
}

/**
 * Order rules so parents precede children in the file (Wazuh's 4.x rule
 * linker resolves <if_sid>/<if_matched_sid> against the tree built SO FAR
 * while parsing the file — a forward reference only produces a WARNING
 * (7617/7620) and the child is dropped or ignored, silently disarming it;
 * defect 7, issue #42, verified live on 4.14.6). Kahn-style pass, stable
 * by id. Two dependency kinds:
 *   - <if_sid>: internal parents (>= FIRST_INTERNAL_SID, i.e. inside this
 *     file) must be emitted first; shipped parents (80700 auditd root,
 *     87900 docker, 61600 sysmon, ...) are already in the loader's tree, so
 *     they are treated as satisfied.
 *   - <if_matched_sid>: 4.14.6 resolves these in parse order too (a
 *     sustained rule emitted before its drift parent is "ignored" by the
 *     linker), so the parent drift rule must precede the correlation rule.
 */
export function orderRulesParentsFirst(rules: XmlRule[]): XmlRule[] {
  const pending = [...rules].sort((a, b) => a.id - b.id);
  const emittedIds = new Set<number>();
  const out: XmlRule[] = [];
  const satisfied = (r: XmlRule) => {
    const sidOk = r.ifSid === undefined || emittedIds.has(r.ifSid) || r.ifSid < FIRST_INTERNAL_SID;
    const matchedOk = r.ifMatchedSid === undefined || emittedIds.has(r.ifMatchedSid);
    return sidOk && matchedOk;
  };
  while (pending.length > 0) {
    const idx = pending.findIndex(satisfied);
    if (idx === -1) {
      // dangling internal if_sid: keep emitting in id order (loader will say so, loud)
      out.push(pending.shift()!);
      continue;
    }
    const [rule] = pending.splice(idx, 1);
    out.push(rule);
    emittedIds.add(rule.id);
  }
  return out;
}

/**
 * Render a complete Wazuh rules file. Wazuh 4.x rejects a file whose top
 * level is bare <rule> elements without the <group name="..."> wrapper
 * ("Invalid rule ... error 1220" — defect 1, issue #42).
 */
export function renderRulesFile(purpose: string, workload: string, extra: string | undefined, rules: XmlRule[]): string {
  return [
    xmlFileHeader(purpose, workload, extra),
    "",
    `<group name="sbob,${workload}">`,
    ...orderRulesParentsFirst(rules).map(renderRule).join("\n\n").split("\n"),
    "</group>",
    "",
  ].join("\n");
}

export interface Decoder {
  name: string;
  parent?: string;
  prematch?: string;
  regex?: string;
  order?: string;
  comment?: string;
}

export function renderDecoder(d: Decoder): string {
  const lines: string[] = [];
  if (d.comment) lines.push(`  <!-- ${d.comment} -->`);
  lines.push(`  <decoder name="${escAttr(d.name)}">`);
  if (d.parent !== undefined) lines.push(`    <parent>${esc(d.parent)}</parent>`);
  if (d.prematch !== undefined) lines.push(`    <prematch>${esc(d.prematch)}</prematch>`);
  if (d.regex !== undefined) lines.push(`    <regex>${esc(d.regex)}</regex>`);
  if (d.order !== undefined) lines.push(`    <order>${esc(d.order)}</order>`);
  lines.push(`  </decoder>`);
  return lines.join("\n");
}

export function xmlFileHeader(purpose: string, workload: string, extra?: string): string {
  const h = [
    "<!--",
    `  ${purpose}`,
    `  workload: ${workload}`,
    "  generated by sbobctl (do not edit by hand; regenerate from the pinned SBoB)",
  ];
  if (extra) h.push(`  ${extra}`);
  h.push("-->");
  return h.join("\n");
}

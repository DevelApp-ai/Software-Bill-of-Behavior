/**
 * XML emission helpers for Wazuh artifacts (wazuh-manager 4.14.x schema).
 *
 * Engine facts baked into these helpers (verified against wazuh 4.14.6
 * src/analysisd/{rules.c,list.c,decoders/} and the shipped ruleset):
 *   - frequency/timeframe are RULE ATTRIBUTES on 4.14 (<frequency>/<timeframe>
 *     child elements fail the loader: unknown-element errors 1202/1220).
 *   - raw double quotes are legal in element TEXT content (the 4.14 loader
 *     does not require &quot; in content); attributes must escape them and
 *     single quotes are NOT predefined in content.
 *   - <field> conditions compile with OS_Regex unless type="pcre2".
 *   - frequency children correlate with <if_matched_sid> + <same_field>; an
 *     EMPTY <same_field/> never correlates (FindField("") finds nothing) and
 *     static fields (e.g. srcip) are invisible to same_field — static srcip
 *     correlation needs <same_srcip/>.
 */

export interface XmlRule {
  id: number;
  level: number;
  ifSid?: number;
  ifGroup?: string;
  /** Correlate on a previously FIRED rule id (frequency children). */
  ifMatchedSid?: number;
  match?: string;
  fields?: Array<{ name: string; regex: string }>;
  list?: { field: string; lookup: string; src: string };
  /** Correlate the repeated event on a dynamic field, or the static srcip. */
  sameField?: { name: string } | { staticSrcip: true };
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

/** Escape for XML element text content (keeps raw quotes — valid on 4.14). */
export function escText(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Escape for XML attribute values (adds the double-quote entity). */
export function escAttr(s: string): string {
  return escText(s).replace(/"/g, "&quot;");
}

export function renderRule(rule: XmlRule): string {
  const lines: string[] = [];
  // frequency/timeframe are rule attributes on wazuh 4.14 (child elements
  // fail the loader — unknown-element errors 1202/1220).
  const attrs = [` id="${escAttr(String(rule.id))}"`, `level="${escAttr(String(rule.level))}"`];
  if (rule.frequency !== undefined) attrs.push(`frequency="${escAttr(String(rule.frequency))}"`);
  if (rule.timeframe !== undefined) attrs.push(`timeframe="${escAttr(String(rule.timeframe))}"`);
  if (rule.comment) lines.push(`  <!-- ${escText(rule.comment)} -->`);
  lines.push(`  <rule ${attrs.join(" ")}>`);
  if (rule.ifSid !== undefined) lines.push(`    <if_sid>${escText(String(rule.ifSid))}</if_sid>`);
  if (rule.ifGroup !== undefined) lines.push(`    <if_group>${escText(rule.ifGroup)}</if_group>`);
  if (rule.ifMatchedSid !== undefined) lines.push(`    <if_matched_sid>${escText(String(rule.ifMatchedSid))}</if_matched_sid>`);
  if (rule.match !== undefined) lines.push(`    <match>${escText(rule.match)}</match>`);
  for (const f of rule.fields ?? []) {
    // Wazuh analysisd compiles <field> conditions with OS_Regex unless the
    // element carries type="pcre2" (wazuh/src/analysisd/rules.c, Rules_OP_ReadRules
    // -> w_check_attr_type; default EXP_TYPE_OSREGEX). Every sbobctl field
    // condition uses PCRE2 constructs (character classes, lookaheads), so the
    // attribute is mandatory: without it the ruleset fails to load.
    lines.push(`    <field name="${escAttr(f.name)}" type="pcre2">${escText(f.regex)}</field>`);
  }
  if (rule.list !== undefined) {
    lines.push(`    <list field="${escAttr(rule.list.field)}" lookup="${escAttr(rule.list.lookup)}">${escText(rule.list.src)}</list>`);
  }
  if (rule.sameField !== undefined) {
    if ("staticSrcip" in rule.sameField && rule.sameField.staticSrcip) {
      // static fields (srcip) are invisible to same_field — same_srcip instead
      lines.push(`    <same_srcip />`);
    } else {
      lines.push(`    <same_field>${escText((rule.sameField as { name: string }).name)}</same_field>`);
    }
  }
  for (const g of rule.groups) lines.push(`    <group>${escText(g.join(","))}</group>`);
  for (const m of rule.mitre ?? []) lines.push(`    <mitre><id>${escText(m)}</id></mitre>`);
  for (const o of rule.options ?? []) lines.push(`    <options>${escText(o)}</options>`);
  lines.push(`    <description>${escText(rule.description)}</description>`);
  lines.push(`  </rule>`);
  return lines.join("\n");
}

/**
 * Render a complete rules file: header comment, blank line, one root
 * <group name="..."> wrapper around all rules. Wazuh requires every rule to
 * live inside a group (rules outside a group fail the loader); the root
 * group also namespaced-loads the workload band.
 */
export function renderRuleFile(header: string, rootGroups: string[], rules: XmlRule[]): string {
  return [
    header,
    "",
    `<group name="${escAttr(rootGroups.join(","))}">`,
    rules.map(renderRule).join("\n\n"),
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
  if (d.comment) lines.push(`  <!-- ${escText(d.comment)} -->`);
  lines.push(`  <decoder name="${escAttr(d.name)}">`);
  if (d.parent !== undefined) lines.push(`    <parent>${escText(d.parent)}</parent>`);
  if (d.prematch !== undefined) lines.push(`    <prematch>${escText(d.prematch)}</prematch>`);
  if (d.regex !== undefined) lines.push(`    <regex>${escText(d.regex)}</regex>`);
  if (d.order !== undefined) lines.push(`    <order>${escText(d.order)}</order>`);
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

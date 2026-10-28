/**
 * Minimal YAML subset parser (zero-dependency).
 *
 * Scope: exactly the YAML used by SBoB profiles and the workload slot registry:
 *   - a single document (leading `---` marker tolerated)
 *   - block mappings and block sequences with indentation-based nesting
 *   - flow sequences `[...]` and flow mappings `{...}` on a single line
 *   - plain scalars, single- and double-quoted scalars (double quotes support \" \\ \n \t)
 *   - comments (`#` at line start or preceded by whitespace, outside quotes)
 *   - null (`null`, `~`, empty), true/false, integers, floats; everything else is a string
 *
 * Explicitly unsupported (loud failure, never silent misparse):
 *   - block scalars (`|`, `>`) and multi-line flow collections
 *   - anchors, aliases, tags, merge keys
 *   - complex mapping keys, tabs for indentation
 */
import { SbobError } from "./errors.ts";

export type YamlValue = null | boolean | number | string | YamlValue[] | { [key: string]: YamlValue };

export class YamlParseError extends SbobError {
  readonly line: number;
  constructor(message: string, line: number) {
    super("ERR_YAML_PARSE", `line ${line}: ${message}`, { line });
    this.name = "YamlParseError";
    this.line = line;
  }
}

interface SrcLine {
  indent: number;
  text: string; // content with comments stripped, trailing spaces trimmed
  num: number; // 1-based source line number
}

const FLOW_OPENERS: Record<string, string> = { "[": "]", "{": "}" };

function stripComment(src: string, num: number): string {
  let inS = false;
  let inD = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) {
      if (inD && src[i - 1] === "\\") continue; // escaped quote, stay in double quotes
      inD = !inD;
    } else if (c === "#" && !inS && !inD && (i === 0 || src[i - 1] === " " || src[i - 1] === "\t")) {
      return src.slice(0, i);
    }
  }
  // unterminated double quote: comment stripping may have been wrong, keep raw
  return src;
}

function preprocess(source: string): SrcLine[] {
  const out: SrcLine[] = [];
  const lines = source.split(/\r?\n/);
  let docStarted = false;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const num = i + 1;
    // tab indentation is a silent-misparse hazard: reject before any trimming
    if (/^\t/.test(raw)) {
      throw new YamlParseError("tab indentation is not supported (use spaces)", num);
    }
    const stripped = stripComment(raw, num).trimEnd();
    if (!stripped.trim()) continue;
    if (stripped.trim() === "---") {
      if (docStarted) break; // single-document tool: stop at the second marker
      docStarted = true;
      continue;
    }
    if (stripped.trim() === "...") break;
    const indentMatch = /^ */.exec(stripped);
    if (indentMatch === null) throw new YamlParseError("unparsable line", num);
    out.push({ indent: indentMatch[0].length, text: stripped.trim(), num });
  }
  return out;
}

function parseScalar(raw: string, num: number): YamlValue {
  const s = raw.trim();
  if (s === "") return null;
  if (s === "null" || s === "~" || s === "Null" || s === "NULL") return null;
  if (s === "true" || s === "True" || s === "TRUE") return true;
  if (s === "false" || s === "False" || s === "FALSE") return false;
  if (s.startsWith("'") && s.endsWith("'") && s.length >= 2) {
    const inner = s.slice(1, -1);
    if (inner.includes("'")) throw new YamlParseError("escaping single quotes inside single-quoted scalars is not supported", num);
    return inner;
  }
  if (s.startsWith('"') && s.endsWith('"') && s.length >= 2) {
    const inner = s.slice(1, -1);
    if (!isBalancedDoubleQuoted(s)) throw new YamlParseError("unterminated or malformed double-quoted scalar", num);
    return inner.replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d+\.\d+$/.test(s)) return Number(s);
  return s;
}

function isBalancedDoubleQuoted(s: string): boolean {
  if (!s.startsWith('"')) return false;
  let inD = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && inD) { i++; continue; }
    if (c === '"') inD = !inD;
  }
  return !inD && s.endsWith('"');
}

/** Split "key: value" outside quotes. Returns [key, hasValue, valueRaw]. */
function splitKeyValue(text: string, num: number): { key: string; valueRaw: string | null } {
  if (text.startsWith("'") || text.startsWith('"')) {
    // quoted key: find the closing quote, then expect ':'
    const quote = text[0];
    let end = -1;
    for (let i = 1; i < text.length; i++) {
      if (quote === '"' && text[i] === "\\") { i++; continue; }
      if (text[i] === quote) { end = i; break; }
    }
    if (end === -1) throw new YamlParseError("unterminated quoted mapping key", num);
    const key = String(parseScalar(text.slice(0, end + 1), num));
    const rest = text.slice(end + 1).trim();
    if (!rest.startsWith(":")) throw new YamlParseError(`expected ':' after quoted key "${key}"`, num);
    return { key, valueRaw: rest.slice(1).trim() || null };
  }
  // plain key: scan for ':' followed by space or end-of-line, outside brackets/quotes
  let depth = 0;
  let inS = false, inD = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inS) { if (c === "'") inS = false; continue; }
    if (inD) { if (c === "\\") i++; else if (c === '"') inD = false; continue; }
    if (c === "'") { inS = true; continue; }
    if (c === '"') { inD = true; continue; }
    if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") depth--;
    else if (c === ":" && depth === 0 && (i === text.length - 1 || text[i + 1] === " ")) {
      const key = text.slice(0, i).trim();
      if (!key) throw new YamlParseError("empty mapping key", num);
      return { key, valueRaw: text.slice(i + 1).trim() || null };
    }
  }
  throw new YamlParseError("mapping line has no ':' key separator", num);
}

/** Parse a single-line flow collection starting at s[pos]. */
function parseFlow(s: string, pos: number, num: number): { value: YamlValue; next: number } {
  const opener = s[pos];
  const closer = FLOW_OPENERS[opener];
  if (!closer) throw new YamlParseError(`unexpected flow character "${opener}"`, num);
  pos++;
  const items: YamlValue[] = [];
  const map: Record<string, YamlValue> = {};
  const isMap = opener === "{";

  const skipWs = () => {
    while (pos < s.length && (s[pos] === " " || s[pos] === "\t")) pos++;
  };

  const readFlowScalar = (stopAtColon = false): string => {
    skipWs();
    if (pos < s.length && (s[pos] === "'" || s[pos] === '"')) {
      const quote = s[pos];
      const start = pos;
      pos++;
      while (pos < s.length) {
        if (quote === '"' && s[pos] === "\\") { pos += 2; continue; }
        if (s[pos] === quote) { pos++; break; }
        pos++;
      }
      return s.slice(start, pos);
    }
    const start = pos;
    while (pos < s.length) {
      const c = s[pos];
      if (c === "," || c === "]" || c === "}") break;
      if (stopAtColon && c === ":" && (pos + 1 >= s.length || s[pos + 1] === " ")) break;
      pos++;
    }
    return s.slice(start, pos).trim();
  };

  skipWs();
  if (pos < s.length && s[pos] === closer) return { value: isMap ? {} : [], next: pos + 1 };

  for (;;) {
    skipWs();
    if (isMap) {
      const keyRaw = readFlowScalar(true);
      skipWs();
      if (s[pos] !== ":") throw new YamlParseError(`expected ':' in flow mapping near "${s.slice(Math.max(0, pos - 20), pos + 20)}"`, num);
      pos++;
      let value: YamlValue;
      skipWs();
      if (s[pos] === "[" || s[pos] === "{") {
        const r = parseFlow(s, pos, num);
        value = r.value;
        pos = r.next;
      } else {
        value = parseScalar(readFlowScalar(false), num);
      }
      const key = String(parseScalar(keyRaw, num));
      if (key in map) throw new YamlParseError(`duplicate key "${key}" in flow mapping`, num);
      map[key] = value;
    } else {
      skipWs();
      if (s[pos] === "[" || s[pos] === "{") {
        const r = parseFlow(s, pos, num);
        items.push(r.value);
        pos = r.next;
      } else {
        items.push(parseScalar(readFlowScalar(false), num));
      }
    }
    skipWs();
    if (pos >= s.length) throw new YamlParseError(`unterminated flow collection (missing "${closer}")`, num);
    if (s[pos] === ",") { pos++; continue; }
    if (s[pos] === closer) { pos++; break; }
    throw new YamlParseError(`expected ',' or '${closer}' in flow collection, got "${s[pos]}"`, num);
  }
  return { value: isMap ? map : items, next: pos };
}

interface ParseResult {
  value: YamlValue;
  next: number;
}

function parseNode(lines: SrcLine[], idx: number, indent: number, num: number): ParseResult {
  if (idx >= lines.length || lines[idx].indent < indent) return { value: null, next: idx };
  if (lines[idx].text === "-" || lines[idx].text.startsWith("- ")) return parseSeq(lines, idx, indent, num);
  return parseMap(lines, idx, indent, num);
}

function parseSeq(lines: SrcLine[], idx: number, indent: number, num: number): ParseResult {
  const items: YamlValue[] = [];
  while (idx < lines.length && lines[idx].indent === indent && (lines[idx].text === "-" || lines[idx].text.startsWith("- "))) {
    const line = lines[idx];
    const rest = line.text === "-" ? "" : line.text.slice(2);
    if (rest === "") {
      // nested block on following lines
      if (idx + 1 < lines.length && lines[idx + 1].indent > indent) {
        const r = parseNode(lines, idx + 1, lines[idx + 1].indent, lines[idx + 1].num);
        items.push(r.value);
        idx = r.next;
      } else {
        items.push(null);
        idx++;
      }
    } else if (rest.startsWith("[") || rest.startsWith("{")) {
      const r = parseFlow(rest, 0, line.num);
      if (r.next !== rest.length) throw new YamlParseError("trailing content after flow collection", line.num);
      items.push(r.value);
      idx++;
    } else if (rest.includes(":") && splitKeyValueSafe(rest)) {
      // map starting inline on the dash line: re-anchor at indent+2
      const virtualIndent = indent + 2;
      const sub: SrcLine[] = [{ indent: virtualIndent, text: rest, num: line.num }];
      let j = idx + 1;
      while (j < lines.length && lines[j].indent >= virtualIndent) { sub.push(lines[j]); j++; }
      const r = parseMap(sub, 0, virtualIndent, line.num);
      items.push(r.value);
      idx = j;
    } else {
      items.push(parseScalar(rest, line.num));
      idx++;
    }
  }
  return { value: items, next: idx };
}

function splitKeyValueSafe(text: string): boolean {
  try {
    splitKeyValue(text, 0);
    return true;
  } catch {
    return false;
  }
}

function parseMap(lines: SrcLine[], idx: number, indent: number, num: number): ParseResult {
  const map: Record<string, YamlValue> = {};
  while (idx < lines.length && lines[idx].indent === indent && lines[idx].text !== "-" && !lines[idx].text.startsWith("- ")) {
    const line = lines[idx];
    const { key, valueRaw } = splitKeyValue(line.text, line.num);
    if (key in map) throw new YamlParseError(`duplicate mapping key "${key}"`, line.num);
    if (valueRaw === null || valueRaw === "") {
      // nested node on following lines (deeper indent), or null
      if (idx + 1 < lines.length && lines[idx + 1].indent > indent) {
        const r = parseNode(lines, idx + 1, lines[idx + 1].indent, lines[idx + 1].num);
        map[key] = r.value;
        idx = r.next;
      } else if (idx + 1 < lines.length && lines[idx + 1].indent === indent && (lines[idx + 1].text === "-" || lines[idx + 1].text.startsWith("- "))) {
        // sequences may sit at the same indent as their key (common YAML style)
        const r = parseSeq(lines, idx + 1, indent, lines[idx + 1].num);
        map[key] = r.value;
        idx = r.next;
      } else {
        map[key] = null;
        idx++;
      }
    } else if (valueRaw === "|" || valueRaw === ">" || valueRaw.startsWith("|") || valueRaw.startsWith(">")) {
      throw new YamlParseError(`block scalar "${valueRaw}" is not supported by the sbobctl YAML subset parser`, line.num);
    } else if (valueRaw.startsWith("[") || valueRaw.startsWith("{")) {
      const r = parseFlow(valueRaw, 0, line.num);
      if (r.next !== valueRaw.length) throw new YamlParseError("trailing content after flow collection", line.num);
      map[key] = r.value;
      idx++;
    } else if (valueRaw.startsWith("&") || valueRaw.startsWith("*")) {
      throw new YamlParseError("anchors and aliases are not supported", line.num);
    } else {
      map[key] = parseScalar(valueRaw, line.num);
      idx++;
    }
    // any deeper line that was not consumed is a structural error
    if (idx < lines.length && lines[idx].indent > indent) {
      throw new YamlParseError("unexpected deeper indentation (unsupported YAML construct?)", lines[idx].num);
    }
  }
  return { value: map, next: idx };
}

export function parseYaml(source: string): YamlValue {
  const lines = preprocess(source);
  if (lines.length === 0) return null;
  const r = parseNode(lines, 0, lines[0].indent, lines[0].num);
  if (r.next !== lines.length) {
    throw new YamlParseError(`unexpected content at indentation level ${lines[r.next].indent}`, lines[r.next].num);
  }
  return r.value;
}

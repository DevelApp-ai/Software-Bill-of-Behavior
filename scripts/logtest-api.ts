#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Wazuh detection-testing harness — API-driven corpus replay (issue #23)
//
// The wazuh-logtest CLI pipes are text-only and one-shot: they cannot assert
// on structured rule output, and they cannot prove the SUSTAINED drift rules
// (frequency 8 within 120s) because each corpus line lands in a fresh state.
// The Wazuh server logtest API (Wazuh >= 4.4, <rule_test> enabled) fixes both:
//
//   PUT  /logtest                   body {log, token?} -> JSON per line
//   DEL  /logtest/sessions/{token}  close the session
//
// Session tokens are reused across requests, so `firedtimes` accumulates the
// same way the live analysis engine does. Replaying the drift corpus eight
// times inside ONE session makes the sustained-drift frequency children fire
// exactly as they would in production (e.g. php-fpm slot 1: 100112/100122/
// 100132 — the PHP2Shell scenario, docs/php2shell-scenario.md).
//
// Usage (from a host that can reach the lab Wazuh server API):
//   SBOB_WAZUH_API_PASS=... node scripts/logtest-api.ts --target php \
//     --api https://lab-manager:55000
//
// Usage (from a host that can reach the lab Wazuh server API):
//   SBOB_WAZUH_API_PASS=... node scripts/logtest-api.ts --target php \
//     --api https://lab-manager:55000
//
// Options:
//   --target <linux|windows|k8s|php>   corpus pair + expected rule ids
//   --api <url>                        or SBOB_WAZUH_API_URL (https://host:55000)
//   --user <name>                      or SBOB_WAZUH_API_USER (default: wazuh)
//   --pass <secret>                    preferred: SBOB_WAZUH_API_PASS or --pass-file
//   --pass-file <path>                 read the API password from a file
//   --repeats <n>                      sustained-check passes (default: 8)
//   --skip-sustained                   skip the frequency-rule check
//   --verify-tls                       verify the API certificate (lab CAs are
//                                      self-signed by default; off by default)
//
// Exit codes: 0 = all detection tests pass, 1 = detection test failed,
//             2 = usage/transport error (same contract as logtest-corpus.sh).
// The response schema is parsed defensively (rule id from data.rule.id,
// data.alert.rule.id or the phase-3 text output) so minor API shape drift
// between 4.x minors does not break the harness.
// ---------------------------------------------------------------------------
import { readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export interface TargetSpec {
  benign: string;
  drift: string;
  /** rule ids the drift corpus MUST fire */
  driftIds: string[];
  /** frequency children (8 matches / 120s) proven by the sustained check */
  sustainedIds: string[];
  /** informational rules allowed to alert on the benign corpus (k8s attribution) */
  attributionInfoIds: string[];
}

export const TARGETS: Record<string, TargetSpec> = {
  linux: {
    benign: "test/corpus/redis-benign.audit",
    drift: "test/corpus/redis-drift.audit",
    driftIds: ["100011", "100021", "100031", "100060", "100062"],
    sustainedIds: ["100012", "100022", "100032"],
    attributionInfoIds: [],
  },
  windows: {
    benign: "test/corpus/redis-benign.win.jsonl",
    drift: "test/corpus/redis-drift.win.jsonl",
    driftIds: ["100016", "100006", "100026", "100036", "100007"],
    sustainedIds: [], // M2 windows ruleset has no frequency children
    attributionInfoIds: [],
  },
  k8s: {
    benign: "test/corpus/redis-benign.k8s.audit",
    drift: "test/corpus/redis-drift.k8s.audit",
    driftIds: ["100011", "100021", "100031", "100060", "100062"],
    sustainedIds: ["100012", "100022", "100032"],
    attributionInfoIds: ["100070", "100071", "100073", "100074"],
  },
  // PHP2Shell scenario (CVE-2026-109618 / CVE-2026-109619) — php-fpm slot 1
  php: {
    benign: "test/corpus/php-benign.audit",
    drift: "test/corpus/php-drift.audit",
    driftIds: ["100111", "100121", "100131", "100163"],
    sustainedIds: ["100112", "100122", "100132"],
    attributionInfoIds: [],
  },
};

export const SUSTAINED_REPEATS_DEFAULT = 8;

// ---------------------------------------------------------------------------
// pure helpers (unit-tested in test/logtest-api.test.ts)
// ---------------------------------------------------------------------------

/** corpus files are auditd-shaped: `#` comments and blank lines are not events */
export function corpusLines(text: string): string[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** the PUT /logtest envelope puts payload fields under `data`; tolerate both */
function dataOf(resp: unknown): Record<string, unknown> {
  const r = asRecord(resp);
  if (r === null) return {};
  return asRecord(r["data"]) ?? r;
}

/** rule record from data.rule.id, or from the alert object (data.alert.rule.id) */
function ruleRecordOf(data: Record<string, unknown>): Record<string, unknown> | null {
  const rule = asRecord(data["rule"]);
  if (rule !== null) return rule;
  const alert = asRecord(data["alert"]);
  const alertRule = alert === null ? null : asRecord(alert["rule"]);
  return alertRule;
}

/** the matched rule id, from the JSON field or the phase-3 text output */
export function extractRuleId(resp: unknown): string | null {
  const data = dataOf(resp);
  const rule = ruleRecordOf(data);
  if (rule !== null && rule["id"] != null) return String(rule["id"]);
  const out = data["output"];
  if (Array.isArray(out)) {
    for (const entry of out) {
      if (typeof entry !== "string") continue;
      const m = /^id:\s*'(\d+)'\s*$/.exec(entry.trim());
      if (m) return m[1]!;
    }
  }
  return null;
}

/** alert semantics: level >= the alert threshold — not a mere base-chain match */
export function isAlert(resp: unknown): boolean {
  const data = dataOf(resp);
  const alert = data["alert"];
  if (alert === true) return true;
  const alertRec = asRecord(alert);
  if (alertRec !== null && ruleRecordOf(alertRec) !== null) return true;
  const out = data["output"];
  if (Array.isArray(out)) {
    return out.some((l) => typeof l === "string" && l.includes("**Alert to be generated."));
  }
  return false;
}

/** session token for firedtimes continuity (first response carries it) */
export function extractToken(resp: unknown): string | null {
  const t = dataOf(resp)["token"];
  return typeof t === "string" && t.length > 0 ? t : null;
}

/** engine diagnostics (decoder/rule errors come back in `messages`) */
export function extractMessages(resp: unknown): string[] {
  const msgs = dataOf(resp)["messages"];
  return Array.isArray(msgs) ? msgs.filter((m): m is string => typeof m === "string") : [];
}

export interface ReconcileResult {
  missing: string[];
  firedUnique: string[];
}

/** expected-vs-fired: every mapped drift id must appear among the fired ids */
export function reconcile(expected: readonly string[], fired: readonly string[]): ReconcileResult {
  const seen = new Set(fired);
  return {
    missing: expected.filter((id) => !seen.has(id)),
    firedUnique: [...seen],
  };
}

// ---------------------------------------------------------------------------
// transport (node http/https — zero dependencies; self-signed CAs allowed)
// ---------------------------------------------------------------------------

export interface Transport {
  login(api: string, user: string, pass: string): Promise<string>;
  putLog(api: string, jwt: string, log: string, sessionToken: string | null): Promise<unknown>;
  closeSession(api: string, jwt: string, sessionToken: string): Promise<void>;
}

interface HttpReply {
  status: number;
  body: string;
}

function requestRaw(url: string, method: string, headers: Record<string, string>, body: string | null, verifyTls: boolean): Promise<HttpReply> {
  return new Promise<HttpReply>((resolve, reject) => {
    const u = new URL(url);
    const collect = (res: IncomingMessage): void => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
    };
    const req =
      u.protocol === "https:"
        ? httpsRequest(u, { method, headers, rejectUnauthorized: verifyTls }, collect)
        : httpRequest(u, { method, headers }, collect);
    req.on("error", reject);
    req.setTimeout(15_000, () => req.destroy(new Error("request timeout")));
    if (body !== null) req.write(body);
    req.end();
  });
}

export function makeTransport(verifyTls: boolean): Transport {
  return {
    async login(api: string, user: string, pass: string): Promise<string> {
      const basic = Buffer.from(`${user}:${pass}`, "utf8").toString("base64");
      const reply = await requestRaw(
        `${api}/security/user/authenticate?raw=true`,
        "POST",
        { Authorization: `Basic ${basic}` },
        null,
        verifyTls,
      );
      const token = reply.body.trim();
      if (reply.status !== 200 || token.length === 0 || token.startsWith("{")) {
        throw new Error(`API login failed (HTTP ${reply.status}): ${reply.body.slice(0, 200)}`);
      }
      return token;
    },
    async putLog(api: string, jwt: string, log: string, sessionToken: string | null): Promise<unknown> {
      const payload = sessionToken === null ? { log } : { log, token: sessionToken };
      const reply = await requestRaw(
        `${api}/logtest`,
        "PUT",
        { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
        JSON.stringify(payload),
        verifyTls,
      );
      if (reply.status !== 200) {
        throw new Error(`PUT /logtest failed (HTTP ${reply.status}): ${reply.body.slice(0, 200)}`);
      }
      return JSON.parse(reply.body);
    },
    async closeSession(api: string, jwt: string, sessionToken: string): Promise<void> {
      await requestRaw(
        `${api}/logtest/sessions/${sessionToken}`,
        "DELETE",
        { Authorization: `Bearer ${jwt}` },
        null,
        verifyTls,
      );
    },
  };
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

export interface ReplayResult {
  /** every matched rule id, in order (base chain included) */
  ruleIds: string[];
  /** rule ids of the lines that generated alerts */
  alertRuleIds: string[];
  lineCount: number;
  sessionToken: string | null;
  messages: string[];
}

export async function replayCorpus(
  transport: Transport,
  api: string,
  jwt: string,
  lines: readonly string[],
): Promise<ReplayResult> {
  let token: string | null = null;
  const ruleIds: string[] = [];
  const alertRuleIds: string[] = [];
  const messages: string[] = [];
  for (const log of lines) {
    const resp = await transport.putLog(api, jwt, log, token);
    const t = extractToken(resp);
    if (t !== null) token = t;
    messages.push(...extractMessages(resp));
    const id = extractRuleId(resp);
    if (id !== null) ruleIds.push(id);
    if (isAlert(resp) && id !== null) alertRuleIds.push(id);
  }
  return { ruleIds, alertRuleIds, lineCount: lines.length, sessionToken: token, messages };
}

/** 8 passes of the drift corpus inside ONE session -> frequency children fire */
export function repeatLines(lines: readonly string[], repeats: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < repeats; i++) out.push(...lines);
  return out;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export interface CliConfig {
  target: string;
  api: string;
  user: string;
  pass: string | null;
  verifyTls: boolean;
  repeats: number;
  skipSustained: boolean;
}

export type ParseResult = { ok: true; config: CliConfig } | { ok: false; error: string; usage: boolean };

export function parseArgs(
  argv: readonly string[],
  env: Record<string, string | undefined> = process.env,
): ParseResult {
  const c: CliConfig = {
    target: "",
    api: "",
    user: "",
    pass: null,
    verifyTls: false,
    repeats: SUSTAINED_REPEATS_DEFAULT,
    skipSustained: false,
  };
  const usage = "usage: node scripts/logtest-api.ts --target <linux|windows|k8s|php> --api https://host:55000\n" +
    "       credentials: SBOB_WAZUH_API_USER / SBOB_WAZUH_API_PASS (or --user/--pass-file)";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const next = (): string | null => (i + 1 < argv.length ? argv[++i]! : null);
    if (a === "--help" || a === "-h") return { ok: false, error: usage, usage: true };
    else if (a === "--target") {
      const v = next();
      if (v === null || !(v in TARGETS)) return { ok: false, error: `unknown or missing --target (expected: ${Object.keys(TARGETS).join("|")})`, usage: true };
      c.target = v;
    } else if (a === "--api") c.api = next() ?? "";
    else if (a === "--user") c.user = next() ?? "";
    else if (a === "--pass") c.pass = next();
    else if (a === "--pass-file") {
      const f = next();
      if (f === null) return { ok: false, error: "--pass-file requires a path", usage: true };
      try {
        c.pass = readFileSync(f, "utf8").trim();
      } catch {
        return { ok: false, error: `cannot read --pass-file ${f}`, usage: true };
      }
    } else if (a === "--repeats") {
      const v = next();
      const n = v === null ? Number.NaN : Number(v);
      if (!Number.isInteger(n) || n < 1) return { ok: false, error: "--repeats requires an integer >= 1", usage: true };
      c.repeats = n;
    } else if (a === "--skip-sustained") c.skipSustained = true;
    else if (a === "--verify-tls") c.verifyTls = true;
    else return { ok: false, error: `unknown option ${a}\n${usage}`, usage: true };
  }
  if (c.target === "") return { ok: false, error: "--target is required", usage: true };
  c.api = (c.api || env["SBOB_WAZUH_API_URL"] || "").replace(/\/+$/, "");
  if (c.api === "" || !/^https?:\/\//.test(c.api)) return { ok: false, error: "--api (or SBOB_WAZUH_API_URL) must be an http(s) URL", usage: true };
  c.user = c.user || env["SBOB_WAZUH_API_USER"] || "wazuh";
  c.pass = c.pass ?? env["SBOB_WAZUH_API_PASS"] ?? null;
  if (c.pass === null || c.pass === "") return { ok: false, error: "API password missing: pass SBOB_WAZUH_API_PASS or --pass-file (avoid --pass in shell history)", usage: true };
  return { ok: true, config: c };
}

function fail(line: string): void {
  console.error(`FAIL: ${line}`);
}

export async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if (!parsed.ok) {
    console.error(parsed.error);
    return 2;
  }
  const cfg = parsed.config;
  const spec = TARGETS[cfg.target]!;
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const read = (p: string): string[] => corpusLines(readFileSync(join(repoRoot, p), "utf8"));

  const transport = makeTransport(cfg.verifyTls);
  let jwt: string;
  try {
    jwt = await transport.login(cfg.api, cfg.user, cfg.pass!);
  } catch (e) {
    console.error(`ERROR: Wazuh API login failed — ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }

  // --- benign: zero alerts (attribution info rules exempt on k8s) ---
  const allowedInfo = new Set(spec.attributionInfoIds);
  console.log(`== [${cfg.target}] benign corpus: expecting NO drift alerts ==`);
  let benign: ReplayResult;
  try {
    benign = await replayCorpus(transport, cfg.api, jwt, read(spec.benign));
  } catch (e) {
    console.error(`ERROR: benign replay transport failure — ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }
  const benignForbidden = benign.alertRuleIds.filter((id) => !allowedInfo.has(id));
  if (benign.lineCount === 0) {
    fail(`benign corpus for target ${cfg.target} is empty`);
    return 1;
  }
  if (benignForbidden.length > 0) {
    fail(`benign corpus generated drift alerts (${[...new Set(benignForbidden)].join(", ")})`);
    console.error("      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading");
    return 1;
  }
  const infoSeen = [...new Set(benign.ruleIds)].filter((id) => allowedInfo.has(id));
  if (infoSeen.length > 0) console.log(`  (attribution info, allowed): ${infoSeen.join(", ")}`);
  console.log("OK: benign corpus fired no drift alerts");

  // --- drift: every mapped rule id must fire ---
  console.log(`== [${cfg.target}] drift corpus: expecting ${spec.driftIds.join(" ")} ==`);
  const driftLines = read(spec.drift);
  let drift: ReplayResult;
  try {
    drift = await replayCorpus(transport, cfg.api, jwt, driftLines);
  } catch (e) {
    console.error(`ERROR: drift replay transport failure — ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }
  const rec = reconcile(spec.driftIds, drift.ruleIds);
  if (rec.missing.length > 0) {
    fail(`drift rules did not fire: ${rec.missing.join(", ")}`);
    console.error("      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading");
    console.error(`      fired during replay: ${rec.firedUnique.join(", ") || "(none)"}`);
    return 1;
  }
  for (const id of spec.driftIds) console.log(`OK: rule ${id} fired`);

  // --- sustained: frequency children fire at 8 matches within the timeframe ---
  if (!cfg.skipSustained && spec.sustainedIds.length > 0) {
    console.log(`== [${cfg.target}] sustained check: expecting ${spec.sustainedIds.join(" ")} (${cfg.repeats} passes, one session) ==`);
    let sustained: ReplayResult;
    try {
      sustained = await replayCorpus(transport, cfg.api, jwt, repeatLines(driftLines, cfg.repeats));
    } catch (e) {
      console.error(`ERROR: sustained replay transport failure — ${e instanceof Error ? e.message : String(e)}`);
      return 2;
    }
    const srec = reconcile(spec.sustainedIds, sustained.ruleIds);
    if (srec.missing.length > 0) {
      fail(`sustained drift rules did not fire after ${cfg.repeats} passes: ${srec.missing.join(", ")}`);
      console.error("      frequency rules need 8 matches within 120s in ONE logtest session —");
      console.error("      check the session token is being reused (firedtimes continuity)");
      return 1;
    }
    for (const id of spec.sustainedIds) console.log(`OK: sustained rule ${id} fired`);
  }

  // best-effort session cleanup
  try {
    if (drift.sessionToken !== null) await transport.closeSession(cfg.api, jwt, drift.sessionToken);
  } catch {
    /* session_timeout closes it anyway */
  }

  console.log("");
  console.log(`PASS (${cfg.target}): API detection tests succeeded — detection proven, not just replayed.`);
  return 0;
}

// run only when executed directly (node scripts/logtest-api.ts); imports stay inert
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}

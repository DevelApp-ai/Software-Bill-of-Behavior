/**
 * Wazuh detection-testing harness tests (issue #23, docs/php2shell-scenario.md)
 * — scripts/logtest-api.ts drives the corpora through the Wazuh server logtest
 * API (PUT /logtest, Wazuh >= 4.4) instead of piping text into wazuh-logtest:
 * JSON-asserted rule ids, session-token continuity (firedtimes), and the
 * SUSTAINED drift frequency rules (8 matches / 120s) that a one-shot replay
 * cannot prove. The transport is injectable, so everything here runs against
 * mock responses shaped like the documented API output — the live lab run is
 * the remaining step (same labValidation: pending contract as the bundles).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TARGETS,
  SUSTAINED_REPEATS_DEFAULT,
  corpusLines,
  extractRuleId,
  extractToken,
  extractMessages,
  isAlert,
  reconcile,
  replayCorpus,
  repeatLines,
  parseArgs,
  type Transport,
} from "../scripts/logtest-api.ts";

// ---------------------------------------------------------------------------
// target contract — must mirror scripts/logtest-corpus.sh exactly
// ---------------------------------------------------------------------------

test("php target maps the PHP2Shell drift and sustained rule bands", () => {
  const php = TARGETS["php"]!;
  assert.deepEqual(php.driftIds, ["100111", "100121", "100131", "100163"]);
  assert.deepEqual(php.sustainedIds, ["100112", "100122", "100132"]);
  assert.equal(php.benign, "test/corpus/php-benign.audit");
  assert.equal(php.drift, "test/corpus/php-drift.audit");
  assert.deepEqual(php.attributionInfoIds, []);
});

test("redis targets match the logtest-corpus.sh harness ids", () => {
  const linux = TARGETS["linux"]!;
  assert.deepEqual(linux.driftIds, ["100011", "100021", "100031", "100060", "100062"]);
  const k8s = TARGETS["k8s"]!;
  assert.deepEqual(k8s.driftIds, linux.driftIds);
  assert.deepEqual(k8s.attributionInfoIds, ["100070", "100071", "100073", "100074"], "attribution info rules are exempt on benign");
  const win = TARGETS["windows"]!;
  assert.deepEqual(win.driftIds, ["100016", "100006", "100026", "100036", "100007"]);
  assert.deepEqual(win.sustainedIds, [], "M2 windows ruleset has no frequency children");
});

test("sustained default is the frequency threshold (8 matches)", () => {
  assert.equal(SUSTAINED_REPEATS_DEFAULT, 8);
});

// ---------------------------------------------------------------------------
// corpus line handling
// ---------------------------------------------------------------------------

test("corpusLines drops comments and blanks, keeps event lines trimmed", () => {
  const text = [
    "# Drift events: each violates the php-fpm SBoB",
    "",
    "type=SYSCALL msg=audit(1699999990.100:2001): arch=c000003e syscall=59",
    "  # indented comment is still a comment after trimming",
    "  type=PATH msg=audit(1699999990.100:2001): item=0",
  ].join("\n");
  assert.deepEqual(corpusLines(text), [
    "type=SYSCALL msg=audit(1699999990.100:2001): arch=c000003e syscall=59",
    "type=PATH msg=audit(1699999990.100:2001): item=0",
  ]);
});

// ---------------------------------------------------------------------------
// response parsing — defensive across the documented API output shapes
// ---------------------------------------------------------------------------

/** the phase-3 text shape the official docs show for wazuh-logtest output */
const TEXT_RESPONSE = {
  data: {
    token: "3b275b49-9c5e-40d1-bdf0-95d13a1e6d04",
    output: [
      "**Phase 1: Completed pre-decoding.",
      "**Phase 2: Completed decoding.",
      "**Phase 3: Completed filtering (rules).",
      "id: '100111'",
      "level: '9'",
      "description: 'SBoB drift: process /bin/sh not declared in execs[] of php-fpm SBoB v0.0.4'",
      "groups: '[\"sbob\",\"php-fpm\",\"sbob-drift\",\"process-execution\"]'",
      "**Alert to be generated.",
    ],
    messages: [],
  },
};

/** the JSON-object shape: rule id as a structured field */
const JSON_RESPONSE = {
  data: {
    token: "f6a7f8d0-1234-4abc-9def-567890abcdef",
    alert: true,
    rule: { id: 100121, level: 9, groups: ["sbob", "php-fpm", "sbob-drift", "file-access"] },
    decoder: { name: "sbob-php-fpm-path-name" },
    messages: [],
  },
};

/** base-chain match: rule matched, level 0, no alert */
const BASE_RESPONSE = {
  data: {
    token: "same-session-token",
    alert: false,
    rule: { id: 100110, level: 0, description: "SBoB base: exec base for workload php-fpm" },
    messages: [],
  },
};

test("extractRuleId reads the id from the phase-3 text output", () => {
  assert.equal(extractRuleId(TEXT_RESPONSE), "100111");
});

test("extractRuleId reads structured rule ids (numbers and strings)", () => {
  assert.equal(extractRuleId(JSON_RESPONSE), "100121");
  const alertObjectShape = { data: { alert: { rule: { id: "100132", level: 12 } } } };
  assert.equal(extractRuleId(alertObjectShape), "100132");
  assert.equal(extractRuleId(BASE_RESPONSE), "100110");
});

test("extractRuleId returns null when nothing matched (no rule, no phase-3 id)", () => {
  assert.equal(extractRuleId({ data: { token: "t", output: ["**Phase 1: Completed pre-decoding."], messages: [] } }), null);
  assert.equal(extractRuleId({ data: {} }), null);
  assert.equal(extractRuleId(null), null);
});

test("isAlert: alert to be generated — in text and JSON shapes; false on level-0 base chain", () => {
  assert.ok(isAlert(TEXT_RESPONSE), "phase-3 text carries the alert marker");
  assert.ok(isAlert(JSON_RESPONSE), "alert: true");
  assert.ok(!isAlert(BASE_RESPONSE), "base chain matches without alerting");
  assert.ok(!isAlert({ data: { output: ["**Phase 2: Completed decoding."] } }), "no alert marker");
});

test("extractToken and extractMessages surface session continuity and engine diagnostics", () => {
  assert.equal(extractToken(TEXT_RESPONSE), "3b275b49-9c5e-40d1-bdf0-95d13a1e6d04");
  assert.equal(extractToken(BASE_RESPONSE), "same-session-token");
  assert.equal(extractToken({ data: {} }), null);
  assert.deepEqual(extractMessages({ data: { messages: ["invalid token"] } }), ["invalid token"]);
  assert.deepEqual(extractMessages(TEXT_RESPONSE), []);
});

// ---------------------------------------------------------------------------
// reconcile — expected vs fired
// ---------------------------------------------------------------------------

test("reconcile: all expected ids fired -> no missing", () => {
  const rec = reconcile(["100111", "100121", "100131", "100163"], [
    "100100", "100110", "100111", // exec event: base chain + drift
    "100120", "100121", // open event
    "100131", // connect event
    "100163", // memfd signature
  ]);
  assert.deepEqual(rec.missing, []);
  assert.ok(rec.firedUnique.includes("100111"));
});

test("reconcile: missing ids are reported for the failure message", () => {
  const rec = reconcile(["100111", "100121", "100131", "100163"], ["100111", "100121"]);
  assert.deepEqual(rec.missing, ["100131", "100163"]);
});

// ---------------------------------------------------------------------------
// replay — transport injectable, session token continuity, alert accounting
// ---------------------------------------------------------------------------

class MockTransport implements Transport {
  public putCalls: Array<{ log: string; sessionToken: string | null }> = [];
  public closedWith: string | null = null;
  public jwt = "mock-jwt";
  private respond: (log: string, putIndex: number, sessionToken: string | null) => unknown;
  constructor(respond: (log: string, putIndex: number, sessionToken: string | null) => unknown) {
    this.respond = respond;
  }
  async login(_api: string, user: string, _pass: string): Promise<string> {
    assert.equal(user, "wazuh");
    return this.jwt;
  }
  async putLog(_api: string, _jwt: string, log: string, sessionToken: string | null): Promise<unknown> {
    this.putCalls.push({ log, sessionToken });
    return this.respond(log, this.putCalls.length, sessionToken);
  }
  async closeSession(_api: string, _jwt: string, sessionToken: string): Promise<void> {
    this.closedWith = sessionToken;
  }
}

test("replayCorpus: collects rule ids, counts alerts, reuses the session token", async () => {
  const t = new MockTransport((_log, i, sessionToken) => {
    // first request opens the session (no token), the API hands one back
    if (i === 1) return { data: { token: "sess-1", alert: true, rule: { id: 100111, level: 9 } } };
    if (i === 2) return { data: { token: "sess-1", alert: false, rule: { id: 100120, level: 0 } } };
    assert.notEqual(sessionToken, null, "session token must ride along after the first line");
    return { data: { token: "sess-1", alert: true, rule: { id: 100163, level: 10 } } };
  });
  const result = await replayCorpus(t, "https://lab:55000", t.jwt, [
    "exec-drift-line",
    "open-base-line",
    "memfd-sig-line",
  ]);
  assert.deepEqual(result.ruleIds, ["100111", "100120", "100163"]);
  assert.deepEqual(result.alertRuleIds, ["100111", "100163"], "level-0 base match is not an alert");
  assert.equal(result.lineCount, 3);
  assert.equal(result.sessionToken, "sess-1");
  assert.equal(t.putCalls[1]!.sessionToken, "sess-1");
  assert.equal(t.putCalls[2]!.sessionToken, "sess-1");
});

test("benign replay stays silent: only level-0 base-chain matches, zero alerts", async () => {
  const t = new MockTransport(() => ({ data: { token: "sess-benign", alert: false, rule: { id: 100110, level: 0 } } }));
  const result = await replayCorpus(t, "https://lab:55000", t.jwt, ["l1", "l2", "l3", "l4", "l5"]);
  assert.deepEqual(result.alertRuleIds, []);
  assert.ok(result.ruleIds.every((id) => id.endsWith("0")), "only the level-0 base chain may match");
});

test("sustained replay: the 8th pass flips the drift rule into its frequency child", async () => {
  // the exec drift line appears once per corpus pass; the analysis engine
  // raises 100111 -> 100112 when firedtimes hits 8 within the timeframe
  const counts = new Map<string, number>();
  const t = new MockTransport((log) => {
    const n = (counts.get(log) ?? 0) + 1;
    counts.set(log, n);
    if (log.includes("sbob-exec") && n < 8) {
      return { data: { token: "sess-sust", alert: true, rule: { id: 100111, level: 9 } } };
    }
    if (log.includes("sbob-exec")) {
      return { data: { token: "sess-sust", alert: true, rule: { id: 100112, level: 12 } } };
    }
    return { data: { token: "sess-sust", alert: false, rule: { id: 100100, level: 0 } } };
  });
  const driftPass = ["exec: sbob-exec line", "open: other line"];
  const result = await replayCorpus(t, "https://lab:55000", t.jwt, repeatLines(driftPass, 8));
  // the frequency child fired on the 8th pass — a one-shot replay cannot show this
  const rec = reconcile(TARGETS["php"]!.sustainedIds, result.ruleIds);
  assert.equal(rec.missing.filter((id) => id === "100112").length, 0, "100112 fired at firedtimes=8");
  assert.ok(result.ruleIds.includes("100111"));
  assert.equal(t.putCalls[0]!.sessionToken, null, "session opens on the first line");
  assert.ok(t.putCalls.slice(1).every((c) => c.sessionToken === "sess-sust"));
});

test("repeatLines concatenates the passes in order", () => {
  assert.deepEqual(repeatLines(["a", "b"], 3), ["a", "b", "a", "b", "a", "b"]);
  assert.deepEqual(repeatLines(["a"], 1), ["a"]);
});

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

const ENV = { SBOB_WAZUH_API_USER: undefined, SBOB_WAZUH_API_URL: undefined, SBOB_WAZUH_API_PASS: "secret" };

test("parseArgs: happy path with env fallbacks", () => {
  const r = parseArgs(["--target", "php", "--api", "https://lab-manager:55000/"], { ...ENV });
  assert.ok(r.ok);
  assert.equal(r.config.target, "php");
  assert.equal(r.config.api, "https://lab-manager:55000", "trailing slash stripped");
  assert.equal(r.config.user, "wazuh", "default API user");
  assert.equal(r.config.pass, "secret");
  assert.equal(r.config.repeats, 8);
  assert.equal(r.config.verifyTls, false, "lab CAs are self-signed by default");
});

test("parseArgs: --target validation and missing-argument errors", () => {
  assert.ok(!parseArgs(["--target", "nope", "--api", "https://x:55000"], ENV).ok);
  assert.ok(!parseArgs([], ENV).ok, "--target is required");
  assert.ok(!parseArgs(["--target", "php"], { SBOB_WAZUH_API_PASS: "x" }).ok, "--api required");
  assert.ok(!parseArgs(["--target", "php", "--api", "lab-manager:55000"], ENV).ok, "api must be http(s)");
  assert.ok(!parseArgs(["--target", "php", "--api", "https://x:55000"], {}).ok, "password required");
  assert.ok(!parseArgs(["--target", "php", "--api", "https://x:55000", "--bogus"], ENV).ok, "unknown option rejected");
  assert.ok(!parseArgs(["--target", "php", "--api", "https://x:55000", "--repeats", "x"], ENV).ok);
});

test("parseArgs: --pass-file, --user override, --skip-sustained, --verify-tls", () => {
  const dir = mkdtempSync(join(tmpdir(), "logtest-api-"));
  try {
    const passFile = join(dir, "pass.txt");
    writeFileSync(passFile, "file-secret\n");
    const r = parseArgs(
      ["--target", "linux", "--api", "https://x:55000", "--user", "ops", "--pass-file", passFile, "--skip-sustained", "--verify-tls", "--repeats", "3"],
      {},
    );
    assert.ok(r.ok);
    assert.equal(r.config.user, "ops");
    assert.equal(r.config.pass, "file-secret", "trailing newline trimmed");
    assert.equal(r.config.skipSustained, true);
    assert.equal(r.config.verifyTls, true);
    assert.equal(r.config.repeats, 3);
    assert.ok(!parseArgs(["--target", "php", "--api", "https://x", "--pass-file", join(dir, "missing")], {}).ok);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parseArgs: --help short-circuits with the usage banner", () => {
  const r = parseArgs(["--help"], ENV);
  assert.ok(!r.ok);
  assert.ok(r.usage);
  assert.match(r.error, /--target <linux\|windows\|k8s\|php>/);
});

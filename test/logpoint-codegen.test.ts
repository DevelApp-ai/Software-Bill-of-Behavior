/**
 * LogPoint codegen (M6 / issue #7, TDS 13) — auditd-plane LQL rules pinned to
 * LogPoint's own field taxonomy (pySigma-backend-logpoint logpoint_mapping.py:
 * type→event_type, exe→path, name→path), allowlist-inversion semantics,
 * per-peer egress groups and the manifest coverage notes carrying the
 * documented v1 limits (raw daddr/dport, DNS-NAME, windows plane, glob
 * broadening).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import type { IR } from "../src/types.ts";
import { generateLogPointBundle } from "../src/codegen/logpoint.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;

function redisIR(): IR {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  return buildIR(validateSbob(parsed), parsed);
}

function pick(files: { path: string; content: string }[], path: string): string {
  const f = files.find((x) => x.path === path);
  assert.ok(f, `bundle file ${path}`);
  return f.content;
}

// --- bundle shape ---------------------------------------------------------------

test("logpoint bundle: 3 auditd-plane rule files + manifest, deterministic", () => {
  const a = generateLogPointBundle(redisIR());
  const b = generateLogPointBundle(redisIR());
  assert.deepEqual(a.map((f) => f.path), [
    "logpoint/sbob/redis_execs_linux.lql",
    "logpoint/sbob/redis_opens_linux.lql",
    "logpoint/sbob/redis_egress_linux.lql",
    "redis.manifest.json",
  ]);
  assert.deepEqual(a, b); // deterministic — no Date.now/Math.random leakage
});

// --- rule contents (LogPoint auditd taxonomy) -----------------------------------

test("logpoint execs rule: event_type/syscall selection with the inverted exe allowlist on the normalized path field", () => {
  const rule = pick(generateLogPointBundle(redisIR()), "logpoint/sbob/redis_execs_linux.lql");
  assert.equal(
    rule,
    '"event_type"="SYSCALL" "syscall"="execve" - ("path" IN ["/usr/bin/redis-server", "/bin/sh"])\n',
  );
});

test("logpoint opens rule: open/openat selection, exact + globbed path filter", () => {
  const rule = pick(generateLogPointBundle(redisIR()), "logpoint/sbob/redis_opens_linux.lql");
  assert.equal(
    rule,
    '"event_type"="SYSCALL" "syscall" IN ["open", "openat"] - ("path" IN ["/etc/resolv.conf", "/data/*"])\n',
  );
});

test("logpoint egress rule: per-peer (daddr AND dport) groups under one negation", () => {
  const rule = pick(generateLogPointBundle(redisIR()), "logpoint/sbob/redis_egress_linux.lql");
  assert.equal(
    rule,
    '"event_type"="SYSCALL" "syscall"="connect" - ' +
      '(("daddr" IN ["10.96.0.10"] AND "dport" IN [53]) OR ("daddr" IN ["162.0.217.171"] AND "dport" IN [443]))\n',
  );
});

test("logpoint egress rule: a peer with any-port (null) entries keeps the daddr-only group", () => {
  const ir = redisIR();
  ir.sections.egress!.entries[0]!.ports = [null];
  const rule = pick(generateLogPointBundle(ir), "logpoint/sbob/redis_egress_linux.lql");
  assert.equal(
    rule,
    '"event_type"="SYSCALL" "syscall"="connect" - ' +
      '(("daddr" IN ["10.96.0.10"]) OR ("daddr" IN ["162.0.217.171"] AND "dport" IN [443]))\n',
  );
});

// --- manifest --------------------------------------------------------------------

test("logpoint manifest: coverage notes carry the documented v1 limits", () => {
  const manifest = JSON.parse(pick(generateLogPointBundle(redisIR()), "redis.manifest.json")) as {
    target: string;
    labValidation: string;
    files: string[];
    coverageNotes: string[];
  };
  assert.equal(manifest.target, "logpoint");
  assert.equal(manifest.labValidation, "pending");
  assert.deepEqual(manifest.files, [
    "logpoint/sbob/redis_execs_linux.lql",
    "logpoint/sbob/redis_opens_linux.lql",
    "logpoint/sbob/redis_egress_linux.lql",
  ]);
  const notes = manifest.coverageNotes.join("\n");
  assert.match(notes, /raw auditd daddr\/dport/); // taxonomy-unnormalized destination fields
  assert.match(notes, /DNS-NAME documented blind/);
  assert.match(notes, /logpoint_windows/); // windows plane rides the sigma conversion
  assert.match(notes, /ingress\[\] rules are not emitted in v1/);
  assert.match(notes, /engine broadening documented in TDS 13/);
  assert.match(notes, /Wazuh bundle remains the args-precise/);
});

// --- section-absent semantics ------------------------------------------------------

test("logpoint section-absent semantics: no rules, absence + blind notes in the manifest", () => {
  const ir = redisIR();
  ir.sections.execs = undefined;
  ir.sections.opens = undefined;
  ir.sections.egress = undefined;
  ir.sections.ingress = undefined;
  const files = generateLogPointBundle(ir);
  assert.deepEqual(files.map((f) => f.path), ["redis.manifest.json"]);
  const notes = (JSON.parse(files[0]!.content) as { coverageNotes: string[] }).coverageNotes.join("\n");
  assert.match(notes, /execs\[\] section absent/);
  assert.match(notes, /opens\[\] section absent/);
  assert.match(notes, /egress\[\] section absent/);
  // ingress absent → no ingress note (absent is not NONE, TDS 8)
  assert.doesNotMatch(notes, /ingress\[\] rules are not emitted/);
});

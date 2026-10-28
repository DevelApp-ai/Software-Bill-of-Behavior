import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { lintIR, EXECS_ENTRY_CAP } from "../src/lint.ts";
import { SbobError } from "../src/errors.ts";
import type { IR } from "../src/types.ts";

function redisIR(): IR {
  const raw = readFileSync(new URL("../sbobs/redis.yaml", import.meta.url), "utf8");
  const parsed = parseYaml(raw);
  return buildIR(validateSbob(parsed), parsed);
}

function mustThrow(ir: IR, code: string, confirmNone: string[] = []): SbobError {
  try {
    lintIR(ir, { confirmNone, requireScope: true });
  } catch (e) {
    assert.ok(e instanceof SbobError);
    assert.equal((e as SbobError).code, code);
    return e as SbobError;
  }
  throw new Error(`expected lint failure ${code}, lint passed`);
}

const VALID_EMPTY = `
apiVersion: sbob.k8sstormcenter.io/v1
kind: SoftwareBillOfBehavior
metadata:
  name: empty
  namespace: ns
spec:
  imageID: docker.io/x@sha256:aa
  execs: []
`;

test("healthy redis IR passes lint", () => {
  lintIR(redisIR(), { confirmNone: [], requireScope: true });
});

test("explicitly empty section without --confirm-none is ERR_NONE_UNCONFIRMED", () => {
  const raw = VALID_EMPTY;
  const parsed = parseYaml(raw);
  const ir = buildIR(validateSbob(parsed), parsed);
  mustThrow(ir, "ERR_NONE_UNCONFIRMED");
  // and passes once confirmed
  lintIR(ir, { confirmNone: ["execs"], requireScope: true });
});

test("missing namespace is ERR_MISSING_SCOPE", () => {
  const ir = redisIR();
  (ir.workload as { namespace?: string }).namespace = "";
  mustThrow(ir, "ERR_MISSING_SCOPE");
});

test("execs over the entry cap is ERR_SECTION_CAP", () => {
  const ir = redisIR();
  const section = ir.sections.execs!;
  const entry = section.entries[0];
  while (section.entries.length <= EXECS_ENTRY_CAP) {
    section.entries.push({ ...entry, exact: `${entry.exact}-${section.entries.length}` } as typeof entry);
  }
  mustThrow(ir, "ERR_SECTION_CAP");
});

test("compiled patterns over the regex budget are ERR_REGEX_BUDGET", () => {
  const ir = redisIR();
  ir.sections.execs!.patterns = Array.from(
    { length: 100 },
    (_, i) => `/opt/some/very/long/prefix/number-${i}/segment-${i}/tail-${i}`,
  );
  mustThrow(ir, "ERR_REGEX_BUDGET");
});

test("wildcarded sections add the pcre2-required coverage note", () => {
  const ir = redisIR();
  lintIR(ir, { confirmNone: [], requireScope: true });
  assert.ok(
    ir.coverageNotes.some((n) => n.startsWith("pcre2-required")),
    "pcre2-required note present",
  );
});

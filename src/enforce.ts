/**
 * Phase-3 enforcement state model (TDS 14, M7 / issue #8).
 *
 * Monitor → Audit → Enforce rollout state machine, per workload, recorded in
 * a committed state file (GitOps, like the slot registry) and consumed by
 * `sbobctl enforce`:
 *
 *   workload: redis
 *   state: audit                     # default for unlisted sections
 *   sections:                       # optional per-section overrides
 *     execs: audit
 *     egress: enforce
 *   auditRecords:                    # operator-attested clean-window evidence
 *     egress: { started: "2026-10-01", windowDays: 14, incidents: 0 }
 *
 * Safety rules (TDS 14.6 — "never enforce a section whose drift has not been
 * alerting cleanly first"):
 *   - states are monitor | audit | enforce (ladder order enforced);
 *   - a section in `enforce` MUST carry an auditRecord with incidents: 0 and
 *     windowDays >= 1 — otherwise ERR_ENFORCE_NOT_AUDITED;
 *   - a section may not be enforce while the global default is monitor
 *     (the file must be deliberate, not a typo);
 *   - the per-section state may be at most one rung above the global default
 *     (audit → enforce is fine; monitor → enforce is not — you cannot skip
 *     the audit rung).
 *
 * The audit record is an operator attestation, not a live query: the tooling
 * validates its structure, the pilot evidence stays with the operator
 * (M1–M5 precedent).
 */
import { SbobError } from "./errors.ts";
import { parseYaml, type YamlValue } from "./yaml.ts";

export type EnforceStateName = "monitor" | "audit" | "enforce";

export const ENFORCE_SECTION_KEYS = ["execs", "opens", "egress", "ingress"] as const;
export type EnforceSectionKey = (typeof ENFORCE_SECTION_KEYS)[number];

export const STATE_RANK: Record<EnforceStateName, number> = { monitor: 0, audit: 1, enforce: 2 };

export interface AuditRecord {
  /** ISO date the audit window started (operator-attested). */
  started: string;
  /** Length of the clean alerting window in days (>= 1). */
  windowDays: number;
  /** Drift incidents during the window — MUST be 0 to advance to enforce. */
  incidents: number;
}

export interface EnforceStateFile {
  workload: string;
  /** Default state for sections not listed in `sections`. */
  state: EnforceStateName;
  sections: Partial<Record<EnforceSectionKey, EnforceStateName>>;
  auditRecords: Partial<Record<EnforceSectionKey, AuditRecord>>;
}

function asRecord(v: YamlValue, what: string): Record<string, YamlValue> {
  if (v === null || v === undefined || typeof v !== "object" || Array.isArray(v)) {
    throw new SbobError("ERR_ENFORCE_STATE_INVALID", `${what} must be a mapping`);
  }
  return v as Record<string, YamlValue>;
}

function asState(v: YamlValue, what: string): EnforceStateName {
  if (v !== "monitor" && v !== "audit" && v !== "enforce") {
    throw new SbobError("ERR_ENFORCE_STATE_INVALID", `${what} must be monitor|audit|enforce, got: ${String(v)}`);
  }
  return v;
}

export function parseEnforceState(source: string): EnforceStateFile {
  const doc = asRecord(parseYaml(source), "state file");

  const workload = doc["workload"];
  if (typeof workload !== "string" || workload.length === 0) {
    throw new SbobError("ERR_ENFORCE_STATE_INVALID", "workload is required");
  }

  const globalState = asState(doc["state"] ?? "monitor", "state");

  const sections: Partial<Record<EnforceSectionKey, EnforceStateName>> = {};
  if (doc["sections"] !== undefined && doc["sections"] !== null) {
    const raw = asRecord(doc["sections"], "sections");
    for (const [k, v] of Object.entries(raw)) {
      if (!(ENFORCE_SECTION_KEYS as readonly string[]).includes(k)) {
        throw new SbobError(
          "ERR_ENFORCE_STATE_INVALID",
          `unknown section "${k}" (sections: ${ENFORCE_SECTION_KEYS.join(", ")})`,
        );
      }
      sections[k as EnforceSectionKey] = asState(v, `sections.${k}`);
    }
  }

  const auditRecords: Partial<Record<EnforceSectionKey, AuditRecord>> = {};
  if (doc["auditRecords"] !== undefined && doc["auditRecords"] !== null) {
    const raw = asRecord(doc["auditRecords"], "auditRecords");
    for (const [k, v] of Object.entries(raw)) {
      if (!(ENFORCE_SECTION_KEYS as readonly string[]).includes(k)) {
        throw new SbobError("ERR_ENFORCE_STATE_INVALID", `auditRecords: unknown section "${k}"`);
      }
      const rec = asRecord(v, `auditRecords.${k}`);
      const started = rec["started"];
      const windowDays = rec["windowDays"];
      const incidents = rec["incidents"];
      if (typeof started !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(started)) {
        throw new SbobError("ERR_ENFORCE_STATE_INVALID", `auditRecords.${k}.started must be an ISO date (YYYY-MM-DD)`);
      }
      if (typeof windowDays !== "number" || !Number.isInteger(windowDays) || windowDays < 1) {
        throw new SbobError("ERR_ENFORCE_STATE_INVALID", `auditRecords.${k}.windowDays must be an integer >= 1`);
      }
      if (typeof incidents !== "number" || !Number.isInteger(incidents) || incidents < 0) {
        throw new SbobError("ERR_ENFORCE_STATE_INVALID", `auditRecords.${k}.incidents must be an integer >= 0`);
      }
      auditRecords[k as EnforceSectionKey] = { started, windowDays, incidents };
    }
  }

  const file: EnforceStateFile = { workload, state: globalState, sections, auditRecords };
  validateEnforceState(file);
  return file;
}

export function validateEnforceState(file: EnforceStateFile): void {
  for (const key of ENFORCE_SECTION_KEYS) {
    const state = effectiveState(file, key);
    if (state === "enforce") {
      const rec = file.auditRecords[key];
      if (rec === undefined) {
        throw new SbobError(
          "ERR_ENFORCE_NOT_AUDITED",
          `section ${key} is in enforce state without an audit record — record a clean audit window first (TDS 14.6)`,
        );
      }
      if (rec.incidents !== 0) {
        throw new SbobError(
          "ERR_ENFORCE_NOT_AUDITED",
          `section ${key}: audit record shows ${rec.incidents} incident(s) — a section may only enforce after an incident-free audit window`,
        );
      }
    }
    // no skipping rungs: a section may be at most one rung above the global default
    if (STATE_RANK[state] > STATE_RANK[file.state] + 1) {
      throw new SbobError(
        "ERR_ENFORCE_STATE_INVALID",
        `section ${key} is ${state} while the file default is ${file.state} — the Monitor→Audit→Enforce ladder may not skip rungs (TDS 14)`,
      );
    }
  }
}

/** Effective state of a section (per-section override, else the file default). */
export function effectiveState(file: EnforceStateFile, section: EnforceSectionKey): EnforceStateName {
  return file.sections[section] ?? file.state;
}

/** All sections currently in the given state. */
export function sectionsInState(file: EnforceStateFile, state: EnforceStateName): EnforceSectionKey[] {
  return ENFORCE_SECTION_KEYS.filter((k) => effectiveState(file, k) === state);
}

// ---------------------------------------------------------------------------
// sbobctl enforce — CLI orchestration (mirrors transpile: parse → verify →
// lint → state-validate → codegen → write)
// ---------------------------------------------------------------------------

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { validateSbob } from "./schema.ts";
import { buildIR } from "./ir.ts";
import { lintIR } from "./lint.ts";
import { makeAllocator, parseRegistry, registryToYaml, slotFor, type SlotRegistry } from "./ruleids.ts";
import { makeVerifier } from "./signature.ts";
import { generateEnforceBundle, type EnforceTarget } from "./codegen/enforcement.ts";
import type { BundleFile } from "./codegen/linux.ts";

export interface EnforceCliOptions {
  registryPath: string;
  outDir: string;
  target: EnforceTarget;
  statePath: string;
  enforcedNpPath: string;
  skipSignatureVerify: boolean;
  confirmNone: string[];
}

export interface EnforceCliResult {
  workload: string;
  slot: number;
  files: string[];
  enforcing: string[];
  npDrift: number;
  registryUpdated: boolean;
  registryYaml: string;
}

export async function runEnforce(sbobPath: string, opts: EnforceCliOptions): Promise<EnforceCliResult> {
  // 1. registry
  let registry: SlotRegistry;
  let registryOriginal = "";
  try {
    registryOriginal = readFileSync(opts.registryPath, "utf8");
    registry = parseRegistry(registryOriginal);
  } catch (e: any) {
    if (e !== null && typeof e === "object" && "code" in e && (e as any).code !== "ENOENT") throw e;
    registry = { slots: new Map() };
  }

  // 2. SBoB → IR (parse, verify, lint — identical pipeline to transpile)
  const verifier = makeVerifier(opts.skipSignatureVerify);
  const raw = readFileSync(sbobPath, "utf8");
  const verdict = await verifier.verify(sbobPath);
  const parsed = parseYaml(raw);
  const doc = validateSbob(parsed);
  const ir = buildIR(doc, parsed);
  lintIR(ir, { confirmNone: opts.confirmNone, requireScope: true });
  if (verdict.method === "skipped") {
    ir.coverageNotes.push(verdict.note);
  }

  // 3. state file (validates the Monitor→Audit→Enforce ladder, TDS 14.6)
  const state = parseEnforceState(readFileSync(opts.statePath, "utf8"));
  if (state.workload !== ir.workload.name) {
    throw new SbobError(
      "ERR_ENFORCE_STATE_INVALID",
      `state file is for workload "${state.workload}" but the SBoB is "${ir.workload.name}"`,
    );
  }

  // 4. optional enforced-NP diff input
  let enforcedNp: { egress: Array<Record<string, unknown>>; ingress: Array<Record<string, unknown>> } | undefined;
  if (opts.enforcedNpPath !== "") {
    const npRaw = JSON.parse(readFileSync(opts.enforcedNpPath, "utf8"));
    enforcedNp = {
      egress: (npRaw as Record<string, unknown>).egress as Array<Record<string, unknown>>,
      ingress: (npRaw as Record<string, unknown>).ingress as Array<Record<string, unknown>>,
    };
  }

  // 5. codegen + write
  const slot = slotFor(ir.workload.name, registry);
  const alloc = makeAllocator(ir.workload.name, slot);
  const result = generateEnforceBundle(ir, state, alloc, { target: opts.target, enforcedNp });
  for (const f of result.files) {
    const dest = join(opts.outDir, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.content);
  }

  // 6. registry evolution (same contract as transpile)
  const registryNew = registryToYaml(registry);

  const npDrift = result.notes.filter((n) => n.startsWith("np-diff:")).length > 0
    ? Number(/np-diff: (\d+) drifted/.exec(result.notes.find((n) => n.startsWith("np-diff:")) ?? "")?.[1] ?? 0)
    : 0;

  return {
    workload: ir.workload.name,
    slot,
    files: result.files.map((f) => f.path),
    enforcing: result.enforcing,
    npDrift,
    registryUpdated: registryNew !== registryOriginal,
    registryYaml: registryNew,
  };
}

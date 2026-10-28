/**
 * Shared helpers for the phase-2 engine codegens (Sigma, Velociraptor, MDE,
 * Falco — TDS 13, M6 / issue #7): deterministic Sigma UUIDs, wildcard → glob
 * translation, and the per-bundle manifest.
 *
 * Semantics note (documented in docs/engine-matrix.md): the phase-2 engines
 * enforce allowlists with their native matchers, whose glob semantics are
 * slightly broader than the sbobctl PCRE2 compilation (e.g. Sigma `*` may
 * cross a `/` that the ⋯ single-segment wildcard would not). Engines are
 * coverage extensions around the Wazuh primary detection bundle; every
 * semantic deviation is documented as a per-engine partial in the matrix.
 */
import { createHash } from "node:crypto";
import type { IR, PathSeg } from "../types.ts";
import { bundleVersion } from "./opshealth.ts";
import type { BundleFile } from "./linux.ts";

// ---------------------------------------------------------------------------
// Deterministic Sigma rule UUIDs (RFC 4122 v5, SHA-1, DNS-style namespace)
// ---------------------------------------------------------------------------

const SIGMA_NS = "sbobctl.sigma.billofbehavior.com";

function sha1(bytes: Uint8Array): Uint8Array {
  // Node crypto returns a Buffer; typed access keeps this environment-neutral.
  return new Uint8Array(createHash("sha1").update(bytes).digest());
}

/** RFC 4122 name-based (v5) UUID over a fixed sbobctl namespace. */
export function uuid5(name: string): string {
  const enc = new TextEncoder();
  const bytes = sha1(enc.encode(SIGMA_NS + name)).slice(0, 16); // 16 bytes → 32 hex chars
  bytes[6] = (bytes[6]! & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // RFC variant
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ---------------------------------------------------------------------------
// Wildcard AST → glob translation (Sigma/Falco matchers)
// ---------------------------------------------------------------------------

/**
 * Translate compiled path segments into a glob for engines whose matchers do
 * not run the sbobctl PCRE2 compilation: literal → literal, ⋯ (exactly one
 * segment) → `*`, star-mid/star-tail → `*` (documented broadening: engine
 * globs may cross `/` where the SBoB wildcard would not).
 */
export function pathGlob(segs: PathSeg[]): string {
  return (
    "/" +
    segs
      .map((seg) => {
        switch (seg.kind) {
          case "literal":
            return seg.text;
          case "one":
          case "starMid":
          case "starTail":
            return "*";
        }
      })
      .join("/")
  );
}

/**
 * DNS pattern (SBoB wildcards, possibly trailing dot) → engine glob.
 * `*.api.stripe.com.` → `*.api.stripe.com*` — the trailing `*` tolerates the
 * trailing dot that the SBoB DNS convention carries.
 */
export function dnsGlob(pattern: string): string {
  let g = pattern.replace(/\.$/, "");
  if (!g.includes("*")) g = "*" + g;
  return g + "*";
}

// ---------------------------------------------------------------------------
// Engine bundle manifest
// ---------------------------------------------------------------------------

export interface EngineManifest {
  workload: IR["workload"];
  target: string;
  sbobVersion: string;
  imageID: string;
  bundleVersion: string;
  files: string[];
  coverageNotes: string[];
  labValidation: "pending";
}

/** Append the standard per-workload manifest to an engine bundle. */
export function engineManifest(
  ir: IR,
  target: string,
  files: BundleFile[],
  extraNotes: string[],
): void {
  files.push({
    path: `${ir.workload.name}.manifest.json`,
    content:
      JSON.stringify(
        {
          workload: ir.workload,
          target,
          sbobVersion: ir.workload.sbobVersion,
          imageID: ir.workload.imageID,
          bundleVersion: bundleVersion(ir),
          files: files.map((f) => f.path),
          coverageNotes: extraNotes,
          labValidation: "pending",
        },
        null,
        2,
      ) + "\n",
  });
}

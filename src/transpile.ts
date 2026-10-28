/**
 * Transpile orchestration: SBoB files -> linted IR -> target bundle (TDS 3.1).
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { parseYaml } from "./yaml.ts";
import { validateSbob } from "./schema.ts";
import { buildIR } from "./ir.ts";
import { lintIR } from "./lint.ts";
import { makeAllocator, parseRegistry, registryToYaml, slotFor, type SlotRegistry } from "./ruleids.ts";
import { makeVerifier, type SignatureVerifier } from "./signature.ts";
import { generateLinuxBundle, type BundleFile } from "./codegen/linux.ts";
import { generateWindowsBundle } from "./codegen/windows.ts";
import { generateK8sNodeBundle } from "./codegen/k8s.ts";
import type { IR } from "./types.ts";

export interface TranspileOptions {
  registryPath: string;
  outDir: string;
  target: "linux" | "windows" | "k8s-node";
  skipSignatureVerify: boolean;
  confirmNone: string[];
}

export interface TranspileResult {
  workloads: Array<{ name: string; slot: number; files: string[] }>;
  registryUpdated: boolean;
  registryYaml: string;
}

export async function transpile(sbobPaths: string[], opts: TranspileOptions): Promise<TranspileResult> {
  const verifier = makeVerifier(opts.skipSignatureVerify);

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

  // 2. parse, verify, lint each SBoB
  const irs: IR[] = [];
  for (const p of sbobPaths) {
    const raw = readFileSync(p, "utf8");
    const verdict = await verifier.verify(p);
    const parsed = parseYaml(raw);
    const doc = validateSbob(parsed);
    const ir = buildIR(doc, parsed);
    lintIR(ir, { confirmNone: opts.confirmNone, requireScope: true });
    if (verdict.method === "skipped") {
      ir.coverageNotes.push(verdict.note);
    }
    irs.push(ir);
  }

  // duplicate workload names across inputs are an ID collision
  const names = new Set<string>();
  for (const ir of irs) {
    if (names.has(ir.workload.name)) {
      throw new Error(`duplicate workload "${ir.workload.name}" in input set`);
    }
    names.add(ir.workload.name);
  }

  // 3. codegen
  const allFiles: BundleFile[] = [];
  const workloads: TranspileResult["workloads"] = [];
  for (const ir of irs) {
    const slot = slotFor(ir.workload.name, registry);
    const alloc = makeAllocator(ir.workload.name, slot);
    const files =
      opts.target === "linux"
        ? generateLinuxBundle(ir, alloc)
        : opts.target === "windows"
          ? generateWindowsBundle(ir, alloc)
          : generateK8sNodeBundle(ir, alloc);
    for (const f of files) allFiles.push(f);
    workloads.push({ name: ir.workload.name, slot, files: files.map((f) => f.path) });
  }

  // 4. checksums
  const checksumLines = allFiles
    .map((f) => `${createHash("sha256").update(f.content).digest("hex")}  ${f.path}`)
    .sort((a, b) => a.slice(64).localeCompare(b.slice(64)));
  allFiles.push({ path: "checksums.txt", content: checksumLines.join("\n") + "\n" });

  // 5. write bundle
  for (const f of allFiles) {
    const dest = join(opts.outDir, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.content);
  }

  // 6. registry evolution
  const registryNew = registryToYaml(registry);
  const registryUpdated = registryNew !== registryOriginal;

  return { workloads, registryUpdated, registryYaml: registryNew };
}

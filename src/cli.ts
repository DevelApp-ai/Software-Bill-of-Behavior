/**
 * sbobctl CLI — zero-dependency SBoB transpiler (transpile + validate).
 *
 * Usage:
 *   node src/cli.ts transpile --sbob <file.yaml> [--sbob <file2.yaml>]
 *         [--registry docs/sbob-registry.yaml] [--out dist/bundle]
 *         [--target linux|windows] [--skip-signature-verify] [--confirm-none execs,opens]
 *   node src/cli.ts validate --sbob <file.yaml> [--confirm-none execs,opens]
 */
import { readFileSync } from "node:fs";
import { exit } from "node:process";
import { SbobError } from "./errors.ts";
import { parseYaml } from "./yaml.ts";
import { validateSbob } from "./schema.ts";
import { buildIR } from "./ir.ts";
import { lintIR } from "./lint.ts";
import { transpile } from "./transpile.ts";

function usage(): never {
  console.error(`usage: sbobctl <command> [options]

commands:
  transpile  generate a Wazuh detection bundle from one or more SBoB files
  validate   parse, schema-check and lint an SBoB without emitting artifacts

options:
  --sbob <path>                 SBoB YAML file (repeatable for transpile)
  --registry <path>             workload slot registry (default docs/sbob-registry.yaml)
  --out <dir>                   bundle output directory (default dist/bundle)
  --target <name>               codegen target: linux (M1), windows (M2)
  --skip-signature-verify       skip SBoB signature verification (development profiles only)
  --confirm-none <section,...>  accept explicitly-empty (NONE) sections
`);
  exit(2);
}

interface Args {
  command: string;
  sbob: string[];
  registry: string;
  out: string;
  target: string;
  skipSignatureVerify: boolean;
  confirmNone: string[];
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: argv[0] ?? "",
    sbob: [],
    registry: "docs/sbob-registry.yaml",
    out: "dist/bundle",
    target: "linux",
    skipSignatureVerify: false,
    confirmNone: [],
  };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const next = (): string => {
      i++;
      if (i >= argv.length) usage();
      return argv[i] as string;
    };
    if (a === "--sbob") args.sbob.push(next());
    else if (a === "--registry") args.registry = next();
    else if (a === "--out") args.out = next();
    else if (a === "--target") args.target = next();
    else if (a === "--skip-signature-verify") args.skipSignatureVerify = true;
    else if (a === "--confirm-none") {
      args.confirmNone = next().split(",").map((s) => s.trim()).filter(Boolean);
    } else {
      console.error(`unknown option: ${a}`);
      usage();
    }
  }
  return args;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0) usage();
  const args = parseArgs(argv);

  try {
    if (args.command === "transpile") {
      if (args.sbob.length === 0) usage();
      if (args.target !== "linux" && args.target !== "windows") {
        console.error(`target "${args.target}" is not available (targets: linux, windows)`);
        exit(2);
      }
      const result = await transpile(args.sbob, {
        registryPath: args.registry,
        outDir: args.out,
        target: args.target as "linux" | "windows",
        skipSignatureVerify: args.skipSignatureVerify,
        confirmNone: args.confirmNone,
      });
      for (const w of result.workloads) {
        console.log(`workload ${w.name} (slot ${w.slot}): ${w.files.length} files`);
        for (const f of w.files) console.log(`  ${f}`);
      }
      if (result.registryUpdated) {
        console.log("registry updated; commit the new docs/sbob-registry.yaml:");
        console.log(result.registryYaml);
      }
    } else if (args.command === "validate") {
      if (args.sbob.length !== 1) usage();
      const raw = readFileSync(args.sbob[0] as string, "utf8");
      const parsed = parseYaml(raw);
      const doc = validateSbob(parsed);
      const ir = buildIR(doc, parsed);
      lintIR(ir, { confirmNone: args.confirmNone, requireScope: true });
      console.log(`OK: ${doc.metadata.name} (${doc.metadata.namespace}) image ${doc.spec.imageID}`);
      for (const note of ir.coverageNotes) console.log(`  note: ${note}`);
    } else {
      usage();
    }
  } catch (e) {
    if (e instanceof SbobError) {
      console.error(e.message);
      exit(1);
    }
    throw e;
  }
}

void main();

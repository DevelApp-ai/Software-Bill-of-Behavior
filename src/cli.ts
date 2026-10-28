/**
 * sbobctl CLI — zero-dependency SBoB transpiler (transpile + validate + diff).
 *
 * Usage:
 *   node src/cli.ts transpile --sbob <file.yaml> [--sbob <file2.yaml>]
 *         [--registry docs/sbob-registry.yaml] [--out dist/bundle]
 *         [--target linux|windows|k8s-node|sigma|velociraptor|mde|falco]
 *         [--skip-signature-verify] [--confirm-none execs,opens]
 *   node src/cli.ts validate --sbob <file.yaml> [--confirm-none execs,opens]
 *   node src/cli.ts diff --old <a.yaml> --new <b.yaml>
 *         [--report <path>] [--fail-on none|advisory|mandatory]
 *         [--namespace <dir>] [--internal-suffix <suffix>]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { exit } from "node:process";
import { SbobError } from "./errors.ts";
import { parseYaml } from "./yaml.ts";
import { validateSbob } from "./schema.ts";
import { buildIR } from "./ir.ts";
import { lintIR } from "./lint.ts";
import { transpile } from "./transpile.ts";
import { runEnforce } from "./enforce.ts";
import { diffSbobs, formatDiffReport, type GateVerdict } from "./diffgate.ts";

function usage(): never {
  console.error(`usage: sbobctl <command> [options]

commands:
  transpile  generate a Wazuh detection bundle from one or more SBoB files
  validate   parse, schema-check and lint an SBoB without emitting artifacts
  diff       semantic SBoB release diff with scored delta ladder (M8)
  enforce    generate the Phase-3 enforcement bundle from an SBoB + rollout
             state file (seccomp/AppArmor/NetworkPolicy/AppLocker + active
             responses, Monitor->Audit->Enforce gated, M7)

options:
  --sbob <path>                 SBoB YAML file (repeatable for transpile)
  --registry <path>             workload slot registry (default docs/sbob-registry.yaml)
  --out <dir>                   bundle output directory (default dist/bundle)
  --target <name>               codegen target: linux (M1), windows (M2), k8s-node (M3),
                                 sigma / velociraptor / mde / falco (M6, TDS 13)
  --skip-signature-verify       skip SBoB signature verification (development profiles only)
  --confirm-none <section,...>  accept explicitly-empty (NONE) sections
  --state <path>                 (enforce) per-workload rollout state file (TDS 14)
  --enforced-np <path>           (enforce) peers JSON of the live NetworkPolicy (np-diff, TDS 14.4)
  --old <path>                  (diff) prior-release SBoB YAML
  --new <path>                  (diff) next-release SBoB YAML
  --report <path>               (diff) write the machine-readable JSON delta report here
  --fail-on <level>             (diff) exit non-zero at this verdict or above:
                                 none (always 0) | advisory | mandatory (default)
  --namespace <dir>             (diff) package-namespace dir for exec scoring (repeatable;
                                 default: inferred from parent dirs of prior exact execs)
  --internal-suffix <suffix>    (diff) extra internal DNS suffix (repeatable; defaults:
                                 svc, cluster.local, internal, local)
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
  oldSbob: string;
  newSbob: string;
  report: string;
  failOn: string;
  namespaces: string[];
  internalSuffixes: string[];
  statePath: string;
  enforcedNpPath: string;
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
    oldSbob: "",
    newSbob: "",
    report: "",
    failOn: "mandatory",
    namespaces: [],
    internalSuffixes: [],
    statePath: "",
    enforcedNpPath: "",
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
    } else if (a === "--old") args.oldSbob = next();
    else if (a === "--new") args.newSbob = next();
    else if (a === "--report") args.report = next();
    else if (a === "--fail-on") {
      args.failOn = next();
      if (args.failOn !== "none" && args.failOn !== "advisory" && args.failOn !== "mandatory") usage();
    } else if (a === "--namespace") args.namespaces.push(next());
    else if (a === "--internal-suffix") args.internalSuffixes.push(next());
    else if (a === "--state") args.statePath = next();
    else if (a === "--enforced-np") args.enforcedNpPath = next();
    else {
      console.error(`unknown option: ${a}`);
      usage();
    }
  }
  return args;
}

function verdictRank(v: GateVerdict): number {
  return v === "mandatory" ? 2 : v === "advisory" ? 1 : 0;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0) usage();
  const args = parseArgs(argv);

  try {
    if (args.command === "transpile") {
      if (args.sbob.length === 0) usage();
      const KNOWN_TARGETS = ["linux", "windows", "k8s-node", "sigma", "velociraptor", "mde", "falco"] as const;
      if (!(KNOWN_TARGETS as readonly string[]).includes(args.target)) {
        console.error(`target "${args.target}" is not available (targets: ${KNOWN_TARGETS.join(", ")})`);
        exit(2);
      }
      const result = await transpile(args.sbob, {
        registryPath: args.registry,
        outDir: args.out,
        target: args.target as "linux" | "windows" | "k8s-node" | "sigma" | "velociraptor" | "mde" | "falco",
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
    } else if (args.command === "diff") {
      if (args.oldSbob === "" || args.newSbob === "") usage();
      const load = (path: string) => {
        const raw = readFileSync(path, "utf8");
        return validateSbob(parseYaml(raw));
      };
      const result = diffSbobs(load(args.oldSbob), load(args.newSbob), {
        namespaces: args.namespaces,
        internalSuffixes: args.internalSuffixes,
      });
      if (args.report !== "") {
        writeFileSync(args.report, JSON.stringify(result, null, 2) + "\n");
      }
      console.log(formatDiffReport(result));
      const failRank = args.failOn === "none" ? Number.POSITIVE_INFINITY : args.failOn === "advisory" ? 1 : 2;
      if (verdictRank(result.verdict) >= failRank) {
        exit(1);
      }
    } else if (args.command === "enforce") {
      if (args.sbob.length !== 1) usage();
      if (args.statePath === "") usage();
      const ENFORCE_TARGETS = ["linux", "windows", "k8s-node"] as const;
      if (!(ENFORCE_TARGETS as readonly string[]).includes(args.target)) {
        console.error(`target "${args.target}" is not available (enforce targets: ${ENFORCE_TARGETS.join(", ")})`);
        exit(2);
      }
      const result = await runEnforce(args.sbob[0] as string, {
        registryPath: args.registry,
        outDir: args.out,
        target: args.target as "linux" | "windows" | "k8s-node",
        statePath: args.statePath,
        enforcedNpPath: args.enforcedNpPath,
        skipSignatureVerify: args.skipSignatureVerify,
        confirmNone: args.confirmNone,
      });
      console.log(`workload ${result.workload} (slot ${result.slot}): ${result.files.length} files`);
      for (const f of result.files) console.log(`  ${f}`);
      if (result.enforcing.length > 0) {
        console.log(`enforcing sections: ${result.enforcing.join(", ")}`);
      } else {
        console.log("enforcing sections: none (monitor/audit only)");
      }
      if (result.registryUpdated) {
        console.log("registry updated; commit the new docs/sbob-registry.yaml:");
        console.log(result.registryYaml);
      }
      if (result.npDrift > 0) {
        console.error(`np-diff: ${result.npDrift} drifted NetworkPolicy rules`);
        exit(1);
      }
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

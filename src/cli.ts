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
 *   node src/cli.ts profile --events <events.jsonl> --workload <name> --image <imageID>
 *         [--k8s-namespace <ns>] [--window-days <N>] [--out-dir <dir>]
 *         [--dispositions <file>] [--incident <workload>] [--baseline <sbob.yaml>]
 *         [--steady-cutoff <f>] [--sporadic-cutoff <f>] [--cadence-tolerance <f>]
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { exit } from "node:process";
import { SbobError } from "./errors.ts";
import { parseYaml } from "./yaml.ts";
import { validateSbob } from "./schema.ts";
import { buildIR } from "./ir.ts";
import { lintIR } from "./lint.ts";
import { transpile } from "./transpile.ts";
import { diffSbobs, formatDiffReport, type GateVerdict } from "./diffgate.ts";
import {
  parseEventStream, profileEvents,
  DEFAULT_WINDOW_DAYS, STEADY_CUTOFF_DEFAULT, SPORADIC_CUTOFF_DEFAULT, CADENCE_TOLERANCE_DEFAULT,
  type DispositionFile,
} from "./profiler.ts";

function usage(): never {
  console.error(`usage: sbobctl <command> [options]

commands:
  transpile  generate a Wazuh detection bundle from one or more SBoB files
  validate   parse, schema-check and lint an SBoB without emitting artifacts
  diff       semantic SBoB release diff with scored delta ladder (M8)
  profile    derive a candidate SBoB + provenance from an sbob.* event window (M9)

options:
  --sbob <path>                 SBoB YAML file (repeatable for transpile)
  --registry <path>             workload slot registry (default docs/sbob-registry.yaml)
  --out <dir>                   bundle output directory (default dist/bundle)
  --target <name>               codegen target: linux (M1), windows (M2), k8s-node (M3),
                                 sigma / velociraptor / mde / falco (M6, TDS 13)
  --skip-signature-verify       skip SBoB signature verification (development profiles only)
  --confirm-none <section,...>  accept explicitly-empty (NONE) sections
  --old <path>                  (diff) prior-release SBoB YAML
  --new <path>                  (diff) next-release SBoB YAML
  --report <path>               (diff) write the machine-readable JSON delta report here
  --fail-on <level>             (diff) exit non-zero at this verdict or above:
                                 none (always 0) | advisory | mandatory (default)
  --namespace <dir>             (diff) package-namespace dir for exec scoring (repeatable;
                                 default: inferred from parent dirs of prior exact execs)
  --internal-suffix <suffix>    (diff) extra internal DNS suffix (repeatable; defaults:
                                 svc, cluster.local, internal, local)
  --events <path>               (profile) normalized sbob.* event stream (JSONL)
  --workload <name>             (profile) workload to profile from the stream
  --image <imageID>             (profile) container image reference for the candidate
  --k8s-namespace <ns>          (profile) metadata.namespace for the candidate (default: default)
  --window-days <N>             (profile) observation window length written on the
                                 candidate (default 30; must span the slowest
                                 legitimate cadence plus one full drill cycle)
  --out-dir <dir>               (profile) output directory (default dist/profile);
                                 writes <workload>.candidate.yaml and <workload>.provenance.json
  --dispositions <file>         (profile) reviewer dispositions JSON (declare|hold|
                                 exempt-with-expiry|investigate; overrides require a reason)
  --incident <workload>         (profile) workload with an open incident label (repeatable);
                                 quarantined from the review queue until remediated
  --baseline <path>             (profile) prior-release SBoB; runs the M8 diff gate
                                 baseline → candidate and attaches the delta
  --steady-cutoff <f>           (profile) dayRatio at or above → steady (default 0.5)
  --sporadic-cutoff <f>         (profile) dayRatio below → sporadic (default 0.05)
  --cadence-tolerance <f>       (profile) day-gap regularity band for periodic (default 0.25)
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
  events: string;
  profWorkload: string;
  image: string;
  k8sNamespace: string;
  windowDays: number;
  outDir: string;
  dispositions: string;
  incidents: string[];
  baseline: string;
  steadyCutoff: number;
  sporadicCutoff: number;
  cadenceTolerance: number;
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
    events: "",
    profWorkload: "",
    image: "",
    k8sNamespace: "default",
    windowDays: DEFAULT_WINDOW_DAYS,
    outDir: "dist/profile",
    dispositions: "",
    incidents: [],
    baseline: "",
    steadyCutoff: STEADY_CUTOFF_DEFAULT,
    sporadicCutoff: SPORADIC_CUTOFF_DEFAULT,
    cadenceTolerance: CADENCE_TOLERANCE_DEFAULT,
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
    else if (a === "--events") args.events = next();
    else if (a === "--workload") args.profWorkload = next();
    else if (a === "--image") args.image = next();
    else if (a === "--k8s-namespace") args.k8sNamespace = next();
    else if (a === "--window-days") {
      const d = next();
      if (!/^\d+$/.test(d) || Number(d) < 1) usage();
      args.windowDays = Number(d);
    } else if (a === "--out-dir") args.outDir = next();
    else if (a === "--dispositions") args.dispositions = next();
    else if (a === "--incident") args.incidents.push(next());
    else if (a === "--baseline") args.baseline = next();
    else if (a === "--steady-cutoff") args.steadyCutoff = Number(next());
    else if (a === "--sporadic-cutoff") args.sporadicCutoff = Number(next());
    else if (a === "--cadence-tolerance") args.cadenceTolerance = Number(next());
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
    } else if (args.command === "profile") {
      if (args.events === "" || args.profWorkload === "" || args.image === "") usage();
      const stream = parseEventStream(readFileSync(args.events, "utf8"));
      let dispositions: DispositionFile | undefined;
      if (args.dispositions !== "") {
        try {
          dispositions = JSON.parse(readFileSync(args.dispositions, "utf8")) as DispositionFile;
        } catch (e) {
          if (e instanceof SbobError) throw e;
          throw new SbobError("ERR_PROFILE_DISPOSITION", "dispositions file is not valid JSON: " + (e as Error).message);
        }
      }
      let baseline: ReturnType<typeof validateSbob> | undefined;
      if (args.baseline !== "") {
        baseline = validateSbob(parseYaml(readFileSync(args.baseline, "utf8")));
      }
      const result = profileEvents(stream, {
        workload: args.profWorkload,
        imageID: args.image,
        k8sNamespace: args.k8sNamespace,
        windowDays: args.windowDays,
        incidents: args.incidents,
        dispositions,
        baseline,
        steadyCutoff: args.steadyCutoff,
        sporadicCutoff: args.sporadicCutoff,
        cadenceTolerance: args.cadenceTolerance,
      });
      mkdirSync(args.outDir, { recursive: true });
      writeFileSync(args.outDir + "/" + args.profWorkload + ".provenance.json", result.provenanceJson);
      if (result.candidateYaml !== undefined) {
        writeFileSync(args.outDir + "/" + args.profWorkload + ".candidate.yaml", result.candidateYaml);
      }
      console.log(result.reviewReport);
      if (result.status !== "candidate") {
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

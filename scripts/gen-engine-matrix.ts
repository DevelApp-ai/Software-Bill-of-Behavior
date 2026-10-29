/**
 * Dev-time generator for docs/engine-matrix.md (M6 / issue #7, TDS 13).
 *
 * Reads docs/attack-matrix.md (wazuh detection + coverage class per attack)
 * and emits the per-engine blind-spot matrix for the phase-2 codegen
 * targets (sigma-win, sigma-linux, mde, falco, velociraptor, logpoint). Engine cells
 * mirror the wazuh semantics: a row wazuh detects through the exec/open/
 * connect components (100011/100021/100031) is visible to the engines that
 * implement the same component; rows with no component stay blind unless
 * FILELESS-EXE (memfd exec-path never matches the allowlist). Regenerate:
 *
 *   node scripts/gen-engine-matrix.ts
 *
 * Statuses are detect / partial / blind / n-a; the CI gate
 * (scripts/engine-matrix-check.ts) re-checks the committed doc.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { parseMatrixRows } from "../src/attackcheck.ts";

const matrix = parseMatrixRows(readFileSync("docs/attack-matrix.md", "utf8"));

/** wazuh detection components present in the row (signature/overlay ids such as 100003/10006x are wazuh-side only and do not count). */
function components(detection: string): { exec: boolean; open: boolean; connect: boolean } {
  return {
    exec: /100011/.test(detection),
    open: /100021/.test(detection),
    connect: /100031/.test(detection),
  };
}

function cellFor(cls: string, detection: string): { sl: string; mde: string; falco: string; vel: string; lp: string; note: string } {
  const c = components(detection);
  const fileless = cls.includes("FILELESS-EXE");
  const any = c.exec || c.open || c.connect || fileless;

  if (!any) {
    return {
      sl: "blind",
      mde: "blind",
      falco: "blind",
      vel: "blind",
      lp: "blind",
      note: "in-process app-plane activity — documented blind (BLIND-L7, TDS 13)",
    };
  }

  // velociraptor: pslist sweep detects execs (hunt-time), netstat sweep sees
  // established connections only; no v1 open-file sweep.
  let vel = "blind";
  if (c.exec || fileless) vel = "detect";
  else if (c.connect) vel = "partial";

  // mde: DeviceProcessEvents/DeviceNetworkEvents detect exec/connect;
  // DeviceFileEvents sees file-created only (partial for open).
  let mde = "blind";
  if (c.exec || c.connect || fileless) mde = "detect";
  else if (c.open) mde = "partial";

  // logpoint: v1 consumes the same auditd plane as sigma-linux — exec/open
  // rules match the normalized path field; connect rules ride raw
  // daddr/dport fields LogPoint's auditd taxonomy does not normalize.
  let lp = "blind";
  if (c.exec || c.open || fileless) lp = "detect";
  else if (c.connect) lp = "partial";

  return {
    sl: "detect",
    mde,
    falco: "detect",
    vel,
    lp,
    note: "",
  };
}

const perRowNotes: Record<number, string> = {
  5: "exec variant detect; in-process Lua variant stays BLIND-L7",
  7: "memfd exec-path never matches the allowlist; execution-from-memory sig (100063) is wazuh-side",
  10: "RESP blind in-process; the write lands on SAVE (100021 semantics)",
  22: "getent exec detect; resolved DNS name itself blind in engines",
  23: "beacon exec detect; the DNS channel itself is blind (DNS-NAME)",
  25: "miner exec detect; resolved DNS name itself blind in engines",
  27: "in-process Lua blind; file side-effects only (100021)",
  32: "MODULE LOAD dlopen in-process; M4-PENDING via capabilities",
  42: "ptrace sig (100062) is wazuh-side; engines see exec/open",
  44: "RESP blind in-process; the write lands on SAVE (100021 semantics)",
  50: "k8s API plane covered by wazuh 100064/100003; engines see exec/open",
  51: "init_module sig (100060) is wazuh-side; engines see the exec",
  52: "bpf syscall signal M4-PENDING; engines see the exec",
  54: "mount syscall signal M4-PENDING; engines see the exec",
  59: "namespace-change sig (100061) is wazuh-side; engines see the exec",
  60: "process-tracing sig (100062) is wazuh-side; engines see the exec",
};

const defaultNotes: Record<string, string> = {
  EXEC: "execve off-allowlist (100011 semantics)",
  OPEN: "open/openat (100021 semantics); MDE file-create only, no velociraptor v1 sweep",
  CONNECT: "connect off-allowlist (100031 semantics); velociraptor netstat sweep sees established state only; logpoint matches raw auditd daddr/dport (taxonomy-unnormalized) — partial",
};

function noteFor(cls: string, detection: string): string {
  const c = components(detection);
  if (c.exec && c.connect && !c.open) return defaultNotes.CONNECT;
  if (c.exec) return defaultNotes.EXEC;
  if (c.open) return defaultNotes.OPEN;
  if (c.connect) return defaultNotes.CONNECT;
  return "";
}

const lines: string[] = [];
lines.push("# Phase-2 engine blind-spot matrix");
lines.push("");
lines.push(
  "Per-engine coverage of the upstream kill-chain suite " +
    "(docs/upstream-redis-attacks.yaml) by the phase-2 codegen targets " +
    "(M6, issue #7): sigma-windows, sigma-linux, Microsoft Defender for " +
    "Endpoint (MDE) KQL, Falco, Velociraptor and LogPoint artifacts.",
);
lines.push("");
lines.push(
  "This matrix is the TDS 13 acceptance artifact: no attack may be blind " +
    "everywhere unless the blind spot is already a documented class in " +
    "docs/attack-matrix.md (BLIND-L7, DNS-NAME, M4-PENDING, FILELESS-EXE, " +
    "K8S-API). The committed table is re-checked in CI by " +
    "scripts/engine-matrix-check.ts; regenerate it with " +
    "scripts/gen-engine-matrix.ts after changing the attack matrix.",
);
lines.push("");
lines.push("Status semantics:");
lines.push("");
lines.push("- `detect` — the engine's generated artifact fires on the attack class (equivalent to the wazuh 100011/100021/100031 semantics).");
lines.push("- `partial` — the engine detects a subset of the class (e.g. file-create events only, established-state sweep only).");
lines.push("- `blind` — the engine's shipped artifact set cannot see this class.");
lines.push("- `n-a` — the engine plane does not apply (the sigma-windows pack targets Windows-host SBoBs; this suite runs on linux/k8s nodes, so those cells are `n-a` — windows-plane capabilities for file/DNS classes are noted per row).");
lines.push("");
lines.push("Cells describe the shipped M6 artifact set, not what an engine could theoretically do with hand-written content.");
lines.push("");
lines.push("| # | attack | sigma-win | sigma-linux | mde | falco | velociraptor | logpoint | notes |");
lines.push("|---|--------|----------|-------------|-----|-------|--------------|----------|-------|");

for (const [name, row] of matrix) {
  const cell = cellFor(row.coverageClass, row.detection);
  const note = perRowNotes[row.num] ?? (cell.note || noteFor(row.coverageClass, row.detection));
  lines.push(
    "| " + row.num + " | " + name + " | n-a | " + cell.sl + " | " + cell.mde + " | " + cell.falco + " | " + cell.vel + " | " + cell.lp + " | " + note + " |",
  );
}

lines.push("");
lines.push(
  "Wazuh remains the primary detection plane (docs/attack-matrix.md); this " +
    "matrix records how the phase-2 engines cover each other's blind spots " +
    "and where coverage still depends on wazuh signature rules.",
);
lines.push("");

writeFileSync("docs/engine-matrix.md", lines.join("\n"));
console.log("wrote docs/engine-matrix.md with " + matrix.size + " rows");

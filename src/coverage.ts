/**
 * Machine-generated coverage matrix (TDS §8, M4 / issue #5).
 *
 * One row per canonical SBoB coverage surface (sections + the eight
 * rulePolicies generalized rules from TDS 7.4), one column per Phase-1
 * target (linux, windows, k8s). Cell statuses:
 *
 *   covered        rules emitted and evaluated from telemetry
 *   partial        rules emitted with documented limitations (reason codes)
 *   absent         section absent from this SBoB (spec 5.4: absent != NONE;
 *                  informational rule emitted so operators notice)
 *   gap            no rule exists; declared blind spot awaiting a source
 *   not-applicable the surface cannot apply (OS semantics or exemption)
 *
 * Every partial/gap/not-applicable cell carries REASON_CODES entries so the
 * gap is documented, not silent. assertCoverageComplete() is the CI gate
 * (TDS 11.4): it fails the build when a row or column is missing, a status
 * or reason code is unknown, or a limitation cell has no reason.
 */
import type { IR } from "./types.ts";

export type CoverageStatus = "covered" | "partial" | "absent" | "gap" | "not-applicable";

export interface CoverageCell {
  status: CoverageStatus;
  /** REASON_CODES keys documenting why the cell is not `covered`. */
  reasons: string[];
}

export interface CoverageRow {
  section: string;
  cells: { linux: CoverageCell; windows: CoverageCell; k8s: CoverageCell };
}

export interface CoverageMatrix {
  workload: string;
  rows: CoverageRow[];
}

export const REASON_CODES: Record<string, string> = {
  SECTION_ABSENT: "section absent from the SBoB (spec 5.4: absent is not NONE; informational rule emitted)",
  ARGS_WIN_CMDLINE: "Windows args drift is heuristic-equivalent — CommandLine tokenization, not argv (TDS 7.3.4)",
  OPEN_CREATE_ONLY_WIN: "Sysmon EID 11 covers file-create only; broad read-open telemetry does not exist (TDS 8.2)",
  FLAGS_DEFERRED: "opens[].flags child rules deferred (flag bitmask recorded; TDS 6.4)",
  DNS_NODE_BLIND: "DNS names are not observable from node auditd telemetry; Windows agents cover via Sysmon EID 22 (TDS 8)",
  K8SPEER_PHASE3: "podSelector/namespaceSelector entries deferred to the Phase-3 NetworkPolicy diff (TDS 14.3)",
  INGRESS_ACCEPT_WEAK: "Linux accept() telemetry cannot attribute peers; host-firewall ingestion recommended (TDS 8)",
  ENDPOINTS_L7: "HTTP endpoints[] require an L7 source (proxy access logs / Suricata EVE); Phase 2 (TDS 13)",
  CAPS_PENDING: "capabilities[] rules are not yet implemented (baseline capset audit, M4-PENDING)",
  SIG_WIN_DEFERRED: "Windows signature-rule equivalent (Sysmon EID) deferred to a later milestone (TDS 7.4)",
  SIG_CORRELATE: "cross-event correlation delivered as a triage informational rule, not a single-event rule (TDS 7.4)",
  SIG_PARENT_REQUIRED: "overlay requires its parent drift rule; the parent section is absent from this SBoB",
  SIG_MANAGER_JSON: "manager-side JSON rule evaluates the k8s API audit log (TDS 4.4), not node telemetry",
  SIG_SADDR_PENDING: "connect-side evaluation depends on the saddr decoder work item (TDS 7.3.1)",
  SIG_EXEMPT_SUPPRESSED: "containerAllowed=true suppressed rule emission for this workload (spec 4.8: not a deny)",
  SIG_NODE_SCOPED: "node-scoped Mode B audit key — attribution-weak; exempt legitimate actors via processAllowed",
};

/** The canonical coverage surfaces: 10 section rows + 8 rulePolicies rows. */
export const COVERAGE_SECTIONS: string[] = [
  "execs.path",
  "execs.args",
  "opens.path",
  "opens.flags",
  "egress.ipAddresses",
  "egress.dnsNames",
  "egress.selector",
  "ingress.listener",
  "capabilities",
  "endpoints",
  "rulePolicies.module-load",
  "rulePolicies.namespace-change",
  "rulePolicies.process-tracing",
  "rulePolicies.execution-from-memory",
  "rulePolicies.sensitive-file-access",
  "rulePolicies.service-account-token-access",
  "rulePolicies.kubernetes-api-access",
  "rulePolicies.binary-not-in-container-image",
];

type Targets = "linux" | "windows" | "k8s";

function cell(status: CoverageStatus, reasons: string[] = []): CoverageCell {
  return { status, reasons };
}

function absentAll(): { linux: CoverageCell; windows: CoverageCell; k8s: CoverageCell } {
  const c = () => cell("absent", ["SECTION_ABSENT"]);
  return { linux: c(), windows: c(), k8s: c() };
}

/**
 * Build the full section × target matrix for one workload IR. The matrix is
 * embedded in every target manifest (linux, windows, k8s-node) — it describes
 * the workload's coverage, not the bundle that carries it.
 */
export function buildCoverageMatrix(ir: IR): CoverageMatrix {
  const s = ir.sections;
  const rows: CoverageRow[] = [];
  const hasSection = (k: "execs" | "opens" | "egress" | "ingress" | "capabilities" | "endpoints") => s[k] !== undefined;

  // execs[].path ------------------------------------------------------------
  rows.push({
    section: "execs.path",
    cells: hasSection("execs")
      ? { linux: cell("covered"), windows: cell("covered"), k8s: cell("covered") }
      : absentAll(),
  });

  // execs[].args ------------------------------------------------------------
  rows.push({
    section: "execs.args",
    cells: hasSection("execs")
      ? { linux: cell("covered"), windows: cell("partial", ["ARGS_WIN_CMDLINE"]), k8s: cell("covered") }
      : absentAll(),
  });

  // opens[].path / opens[].flags ---------------------------------------------
  rows.push({
    section: "opens.path",
    cells: hasSection("opens")
      ? { linux: cell("covered"), windows: cell("partial", ["OPEN_CREATE_ONLY_WIN"]), k8s: cell("covered") }
      : absentAll(),
  });
  rows.push({
    section: "opens.flags",
    cells: hasSection("opens")
      ? {
          linux: cell("partial", ["FLAGS_DEFERRED"]),
          windows: cell("partial", ["FLAGS_DEFERRED", "OPEN_CREATE_ONLY_WIN"]),
          k8s: cell("partial", ["FLAGS_DEFERRED"]),
        }
      : absentAll(),
  });

  // egress[].ipAddresses / dnsNames / selector -------------------------------
  const egress = s.egress;
  const egressDriftEmitted = egress !== undefined && (egress.exact.length > 0 || egress.patterns.length > 0 || egress.entries.some((e) => e.ports.length > 0));
  rows.push({
    section: "egress.ipAddresses",
    cells: hasSection("egress")
      ? {
          linux: cell("partial", ["SIG_SADDR_PENDING"]),
          windows: cell("covered"),
          k8s: cell("partial", ["SIG_SADDR_PENDING"]),
        }
      : absentAll(),
  });
  rows.push({
    section: "egress.dnsNames",
    cells: hasSection("egress")
      ? {
          linux: cell("partial", ["DNS_NODE_BLIND"]),
          windows: cell("covered"),
          k8s: cell("partial", ["DNS_NODE_BLIND"]),
        }
      : absentAll(),
  });
  const hasK8sPeer = [s.egress, s.ingress].some((sec) => sec?.entries.some((e) => e.k8sPeer) ?? false);
  rows.push({
    section: "egress.selector",
    cells: hasK8sPeer
      ? { linux: cell("not-applicable"), windows: cell("not-applicable"), k8s: cell("partial", ["K8SPEER_PHASE3"]) }
      : { linux: cell("not-applicable"), windows: cell("not-applicable"), k8s: cell("not-applicable") },
  });

  // ingress ------------------------------------------------------------------
  rows.push({
    section: "ingress.listener",
    cells: hasSection("ingress")
      ? {
          linux: cell("partial", ["INGRESS_ACCEPT_WEAK"]),
          windows: cell("covered"),
          k8s: cell("partial", ["INGRESS_ACCEPT_WEAK"]),
        }
      : absentAll(),
  });

  // capabilities / endpoints --------------------------------------------------
  rows.push({
    section: "capabilities",
    cells: hasSection("capabilities")
      ? {
          linux: cell("partial", ["CAPS_PENDING"]),
          windows: cell("not-applicable"),
          k8s: cell("partial", ["CAPS_PENDING"]),
        }
      : absentAll(),
  });
  rows.push({
    section: "endpoints",
    cells: hasSection("endpoints")
      ? {
          linux: cell("gap", ["ENDPOINTS_L7"]),
          windows: cell("gap", ["ENDPOINTS_L7"]),
          k8s: cell("gap", ["ENDPOINTS_L7"]),
        }
      : absentAll(),
  });

  // rulePolicies (TDS 7.4 generalized rules) -----------------------------------
  const suppressed = (policy: string) => ir.rulePolicies?.[policy]?.containerAllowed === true;

  // the four audit-keyed policies: linux/k8s covered (windows deferred)
  for (const policy of ["module-load", "namespace-change", "process-tracing", "execution-from-memory"] as const) {
    const winStatus: CoverageStatus = policy === "namespace-change" ? "not-applicable" : "partial";
    const winReasons = policy === "namespace-change" ? [] : ["SIG_WIN_DEFERRED"];
    const lk = suppressed(policy)
      ? cell("not-applicable", ["SIG_EXEMPT_SUPPRESSED"])
      : cell("covered", ["SIG_NODE_SCOPED"]);
    rows.push({
      section: `rulePolicies.${policy}`,
      cells: {
        linux: lk,
        windows: cell(winStatus, winReasons),
        k8s: lk,
      },
    });
  }

  // sensitive-file-access / service-account-token-access: opens-drift overlays
  const opensDrift = s.opens !== undefined;
  for (const [policy, winApplicable] of [
    ["sensitive-file-access", true],
    ["service-account-token-access", false],
  ] as const) {
    const parentReasons = opensDrift ? ["SIG_NODE_SCOPED"] : ["SIG_PARENT_REQUIRED"];
    const lkStatus: CoverageStatus = suppressed(policy)
      ? "not-applicable"
      : opensDrift
        ? "covered"
        : "partial";
    const lk = suppressed(policy) ? cell(lkStatus, ["SIG_EXEMPT_SUPPRESSED"]) : cell(lkStatus, parentReasons);
    rows.push({
      section: `rulePolicies.${policy}`,
      cells: {
        linux: lk,
        windows: winApplicable
          ? cell("partial", ["SIG_WIN_DEFERRED"])
          : cell("not-applicable"),
        k8s: lk,
      },
    });
  }

  // kubernetes-api-access: connect overlay (0,3) + manager JSON rule (6,4)
  {
    const sup = suppressed("kubernetes-api-access");
    const linuxStatus: CoverageStatus = sup ? "not-applicable" : egressDriftEmitted ? "covered" : "partial";
    const linuxReasons = sup ? ["SIG_EXEMPT_SUPPRESSED"] : egressDriftEmitted ? ["SIG_NODE_SCOPED"] : ["SIG_PARENT_REQUIRED", "SIG_MANAGER_JSON"];
    rows.push({
      section: "rulePolicies.kubernetes-api-access",
      cells: {
        linux: cell(linuxStatus, linuxReasons),
        windows: sup ? cell("not-applicable", ["SIG_EXEMPT_SUPPRESSED"]) : cell("partial", ["SIG_WIN_DEFERRED"]),
        k8s: sup ? cell("not-applicable", ["SIG_EXEMPT_SUPPRESSED"]) : cell("covered", ["SIG_MANAGER_JSON"]),
      },
    });
  }

  // binary-not-in-container-image: k8s lifecycle correlate only
  {
    const sup = suppressed("binary-not-in-container-image");
    rows.push({
      section: "rulePolicies.binary-not-in-container-image",
      cells: {
        linux: sup ? cell("not-applicable", ["SIG_EXEMPT_SUPPRESSED"]) : cell("not-applicable"),
        windows: sup ? cell("not-applicable", ["SIG_EXEMPT_SUPPRESSED"]) : cell("partial", ["SIG_WIN_DEFERRED"]),
        k8s: sup
          ? cell("not-applicable", ["SIG_EXEMPT_SUPPRESSED"])
          : cell("partial", ["SIG_CORRELATE"]),
      },
    });
  }

  return { workload: ir.workload.name, rows };
}

/**
 * CI gate (TDS 11.4): the matrix must be complete and every limitation must
 * carry a known reason code. Returns a list of problems; empty = pass.
 */
export function assertCoverageComplete(matrix: CoverageMatrix): string[] {
  const problems: string[] = [];
  const targets: Targets[] = ["linux", "windows", "k8s"];

  const seen = new Set(matrix.rows.map((r) => r.section));
  for (const section of COVERAGE_SECTIONS) {
    if (!seen.has(section)) problems.push(`missing coverage row: ${section}`);
  }
  for (const section of seen) {
    if (!COVERAGE_SECTIONS.includes(section)) problems.push(`unknown coverage row: ${section}`);
  }

  for (const row of matrix.rows) {
    for (const t of targets) {
      const c = row.cells[t];
      if (c === undefined) {
        problems.push(`${row.section}/${t}: no cell`);
        continue;
      }
      if (!["covered", "partial", "absent", "gap", "not-applicable"].includes(c.status)) {
        problems.push(`${row.section}/${t}: unknown status "${c.status}"`);
      }
      if ((c.status === "partial" || c.status === "gap") && c.reasons.length === 0) {
        problems.push(`${row.section}/${t}: ${c.status} without a reason code`);
      }
      for (const r of c.reasons) {
        if (!(r in REASON_CODES)) problems.push(`${row.section}/${t}: unknown reason code "${r}"`);
      }
    }
  }
  return problems;
}

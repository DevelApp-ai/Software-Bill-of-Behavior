/**
 * seccomp profile codegen (TDS 14.2, M7 / issue #8) — spec-sanctioned
 * syscall-surface enforcement.
 *
 * Profiles are container-global, so the blocklist is the M4 signature
 * syscall surface (module-load / namespace-change / process-tracing /
 * execution-from-memory, TDS 7.4), not the per-section allowlists:
 *
 *   enforcement/sbob/<name>/seccomp/<name>.json   OCI seccomp profile
 *     (pod securityContext.seccompProfile type Localhost, TDS 14.2)
 *   enforcement/sbob/<name>/systemd/<name>-seccomp.conf
 *     (host plane: SystemCallFilter deny-list drop-in, TDS 14.2)
 *
 * State semantics: audit → SCMP_ACT_LOG (kernel logs, allows); enforce →
 * SCMP_ACT_ERRNO (EPERM). monitor → not emitted (the enforce command skips
 * seccomp entirely while the file default is monitor). Sections are not
 * granular here: seccomp has no per-section scope, so the global file state
 * governs the whole profile (documented deviation, TDS 14.6).
 *
 * Documented v1 limitations:
 *   - processAllowed exemptions cannot be honored (seccomp is
 *     container-global, exemptions are process-scoped) — the exemption CDB
 *     lists of the detection bundle remain the escape hatch;
 *   - containerAllowed: true on a signature policy removes its syscalls
 *     from the blocklist (the SBoB declared the whole container exempt);
 *   - the blocklist is arch-independent by name; x86_64 syscall numbers
 *     are listed in the manifest notes only.
 */
import type { IR } from "../../types.ts";
import type { BundleFile } from "./linux.ts";

export interface SeccompSyscall {
  syscall: string;
  /** M4 signature policy that owns this syscall surface. */
  policy: string;
  x86_64: number;
}

export const SIGNATURE_SYSCALLS: SeccompSyscall[] = [
  { syscall: "init_module", policy: "moduleLoad", x86_64: 175 },
  { syscall: "finit_module", policy: "moduleLoad", x86_64: 313 },
  { syscall: "delete_module", policy: "moduleLoad", x86_64: 176 },
  { syscall: "unshare", policy: "namespaceChange", x86_64: 277 },
  { syscall: "setns", policy: "namespaceChange", x86_64: 308 },
  { syscall: "ptrace", policy: "processTracing", x86_64: 101 },
  { syscall: "process_vm_readv", policy: "processTracing", x86_64: 310 },
  { syscall: "process_vm_writev", policy: "processTracing", x86_64: 311 },
  { syscall: "memfd_create", policy: "executionFromMemory", x86_64: 319 },
];

export function seccompBlocklist(ir: IR): SeccompSyscall[] {
  const containerExempt = (policy: string) =>
    ir.rulePolicies?.[policy]?.containerAllowed === true;
  return SIGNATURE_SYSCALLS.filter((s) => !containerExempt(s.policy));
}

/** OCI seccomp profile (k8s pod securityContext; audit = LOG, enforce = ERRNO). */
export function seccompProfile(ir: IR, mode: "audit" | "enforce"): BundleFile {
  const name = ir.workload.name;
  const block = seccompBlocklist(ir);
  const profile = {
    defaultAction: "SCMP_ACT_ALLOW",
    defaultErrnoRet: 1,
    architectures: ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
    syscalls: [
      {
        names: block.map((s) => s.syscall),
        action: mode === "enforce" ? "SCMP_ACT_ERRNO" : "SCMP_ACT_LOG",
        errnoRet: 1,
        comment: `sbob ${name}: M4 signature syscall surface (${mode} mode; generated — do not edit by hand)`,
      },
    ],
  };
  return {
    path: `enforcement/sbob/${name}/seccomp/${name}.json`,
    content: JSON.stringify(profile, null, 2) + "\n",
  };
}

/** systemd SystemCallFilter deny-list drop-in (host plane). */
export function seccompSystemdDropin(ir: IR, mode: "audit" | "enforce"): BundleFile {
  const name = ir.workload.name;
  const block = seccompBlocklist(ir);
  const syscalls = block.map((s) => s.syscall).join(" ");
  const content = [
    `# sbobctl generated syscall-surface filter — workload: ${name} (TDS 14.2, M7)`,
    `# install as /etc/systemd/system/<unit>.d/50-sbob-${name}-seccomp.conf`,
    `# ${mode === "enforce" ? "ENFORCE: violations fail with EPERM" : "AUDIT: violations are logged, not blocked"}`,
    `[Service]`,
    `# RestrictAddressFamilies etc. stay with the unit's own hardening; this drop-in`,
    `# only pins the SBoB signature syscall surface (deny-list semantics).`,
    `SystemCallFilter=~${syscalls}`,
    ``,
  ].join("\n");
  return {
    path: `enforcement/sbob/${name}/systemd/${name}-seccomp.conf`,
    content,
  };
}

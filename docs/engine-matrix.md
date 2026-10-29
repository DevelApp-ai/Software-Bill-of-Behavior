# Phase-2 engine blind-spot matrix

Per-engine coverage of the upstream kill-chain suite (docs/upstream-redis-attacks.yaml) by the phase-2 codegen targets (M6, issue #7): sigma-windows, sigma-linux, Microsoft Defender for Endpoint (MDE) KQL, Falco, Velociraptor and LogPoint artifacts.

This matrix is the TDS 13 acceptance artifact: no attack may be blind everywhere unless the blind spot is already a documented class in docs/attack-matrix.md (BLIND-L7, DNS-NAME, M4-PENDING, FILELESS-EXE, K8S-API). The committed table is re-checked in CI by scripts/engine-matrix-check.ts; regenerate it with scripts/gen-engine-matrix.ts after changing the attack matrix.

Status semantics:

- `detect` — the engine's generated artifact fires on the attack class (equivalent to the wazuh 100011/100021/100031 semantics).
- `partial` — the engine detects a subset of the class (e.g. file-create events only, established-state sweep only).
- `blind` — the engine's shipped artifact set cannot see this class.
- `n-a` — the engine plane does not apply (the sigma-windows pack targets Windows-host SBoBs; this suite runs on linux/k8s nodes, so those cells are `n-a` — windows-plane capabilities for file/DNS classes are noted per row).

Cells describe the shipped M6 artifact set, not what an engine could theoretically do with hand-written content.

| # | attack | sigma-win | sigma-linux | mde | falco | velociraptor | logpoint | notes |
|---|--------|----------|-------------|-----|-------|--------------|----------|-------|
| 1 | recon-info-server | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 2 | recon-config-dump | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 3 | recon-client-list | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 4 | recon-keys-glob | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 5 | lua-cve-full-chain | n-a | detect | detect | detect | detect | detect | exec variant detect; in-process Lua variant stays BLIND-L7 |
| 6 | exec-whoami | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 7 | lua-fileless-memfd | n-a | detect | detect | detect | detect | detect | memfd exec-path never matches the allowlist; execution-from-memory sig (100063) is wazuh-side |
| 8 | exec-devshm | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 9 | lua-reverse-shell | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 10 | persist-config-dir | n-a | detect | partial | detect | blind | detect | RESP blind in-process; the write lands on SAVE (100021 semantics) |
| 11 | evasion-config-reset | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 12 | exec-drifted | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 13 | lua-ld-preload | n-a | detect | partial | detect | blind | detect | open/openat (100021 semantics); MDE file-create only, no velociraptor v1 sweep |
| 14 | exec-sa-token | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 15 | exec-etc-shadow | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 16 | exec-etc-passwd | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 17 | exec-symlink | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 18 | lua-credential-harvest | n-a | detect | partial | detect | blind | detect | open/openat (100021 semantics); MDE file-create only, no velociraptor v1 sweep |
| 19 | exec-proc-environ | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 20 | lateral-slaveof | n-a | detect | detect | detect | partial | partial | connect off-allowlist (100031 semantics); velociraptor netstat sweep sees established state only; logpoint matches raw auditd daddr/dport (taxonomy-unnormalized) — partial |
| 21 | lateral-slaveof-cleanup | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 22 | exec-dns-anomaly | n-a | detect | detect | detect | detect | detect | getent exec detect; resolved DNS name itself blind in engines |
| 23 | lua-dns-beacon | n-a | detect | detect | detect | detect | detect | beacon exec detect; the DNS channel itself is blind (DNS-NAME) |
| 24 | impact-flushall | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 25 | exec-crypto-dns | n-a | detect | detect | detect | detect | detect | miner exec detect; resolved DNS name itself blind in engines |
| 26 | cve-2022-0543-sandbox-escape | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 27 | cve-2022-24735-lua-poisoning | n-a | detect | partial | detect | blind | detect | in-process Lua blind; file side-effects only (100021) |
| 28 | cve-2023-28856-cluster-reset | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 29 | cve-2023-45145-socket-probe | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 30 | persist-rdb-crontab-write | n-a | detect | partial | detect | blind | detect | open/openat (100021 semantics); MDE file-create only, no velociraptor v1 sweep |
| 31 | persist-rdb-ssh-key | n-a | detect | partial | detect | blind | detect | open/openat (100021 semantics); MDE file-create only, no velociraptor v1 sweep |
| 32 | cve-module-load-probe | n-a | blind | blind | blind | blind | blind | MODULE LOAD dlopen in-process; M4-PENDING via capabilities |
| 33 | auth-brute-force-probe | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 34 | cve-2022-35951-xautoclaim | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 35 | lua-os-execute-probe | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 36 | lua-network-scan | n-a | detect | detect | detect | partial | partial | connect off-allowlist (100031 semantics); velociraptor netstat sweep sees established state only; logpoint matches raw auditd daddr/dport (taxonomy-unnormalized) — partial |
| 37 | escape-mount-enumeration | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 38 | escape-docker-socket-probe | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 39 | escape-host-etc-passwd | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 40 | escape-symlink-host-shadow | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 41 | escape-cron-stage-host-tmp | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 42 | escape-ptrace-init-maps | n-a | detect | detect | detect | detect | detect | ptrace sig (100062) is wazuh-side; engines see exec/open |
| 43 | escape-process-pivot-via-lua | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 44 | escape-rdb-write-host-tmp | n-a | blind | blind | blind | blind | blind | RESP blind in-process; the write lands on SAVE (100021 semantics) |
| 45 | escape-rdb-write-payload | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 46 | escape-rdb-save-trigger | n-a | detect | partial | detect | blind | detect | open/openat (100021 semantics); MDE file-create only, no velociraptor v1 sweep |
| 47 | escape-rdb-cleanup | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 48 | egress-rogue-master-replicaof | n-a | detect | detect | detect | partial | partial | connect off-allowlist (100031 semantics); velociraptor netstat sweep sees established state only; logpoint matches raw auditd daddr/dport (taxonomy-unnormalized) — partial |
| 49 | egress-rogue-master-restore | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 50 | k8s-api-recon | n-a | detect | detect | detect | detect | detect | k8s API plane covered by wazuh 100064/100003; engines see exec/open |
| 51 | rootkit-init-module | n-a | detect | detect | detect | detect | detect | init_module sig (100060) is wazuh-side; engines see the exec |
| 52 | rootkit-ebpf-load | n-a | detect | detect | detect | detect | detect | bpf syscall signal M4-PENDING; engines see the exec |
| 53 | persist-hardlink-shadow | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 54 | escape-mount-attempt | n-a | detect | detect | detect | detect | detect | mount syscall signal M4-PENDING; engines see the exec |
| 55 | recon-redis-cli-bigkeys | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 56 | exec-from-data-mount | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 57 | lateral-ssh-nonstandard-port | n-a | detect | detect | detect | detect | detect | connect off-allowlist (100031 semantics); velociraptor netstat sweep sees established state only; logpoint matches raw auditd daddr/dport (taxonomy-unnormalized) — partial |
| 58 | persist-ld-preload | n-a | detect | detect | detect | detect | detect | execve off-allowlist (100011 semantics) |
| 59 | escape-unshare-namespaces | n-a | detect | detect | detect | detect | detect | namespace-change sig (100061) is wazuh-side; engines see the exec |
| 60 | inject-ptrace-pid1 | n-a | detect | detect | detect | detect | detect | process-tracing sig (100062) is wazuh-side; engines see the exec |
| 61 | cleanup-config-restore-dir | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |
| 62 | cleanup-config-restore-dbfilename | n-a | blind | blind | blind | blind | blind | in-process app-plane activity — documented blind (BLIND-L7, TDS 13) |

Wazuh remains the primary detection plane (docs/attack-matrix.md); this matrix records how the phase-2 engines cover each other's blind spots and where coverage still depends on wazuh signature rules.

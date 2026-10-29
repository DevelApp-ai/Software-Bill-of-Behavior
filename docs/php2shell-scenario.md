# PHP2Shell scenario — proving the SBoB point with the October 2026 PHP RCEs

Issue [#23](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/23) validation vehicle: the two PHP RCEs disclosed on 2026-10-21 — **CVE-2026-109618** (RCE via out-of-memory corruption / longjmp) and **CVE-2026-109619** (RCE via stale global state), both CVSS v4.0 9.2, exploited in the wild since 2026-10-21 and in the CISA KEV since 2026-10-26 — mapped onto a php-fpm workload contract.

**The point:** an SBoB does not have to know the CVE. `php-fpm` is a worker process that never spawns a shell, never writes outside the session directory, and only talks to its memcache peer. Whatever the entry vector — memory corruption, stale global state, or next month's CVE — the *post-exploit behavior* is drift by definition. That is the detection story; the enforcement story (TDS 14) is that the same contract, graduated to Enforce, blocks each behavior outright.

## The workload contract

`sbobs/php-fpm.yaml` (slot 1 — rule band `1001xx`), namespace `web-tier`, digest-pinned image:

| section | declaration | drift implication |
| --- | --- | --- |
| `execs[]` | `/usr/local/sbin/php-fpm` only | **any** `/bin/sh`, `/usr/bin/curl`, … exec is drift — php-fpm never shells out |
| `opens[]` | `/var/www/html/*` (read), `/var/lib/php/sessions/*` (write), `/etc/resolv.conf` (read) | a webshell dropped in `/var/tmp` is drift |
| `egress[]` | `10.96.100.10:11211` (internal memcache) | a reverse shell to an external C2 is drift |
| `ingress[]` | `10.244.0.0/16 → :9000` (nginx frontends) | undeclared inbound peers are drift |

## CVE → behavior → rule mapping

Corpus: `test/corpus/php-{benign,drift}.audit`; lab replay: `scripts/logtest-corpus.sh php`.

| # | corpus line | CVE / rationale | rule (slot 1) | level |
| --- | --- | --- | --- | --- |
| 1 | `execve /bin/sh -c …` (`key="sbob-exec-php-fpm"`, exe off-allowlist) | CVE-2026-109618: the hijacked in-worker RCE spawns a shell — the classic PHP2Shell follow-on | **100111** undeclared process execution (T1059) | 9 (100112 sustained @ 8/120s) |
| 2 | `openat /var/tmp/.php2shell.php` O_WRONLY\|O_CREAT | the dropped webshell — `/var/tmp` is not in `opens[]`; the web root is read-only by contract | **100121** undeclared file open (T1005) | 9 (100122 sustained) |
| 3 | `connect 45.155.148.12:4444` | CVE-2026-109619: stale-global-state RCE → reverse shell / C2 callback; only memcache is declared egress | **100131** undeclared outbound connect (T1071) | 9 (100132 sustained) |
| 4 | `memfd_create` (`key="sbob-memfd"`, syscall 319) | the fileless variant: the in-worker payload stages itself in a memfd instead of dropping the webshell | **100163** execution-from-memory signature (T1620) | 10 |

Benign corpus (php-fpm master exec, app-file read, session write, resolver read, memcache connect) must stay silent — only the level-0 base chain (`100100/100110/100120/100130`) may match.

## What enforcement would have done (TDS 14, M7)

The same contract through `sbobctl enforce`, Monitor→Audit→Enforce ladder respected (`enforce` requires an incident-free audit window — state fixture pattern in `test/php-fpm-codegen.test.ts`):

| behavior | enforcement artifact | effect when enforcing |
| --- | --- | --- |
| `/bin/sh` spawn | AppArmor profile (execs[] allowlist, `ixr` on the binary only) | exec **denied** — no shell to hijack |
| webshell drop | AppArmor opens rules + Wazuh AR `sbob-php-fpm-process-kill` (bound to 100111) | write denied (enforce) / drift kill -9 (audit) |
| C2 connect | NetworkPolicy (egress = memcache only; mode: enforce when egress+ingress graduate) | connect **blocked**; `firewall-drop` AR bound to 100131 |
| memfd payload | seccomp profile / systemd `SystemCallFilter` drop-in (M4 signature surface) | `memfd_create` → **EPERM** (enforce) / logged (audit) |

Every block event is itself a Wazuh alert: enforcement telemetry rule (11,1) = `100211` on the `sbob-enforce.log` localfile (TDS 14.6).

## Lab validation steps (secure, corpus-replay only — Stage 1)

Nothing here touches a real PHP; the corpora are recorded auditd lines replayed through `wazuh-logtest` on a disposable manager.

```sh
# 1. transpile the php-fpm bundle (slot 1 is pinned in docs/sbob-registry.yaml)
node src/cli.ts transpile --sbob sbobs/php-fpm.yaml --out dist/php \
  --target linux --registry docs/sbob-registry.yaml --skip-signature-verify

# 2. deploy beside the redis bundle (rules/decoders flattened; CDB lists path-preserved)
scripts/sync-manager.sh dist/php --root <manager-root>

# 3. replay the corpora — benign must stay silent, drift must fire 100111/100121/100131/100163
scripts/logtest-corpus.sh php
```

Stage 2 (live-workload drift in a sealed lab) and Stage 3 (enforcement: Calico-staged NP, AppArmor complain→enforce) follow the runbook; `labValidation: pending` stays on the manifests until then.

## Known caveats (same as the redis bundle)

- The connect leg (100131) depends on the saddr decoder work item (TDS 7.3.1): the decoder currently extracts raw `sbob.saddr`; the `sbob.dst_ip`/`sbob.dst_port` fields the rule consumes land with that item. The corpus already carries the AF_INET hex (`0200 115C 2D9B940C` = 45.155.148.12:4444) so the leg is replay-ready.
- Signature rules are node-scoped (Mode B): declare `rulePolicies.processAllowed` exemptions for node daemons (kubelet, containerd) before a node-wide rollout, or expect benign signature noise.
- Ingress on Linux is informational (TDS 8 accept-attribution gap); the NetworkPolicy enforces the declared nginx peer set regardless.

## References

- watchtowr PHP2Shell FAQ — https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- Wikipedia, "PHP2Shell" (2026 attack campaign)
- CISA KEV addendum 2026-10-26
- Repo grounding: [TDS](TDS.md) §6.1 (rule bands), §7.4 (signatures), §14 (enforcement); [runbook](runbook.md) §9 (AR rollout)

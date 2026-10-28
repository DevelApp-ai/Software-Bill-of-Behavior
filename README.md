# Software-Bill-of-Behavior

**SBoB → Wazuh transpiler** — compile [Software Bill of Behavior](https://billofbehavior.com/bob/docs/spec/) (SBoB) workload manifests into Wazuh detection artifacts: audit rules, CDB allowlists, custom decoders, and drift rulesets.

Monitor **Linux**, **Windows**, and **Kubernetes** deployments from one declared behavioral contract. The design is specified in [docs/TDS.md](docs/TDS.md); implementation is tracked in [issue #1](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/1).

## Status

| Milestone | Scope | Issue |
| --- | --- | --- |
| M1 | Transpiler core: SBoB YAML parser, validator, IR, linter, deterministic rule-ID allocation, PCRE2 wildcard compiler, Linux/k8s-node codegen | [#2](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/2) |
| M2 | Windows Sysmon codegen (EIDs 1/3/11/22; args-drift heuristic, opens file-create partial) — implemented, lab validation pending | [#3](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/3) |
| M3 | Kubernetes attribution: `--target k8s-node` (cgroup decoders, podmap, attribution rules, docker-listener lifecycle, attack matrix) — implemented, lab validation pending | [#4](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/4) |
| M4 | rulePolicies signature rules (module-load / namespace-change / ptrace / memfd, sensitive-path + SA-token + k8s-API overlays, manager-side k8s-audit JSON rule), machine-generated coverage matrix, attack false-negative harness, CI determinism gate — implemented, lab validation pending | [#5](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/5) |
| M5 | GitOps deployment + ops runbook: `scripts/sync-manager.sh` bundle→manager sync (rules/decoders flattened, CDB lists path-preserved, agent groups materialized), ops-health rules (config-check (8,3) audit-rollout signal, sbob-cadence (8,1) image-digest guard), `bundleVersion` manifest field, [docs/runbook.md](docs/runbook.md) with rollout/rollback/triage and the production pilot checklist — implemented, production pilot pending | [#6](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/6) |
| M6 | Phase 2 codegen: `--target sigma` (auditd execve/open/connect + Sysmon EID 1/3/11/22 filter-block rules, deterministic v5 UUIDs), `--target velociraptor` (RE2-safe pslist/netstat conformance sweeps), `--target mde` (DeviceProcessEvents/DeviceFileEvents/DeviceNetworkEvents KQL hunts), `--target falco` (list-based drift rules + DaemonSet + Falcosidekick→Wazuh correlation rule 100103), Envoy `endpoints[]` ingestion ((9,1)/(9,2) manager-side rules) and the per-engine blind-spot matrix ([docs/engine-matrix.md](docs/engine-matrix.md), CI-gated) — implemented, lab validation pending | [#7](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/7) |
| M7 | Phase 3 enforcement behind a Monitor→Audit→Enforce state machine: `sbobctl enforce` (committed per-workload state file with safety gates — enforce requires an incident-free audit window, the ladder may not skip rungs), seccomp (OCI profile / systemd `SystemCallFilter`), AppArmor profiles, Kubernetes NetworkPolicy with declared-vs-enforced np-diff (closes the podSelector/namespaceSelector gap), Windows AppLocker, Wazuh active responses (process-kill / firewall-drop, disabled by default with a flip-to-yes kill-switch) and enforcement telemetry (rule (11,1) `100111` on the `sbob-enforce.log` localfile) — implemented, enforcement pilot in Audit mode pending | [#8](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/8) |
| M8 | SBoB semantic diff gate: scored release deltas (`sbobctl diff`) | [#13](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/13) |
| M9 | Release profiler: observed-behavior → SBoB redraft assist (outline) | [#14](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/14) |

## How it works

```
sbobs/*.yaml ──parse+validate──▶ IR ──lint──▶ codegen ──▶ wazuh bundle
                                              │
   ┌──────────────────────────────────────────┴──────────────┐
   │ wazuh/audit/sbob/<name>.rules      auditctl fragment (linux)  │
   │ wazuh/agent-conf/sbob/<name>.xml   eventchannel (windows)    │
   │ wazuh/lists/sbob/<name>/*         CDB allowlists             │
   │ wazuh/decoders/sbob/<name>.xml     custom decoder chain (linux) │
   │ wazuh/rules/sbob/<id>_<name>_linux.xml   drift rules          │
   │ wazuh/rules/sbob/<id>_<name>_windows.xml drift rules (Sysmon) │
   │ wazuh/rules/sbob/<id>_<name>_k8s-node.xml drift + attribution │
   │ wazuh/lists/sbob/k8s/podmap        pod uid map (k8s)         │
   │ wazuh/agent-conf/sbob/<name>-k8s.xml docker-listener + config-check wodle │
   │ wazuh/agent-conf/sbob/<name>-audit-digest.sh  digest script │
   │ wazuh/manager/sbob/k8s-api-audit.md  api audit ingestion doc │
   │ <name>.manifest.json              coverage notes               │
   │ checksums.txt                     sha256 inventory             │
   └───────────────────────────────────────────────────────────┘
```

Signature rules (M4) invert the model: generic Wazuh rules (audit keys like `sbob-module-load`, `sbob-process-tracing`) fire by default; `rulePolicies.processAllowed` exemptions compile to per-policy CDB lists (`sigexempts/<policy>`) with a `not_match_key` comm condition, and `containerAllowed: true` suppresses the rule entirely. Every bundle manifest carries a machine-generated `coverage` matrix (section × OS with `REASON_CODES`) plus `bundleVersion` (sbob version + image digest); completeness is asserted at codegen time, and CI adds a twice-run determinism diff plus the attack-suite false-negative check (62 upstream redis attacks ⇒ `docs/attack-matrix.md`).

Ops health (M5) closes the loop around the deployed bundle: rule (8,3) config-check keeps firing on any node whose installed sbob audit key-set digest does not match the bundle (audit rules are not hot-deployable — it is the rollout completion signal), and rule (8,1) sbob-cadence alerts when a container starts from the workload image repo with a non-pinned digest. `scripts/sync-manager.sh <bundle>` deploys a bundle into the manager layout and `docs/runbook.md` covers rollout, rollback and alert triage.

Phase-2 engines (M6) reuse the same IR: Sigma rules invert the SBoB allowlists with filter blocks (`condition: selection and not 1 of filter_peer_*`), the Velociraptor artifact runs hunt-time `pslist`/`netstat` conformance sweeps with RE2-safe anchored regexes, MDE gets per-section KQL advanced-hunting queries, and the Falco bundle (rules + DaemonSet) ships its alerts to the Wazuh manager through Falcosidekick, correlated by rule (10,3) `100103`. `endpoints[]` sections get Envoy access-log ingestion ((9,1)/(9,2) manager-side path-drift rules). Per-engine coverage of the 62-attack redis suite is tracked in [docs/engine-matrix.md](docs/engine-matrix.md) — no attack is blind everywhere unless the blind spot is already a documented class in the attack matrix; CI re-checks this (`scripts/engine-matrix-check.ts`).

Phase-3 enforcement (M7) turns the SBoB from an alerting contract into a blocking one, gated by a committed rollout state file: sections graduate Monitor→Audit→Enforce, `enforce` requires an operator-attested incident-free audit window (`ERR_ENFORCE_NOT_AUDITED`), and no section may skip rungs (`ERR_ENFORCE_STATE_INVALID`). Per target the bundle emits seccomp (OCI profile for pods / systemd `SystemCallFilter` drop-in for hosts, over the M4 signature syscall surface), an AppArmor profile (linux), a Kubernetes NetworkPolicy + machine-readable declared-vs-enforced diff (`--enforced-np`, exit 1 on drift — audit-mode NPs are Calico-staged/`--dry-run=server` only, never applied live), a Windows AppLocker policy, and Wazuh active responses (`sbob-<name>-process-kill`, `firewall-drop`) that ship disabled and flip per enforcing section; every block event is itself a Wazuh alert (rule (11,1) enforcement telemetry on the `sbob-enforce.log` localfile) — see [TDS §14](docs/TDS.md).

Drift detection is allowlist-based: every observed `execve`/`open`/`connect` that is **not** declared in the SBoB raises a Wazuh alert. Allowlists are enforced with CDB list lookups (`not_match_key` / `not_address_match_key`) plus negated PCRE2 alternations for wildcarded entries — see [TDS §5](docs/TDS.md).

## Usage

Requires Node.js ≥ 22 (uses native TypeScript type stripping; **zero npm dependencies**).

```sh
# transpile a workload into a Wazuh bundle (linux target)
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle --registry docs/sbob-registry.yaml --skip-signature-verify

# windows target (Sysmon EIDs 1/3/11/22; requires Wazuh >= 4.4 and the shipped ruleset parent rule 61600)
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle-win --target windows --registry docs/sbob-registry.yaml --skip-signature-verify

# kubernetes node target (attribution: cgroup decoders + podmap + docker-listener lifecycle;
# requires the shipped docker integration ruleset, parent rule 87900)
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle-k8s --target k8s-node --registry docs/sbob-registry.yaml --skip-signature-verify

# phase-2 engine targets (M6): sigma, velociraptor, mde, falco
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle-sigma --target sigma --registry docs/sbob-registry.yaml --skip-signature-verify
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle-velo --target velociraptor --registry docs/sbob-registry.yaml --skip-signature-verify
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle-mde --target mde --registry docs/sbob-registry.yaml --skip-signature-verify
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle-falco --target falco --registry docs/sbob-registry.yaml --skip-signature-verify

# schema-validate only
node src/cli.ts validate --sbob sbobs/redis.yaml

# tests (unit + golden bundle comparison)
node --test test/*.test.ts

# semantic release diff — scored behavior-delta ladder (M8; exits 1 on advisory/mandatory verdicts)
node src/cli.ts diff --old releases/webcache-1.2.yaml --new releases/webcache-1.3.yaml --report dist/diff-report.json

# phase-3 enforcement bundle (M7): state file gates the Monitor→Audit→Enforce ladder;
# --enforced-np optionally diffs the declared SBoB against the live NetworkPolicy (exit 1 on drift)
node src/cli.ts enforce --sbob sbobs/redis.yaml --state releases/redis.state.yaml --out dist/enforce-k8s --target k8s-node --registry docs/sbob-registry.yaml --skip-signature-verify
```

Workload rule IDs are derived deterministically from the slot registry (`docs/sbob-registry.yaml`):
`rule_id = 100000 + slot*100 + section_code*10 + variant` — see [TDS §6.1](docs/TDS.md).

## Repository layout

```
sbobs/                  example SBoB manifests
docs/TDS.md             technical design specification
docs/attack-matrix.md   62-attack kill-chain coverage matrix (M3)
docs/sbob-registry.yaml workload slot registry (deterministic rule IDs)
src/                    transpiler sources (zero-dependency TypeScript)
test/                   unit tests + golden bundle + lab corpus
scripts/                golden regeneration + wazuh-logtest lab harness + podmap refresher
```

## Lab validation

Generated bundles carry a `LAB VALIDATION PENDING` banner until validated against a live Wazuh manager. Run `scripts/logtest-corpus.sh` (linux), `scripts/logtest-corpus.sh windows` or `scripts/logtest-corpus.sh k8s` on a lab manager with the bundle installed: the benign corpus must stay silent and the drift corpus must fire the mapped drift rules (linux: 100011/100021/100031 plus signatures 100060/100062; windows: 100016/100006/100026/100036/100007; k8s: 100011/100021/100031 plus the attribution chain — rule 100071 flags podmap-unresolved, and `scripts/sbob-podmap-refresh.sh` seeds the map to silence it). The 62-attack kill-chain mapping is documented in [docs/attack-matrix.md](docs/attack-matrix.md).

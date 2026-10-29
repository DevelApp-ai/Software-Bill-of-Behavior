# Software-Bill-of-Behavior

**SBoB → Wazuh transpiler** — compile [Software Bill of Behavior](https://billofbehavior.com/bob/docs/spec/) (SBoB) workload manifests into Wazuh detection artifacts: audit rules, CDB allowlists, custom decoders, and drift rulesets.

Monitor **Linux**, **Windows**, and **Kubernetes** deployments from one declared behavioral contract. The design is specified in [docs/TDS.md](docs/TDS.md); implementation is tracked in [issue #1](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/1).

## Status

| Milestone | Scope | Issue |
| --- | --- | --- |
| M1 | Transpiler core: SBoB YAML parser, validator, IR, linter, deterministic rule-ID allocation, PCRE2 wildcard compiler, Linux/k8s-node codegen — lab validated in CI ([run 40931193214](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/actions/runs/40931193214)) | [#2](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/2) |
| M2 | Windows Sysmon codegen (EIDs 1/3/11/22; args-drift heuristic, opens file-create partial) — implemented, lab validated in CI ([run 40931193214](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/actions/runs/40931193214)) | [#3](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/3) |
| M3 | Kubernetes attribution: `--target k8s-node` (cgroup decoders, podmap, attribution rules, docker-listener lifecycle, attack matrix) — implemented, lab validated in CI ([run 40931193214](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/actions/runs/40931193214)) | [#4](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/4) |
| M4 | rulePolicies signature rules (module-load / namespace-change / ptrace / memfd, sensitive-path + SA-token + k8s-API overlays, manager-side k8s-audit JSON rule), machine-generated coverage matrix, attack false-negative harness, CI determinism gate — implemented, lab validated in CI ([run 40931193214](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/actions/runs/40931193214)) | [#5](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/5) |
| M5 | GitOps deployment + ops runbook: `scripts/sync-manager.sh` bundle→manager sync (rules/decoders flattened, CDB lists path-preserved, agent groups materialized), ops-health rules (config-check (8,3) audit-rollout signal, sbob-cadence (8,1) image-digest guard), `bundleVersion` manifest field, [docs/runbook.md](docs/runbook.md) with rollout/rollback/triage and the production pilot checklist — implemented, production pilot pending | [#6](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/6) |
| M6 | Phase 2 codegen: `--target sigma` (auditd execve/open/connect + Sysmon EID 1/3/11/22 filter-block rules, deterministic v5 UUIDs), `--target velociraptor` (RE2-safe pslist/netstat conformance sweeps), `--target mde` (DeviceProcessEvents/DeviceFileEvents/DeviceNetworkEvents KQL hunts), `--target falco` (list-based drift rules + DaemonSet + Falcosidekick→Wazuh correlation rule 100103), Envoy `endpoints[]` ingestion ((9,1)/(9,2) manager-side rules) and the per-engine blind-spot matrix ([docs/engine-matrix.md](docs/engine-matrix.md), CI-gated) — implemented, lab validation pending | [#7](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/7) |
| M7 | Phase 3 enforcement behind a Monitor→Audit→Enforce state machine: `sbobctl enforce` (committed per-workload state file with safety gates — enforce requires an incident-free audit window, the ladder may not skip rungs), seccomp (OCI profile / systemd `SystemCallFilter`), AppArmor profiles, Kubernetes NetworkPolicy with declared-vs-enforced np-diff (closes the podSelector/namespaceSelector gap), Windows AppLocker, Wazuh active responses (process-kill / firewall-drop, disabled by default with a flip-to-yes kill-switch) and enforcement telemetry (rule (11,1) `100111` on the `sbob-enforce.log` localfile) — implemented, enforcement pilot in Audit mode pending | [#8](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/8) |
| M8 | SBoB semantic diff gate: scored release deltas (`sbobctl diff`) with verdict + `--fail-on` exit-code semantics, package-namespace scoring, JSON delta report, CI determinism/verdict gate — implemented, advisory calibration cycle pending | [#13](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/13) |
| M9 | Observability bootstrap profiler: derive candidate SBoB from a window of normalized `sbob.*` telemetry (`sbobctl profile`) — candidate + provenance sidecar, disposition taxonomy, taint quarantine, M8 gate integration; implemented, lab validation pending | [#14](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/14) |

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

# derive a candidate SBoB from a normalized sbob.* event window (M9; exits 1 when
# quarantined or nothing is declarable — the odd-behavior review queue is the output)
node src/cli.ts profile --events windows/legacy-cache.jsonl --workload legacy-cache \
  --image "docker.io/legacy/cache@sha256:…" --k8s-namespace legacy-tier \
  --window-days 30 --dispositions review.json --baseline releases/legacy-cache.yaml \
  --out-dir dist/profile
```

Workload rule IDs are derived deterministically from the slot registry (`docs/sbob-registry.yaml`):
`rule_id = 100000 + slot*100 + section_code*10 + variant` — see [TDS §6.1](docs/TDS.md).

## Promotion gate (reusable GitHub Action)

The repo ships a composite action wrapping `sbobctl diff` — the M8 release gate in CI form ([#22](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/22)):

```yaml
jobs:
  sbob-promotion-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # attaches the delta report to the triggering PR
    steps:
      - uses: actions/checkout@v5
      - uses: DevelApp-ai/Software-Bill-of-Behavior@main   # pin to a tag/SHA in real use
        with:
          old: releases/webcache-1.2.yaml   # prior-release SBoB (workspace-relative path)
          new: releases/webcache-1.3.yaml   # next-release SBoB
          fail-on: mandatory                # none | advisory | mandatory (default)
          # namespace: /usr/bin,/app        # optional exec-scoring overrides (comma/newline-separated)
          # internal-suffix: corp.internal   # optional extra internal DNS suffixes
          github-token: ${{ github.token }} # optional: comment the delta on the triggering PR
```

Behavior — deterministic and zero-dependency (Node 22 type stripping, no `npm install`):

- runs `sbobctl diff --old … --new … --fail-on …`, writes `<report-name>.json` (machine-readable delta report) and `<report-name>.delta.md` (verdict markdown), and uploads both as a workflow artifact (always, PR-triggered or not);
- when `github-token` is set and the event is a pull request, attaches the `*.delta.md` verdict to the triggering PR as a comment;
- writes a step summary mirroring the verdict line (verdict, Δ score, fail-on threshold);
- propagates the `sbobctl diff` exit code from `--fail-on` (verdict at/above the threshold ⇒ exit 1), so the gate is green exactly when the release delta is below the threshold;
- a diff that cannot run (invalid SBoB, workload name mismatch) is an `error` verdict and fails the gate — never green on a broken diff.

Outputs: `verdict` (`clean|advisory|mandatory|error`), `score` (Δ), `exit-code`.

This repo consumes its own action on the committed fixture pair in [`.github/workflows/diff-gate-demo.yml`](.github/workflows/diff-gate-demo.yml): the **fixture-verify** job asserts the contract on every PR (clean pair passes; drifted pair fails MANDATORY with exit 1, asserted via `continue-on-error` so ordinary PRs stay green), and a `demo/promotion-*` branch gets the real red **promotion-gate** check with both reports attached — the #22 exit-criteria demo promotion PR.

## The derivation loop (M9)

Most real-world workloads ship no vendor SBoB. The profiler is the on-ramp for them: it consumes a window of **normalized `sbob.*` events** (the same field contract the drift decoders emit — JSONL), clusters them per workload × section, classifies every entry **steady · periodic · sporadic · one-off** (calibratable thresholds), applies the mandatory disposition taxonomy (**declare · hold · exempt-with-expiry · investigate** — no "no decision" states), and emits a candidate SBoB plus a provenance sidecar for human review. Kernel/runtime telemetry (`auditd`, `sysmon`, `ebpf`) is the only confirming source — entries seen only by flow logs or app logs are marked unverified and excluded. Workloads with open incident labels are quarantined: no candidate until remediated. A reviewer who overrides a held or investigated entry to `declare` must write the reason, or the run fails — **no unexplained observation becomes a plain allow.** With `--baseline`, the candidate's first reviewed delta scores through the M8 diff gate. See [TDS §17](docs/TDS.md).

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

Generated bundles carry a `LAB VALIDATION PENDING` banner until validated against a live Wazuh manager. Run `scripts/logtest-corpus.sh` (linux), `scripts/logtest-corpus.sh windows`, `scripts/logtest-corpus.sh k8s` or `scripts/logtest-corpus.sh php` on a lab manager with the bundle installed: the benign corpus must stay silent and the drift corpus must fire the mapped drift rules (linux: 100011/100021/100031 plus signatures 100060/100062; windows: 100016/100006/100026/100036/100007; k8s: 100011/100021/100031 plus the attribution chain — rule 100071 flags podmap-unresolved, and `scripts/sbob-podmap-refresh.sh` seeds the map to silence it). The 62-attack kill-chain mapping is documented in [docs/attack-matrix.md](docs/attack-matrix.md).

The `php` target replays the PHP2Shell scenario ([docs/php2shell-scenario.md](docs/php2shell-scenario.md), issue [#23](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/23)): the `sbobs/php-fpm.yaml` workload (slot 1, rule band `1001xx`) maps the October 2026 PHP RCEs (CVE-2026-109618 / CVE-2026-109619) onto post-exploit behavior drift — `/bin/sh` exec from a hijacked worker (**100111**), webshell drop (**100121**), reverse-shell C2 connect (**100131**) and the memfd fileless variant (**100163**) — proving the SBoB catches the behavior regardless of the entry vector.

For **detection testing** in the Wazuh sense, `scripts/logtest-api.ts` drives the same corpora through the Wazuh server logtest API (`PUT /logtest`, Wazuh ≥ 4.4): JSON-asserted rule ids instead of grepped CLI text, session-token continuity for `firedtimes`, and a sustained gate that replays the drift corpus eight times in one session to make the **frequency children fire** (php: 100112/100122/100132 — 8 matches / 120s), which a one-shot `wazuh-logtest` pipe cannot prove. Logic is unit-tested against mocked API responses (`test/logtest-api.test.ts`); the lab-validate workflow runs it live against the containerized manager.

### Lab-validation evidence (docs/lab-validation.yaml)

The evidence for a green matrix run is committed in [docs/lab-validation.yaml](docs/lab-validation.yaml): one record per workload naming the validated targets, the pinned manager image, the validation date and the Actions run URL. Passing `--lab-validation docs/lab-validation.yaml` to `sbobctl transpile` stamps every workload × target the file lists: the generated XML headers read `LAB VALIDATED (<date>, <manager>): evidence <run URL>` and the manifest carries `labValidation: "validated"` plus the evidence record (`labValidationEvidence`). Workload × target pairs without a record keep the `LAB VALIDATION PENDING` banner and `labValidation: "pending"` — the default is untouched, so unsigned/development bundles stay honestly pending. The committed golden bundles (`test/golden/`) are regenerated with the same flag (`node scripts/regen-golden.ts`), so the golden diff in a flip PR shows exactly what the referenced run proved.

### Automated lab validation (CI, issue #23)

[`.github/workflows/lab-validate.yml`](.github/workflows/lab-validate.yml) runs the whole loop against a **disposable, containerized Wazuh manager** (`wazuh/wazuh-manager`, pinned 4.14.6) as a per-target matrix (linux, windows, k8s, php): transpile → `sync-manager.sh` install (with every generated CDB list declared in `ossec.conf`, because Wazuh does not auto-load lists) → manager restart → **corpus gate** (`wazuh-logtest` inside the container: benign corpus silent, drift corpus fires the mapped rules) → **API detection gate** (`logtest-api.ts` from the runner: JSON-asserted rule ids plus the sustained frequency children). It runs nightly, on `workflow_dispatch`, and on PRs carrying the `lab-validate` label — ordinary PRs stay fast. A green matrix run is validation against a live manager; the manifests' `labValidation` banners can be flipped on the back of its run URL, and the README statuses above track what the latest run proved.

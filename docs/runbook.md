# SBoB → Wazuh Ops Runbook (M5)

Operational procedures for deploying sbobctl bundles into a Wazuh manager and
keeping nodes in sync. Companion to `docs/TDS.md` §10 (deployment and
operations). The production pilot checklist for the redis workload is in
§7.

---

## 1. Bundle → manager layout mapping

A transpiled bundle (`sbobctl transpile --out <dir>`) maps onto the manager
tree as follows; `scripts/sync-manager.sh` performs the copy:

| Bundle path | Manager path | Notes |
|---|---|---|
| `wazuh/rules/sbob/*.xml` | `$ROOT/rules/sbob_<file>` | **Flattened** — the Wazuh rules loader does not recurse into subdirectories |
| `wazuh/decoders/sbob/*.xml` | `$ROOT/decoders/sbob_<file>` | Flattened likewise |
| `wazuh/lists/sbob/**` | `$ROOT/lists/sbob/**` | **Paths preserved** — rule `<list>` sources are lists-root-relative (e.g. `sbob/redis/execs`) |
| `wazuh/agent-conf/sbob/<n>.xml` (+ `<n>-k8s.xml`) | `$ROOT/etc/shared/sbob-<n>/agent.conf` | Concatenated when both targets were transpiled; multiple wodle blocks side-by-side are valid |
| `wazuh/agent-conf/sbob/<n>-audit-digest.sh` | `$ROOT/etc/shared/sbob-<n>/` | Consumed by the command-wodle (config-check, TDS 10.1) |
| `wazuh/manager/**`, `*.manifest.json`, `checksums.txt` | — | Informational; the manifest's coverage matrix documents what the bundle detects |

`$ROOT` is `/var/ossec` by default (`--root` to override). `--dry-run`
prints the mapping without writing.

The manifest `bundleVersion` field (`sbob-v<ver>-<digest12>`, or `-untagged`
for tag-pinned images) identifies the deployed bundle generation per
workload.

## 2. Rollout procedure

1. **PR** — transpile the pinned SBoB, commit the bundle, open a PR.
   CI gates: unit tests, coverage-matrix completeness, determinism
   (byte-identical double transpile), attack false-negative suite.
2. **Merge** — CI green ⇒ merge.
3. **Sync** — on the manager: `scripts/sync-manager.sh <bundle-dir>`.
4. **Restart** — `wazuh-control restart` reloads rules, decoders and CDB
   lists. (They are hot-reloadable in this direction only.)
5. **Node audit rollout** — auditd rules are **not** hot-deployable. Bind each
   node's agent to the `sbob-<name>` group (the group's `agent.conf` carries
   the wodle blocks; the digest script rides along in the group's shared
   dir), then install the new audit fragment on the node. Rule **(8,3)
   config-check** (level 5) keeps firing on that node until its installed
   `-k sbob…` key-set digest matches the bundle — it is the rollout
   completion signal.
6. **Silence check** — after rollout, config-check alerts for that node stop
   within one wodle interval (30m).

## 3. Rollback

1. `git revert` the bundle PR and re-run CI; merge.
2. Re-sync the previous bundle (`scripts/sync-manager.sh`) and restart the
   manager. Rule/decoder/list versions are overwritten in place — keep the
   previous bundle tarball if you need a hard restore.
3. Node audit rollback follows the same procedure as rollout (step 5
   above); config-check confirms completion per node.

## 4. Alert triage

Group prefix `sbob-<family>` appears in each rule's `<group>`; the rule id
encodes the family (TDS 6.1: `100000 + slot*100 + section*10 + variant`).

| Family (group) | Level | Meaning | Action |
|---|---|---|---|
| `sbob-drift` (exec/open/egress/ingress) | 9 | Workload behavior outside its SBoB | SIEM — standard drift alert |
| `sbob-drift` frequency-escalated | 12 | Drift burst above `frequency` | File a ticket (TDS 10.4) |
| `sbob-info` (section-absent) | 2 | SBoB has no such section — rule is profiling only | Profile-quality backlog |
| `sbob-k8s` attribution | 3 | Pod/namespace attribution lookup miss | Backlog; check podmap freshness |
| `sbob-signature` (rulePolicies) | 10–12 | Signature-class behavior (module load, SA token use, …) | Signature alert — investigate |
| `sbob-ops` (8,3) config-check | 5 | Node's audit key set ≠ bundle | Complete the audit rollout on that node (§2 step 5) |
| `sbob-ops` (8,1) sbob-cadence | 9 | Container started from the workload repo with a non-pinned digest | Update the SBoB or roll back the image (TDS 10.3) |

## 5. Performance guidance

- **Prefer Mode A** (literal `execs`/`opens` entries compile to CDB lists —
  O(1) key lookups); PCRE2 alternations (Mode B) only where wildcards force
  them. The lint wildcard-breadth warning flags expensive compilations.
- CDB lists (`not_match_key`) are constant-time; per-rule PCRE2 field checks
  dominate cost — keep SBoB entries specific rather than broad wildcards.
- `frequency` escalation rules only fire on top of already-matched drift;
  they add no steady-state cost.
- The config-check command-wodle runs every 30m per agent and emits one log
  line per node — negligible.

## 6. Known limitations

- **Multi-workload nodes**: the config-check digest covers *all* `-k sbob…`
  keys on a node. On a node hosting several SBoB-managed workloads, one
  workload's rollout shifts the node digest and fires (8,3) until every
  workload's fragment matches its bundle. Run the triage per node, not per
  workload; single-workload agent groups are the exact model.
- **Tag-only image references**: (8,1) sbob-cadence can only verify
  digest-bearing image refs from docker events. Tag-only starts are not
  alerted (TDS 10.3 limitation); pin SBoB images by digest.
- **auditctl key rendering**: the digest script greps `-k sbob…` from
  `auditctl -l`; confirm the quoting/rendering on the target OS during the
  pilot (the script tolerates bare and quoted keys, but verify on the real
  auditctl version).
- **Agent-side shared path**: the wodle invokes the script via
  `/var/ossec/etc/shared/sbob-<name>/`; confirm the agent's shared-dir
  mount exposes this path on the pilot node before relying on config-check.

## 7. M5 production pilot checklist — redis workload

Lab evidence already automated in CI (M1–M4): logtest corpus silence/fire
matrix, coverage manifest, determinism, attack false-negative suite. The
production pilot adds the following; record evidence per item:

- [ ] **Deploy**: transpile redis SBoB (linux + k8s-node targets), sync to
      the manager with `scripts/sync-manager.sh`, restart, confirm
      `wazuh-control` reports no rule/decoder load errors.
- [ ] **Agent groups**: bind the pilot node's agent to `sbob-redis`; confirm
      the group's `agent.conf` and `redis-audit-digest.sh` arrive in the
      agent's shared dir (the wodle command path resolves).
- [ ] **Logtest silence**: on the manager, run `wazuh-logtest` against the
      corpus `test/corpus/redis-drift.audit`-style benign traffic — in-scope
      behavior stays silent.
- [ ] **Drift fires**: exercise one drift per family (undeclared exec, open,
      egress connect) on the node — each raises the level-9 drift alert.
- [ ] **Signature fires**: trigger one signature event (e.g. the
      module-load key) — level-12/10 signature alerts fire.
- [ ] **Config-check**: before the node's audit rollout, (8,3) level 5
      fires within 30m; after installing the fragment, it goes silent within
      one further interval. Confirm the `auditctl -l` key rendering caveat
      (§6).
- [ ] **Cadence** (k8s node): start a container from the redis repo with a
      wrong digest — (8,1) level 9 fires; starts with the pinned digest stay
      silent.
- [ ] **Tiering**: verify drift level-9 alerts reach the SIEM and a
      frequency burst escalates to a ticket (TDS 10.4 exercise).
- [ ] **Rollback**: `git revert` the bundle PR, re-sync, restart, confirm
      the previous rule ids load and config-check re-fires on nodes until
      the reverted fragment is installed.
- [ ] **Bundle version**: the deployed manifest `bundleVersion` matches the
      SBoB version + image digest under management.

## 8. Phase-2 engine bundles (M6) — deploy notes

The `--target falco` bundle is deployed in two halves:

- **Wazuh side** — `wazuh/rules/sbob/100000_redis_falco.xml` (correlation
  rule 100103) and `wazuh/manager/sbob/redis-falco.md` follow the normal
  M5 flow: `scripts/sync-manager.sh` flattens the rule into the manager
  ruleset and the `localfile json` block goes into the manager's
  `ossec.conf`. Nothing new operationally.
- **Node side** — `falco/sbob/redis_rules.yaml` and
  `falco/sbob/redis-daemonset.yaml` are applied as a DaemonSet
  (ConfigMap-embedded rules + falcosidekick with `FALCOSIDEKICK_WAZUH_URL`
  pointing at the manager). Falco alerts therefore arrive as native JSON;
  rule 100103 correlates them by `output_fields.container.name` — one pane
  of glass beside the auditd alerts, no decoder changes.
- **Split-brain caveat**: falco rules are not synced by
  `sync-manager.sh` (which only maps `wazuh/` paths); the DaemonSet is a
  separate k8s artifact. When the SBoB changes, regenerate and re-apply
  *both* halves — a stale DaemonSet alerts against the old allowlist while
  Wazuh rules enforce the new one. The sigma/velociraptor/mde artifacts
  need no deploy action (they feed external tooling directly).
- **Envoy (endpoints[])**: when a workload declares `endpoints[]`, the k8s
  bundle additionally carries `wazuh/lists/sbob/<name>/endpoints_{in,out}`
  and the `(9,1)/(9,2)` rules; the manager doc
  `wazuh/manager/sbob/<name>-envoy.md` pins the Envoy access-log format
  contract that must be configured on the sidecar before the rules are
  meaningful (lab validation pending).

## 9. Phase-3 enforcement rollout (M7)

Enforcement is generated, never hand-written: `node src/cli.ts enforce
--sbob sbobs/redis.yaml --state releases/redis.state.yaml --out dist/enforce
--target linux|windows|k8s-node` emits the enforcement bundle gated by the
committed state file. The state machine is the safety contract:

1. **State transitions.** `monitor` (detection only) → `audit` (enforcement
   artifacts in audit form: seccomp `SCMP_ACT_LOG`, AppArmor `complain`,
   AppLocker `AuditMode`, NP annotated `mode: audit`) → `enforce`
   (blocking). A section may only reach `enforce` with an `auditRecords`
   entry showing `incidents: 0` over an operator-attested window
   (`ERR_ENFORCE_NOT_AUDITED` otherwise), and the ladder may not skip
   rungs — a section is at most one rung above the file default
   (`ERR_ENFORCE_STATE_INVALID`). Promote by editing the committed state
   file; the GitOps review of that diff IS the promotion approval.
2. **Wazuh active responses.** The AR conf (`wazuh/agent-conf/sbob/`
   `<name>-ar.xml`) ships every `<active-response>` with
   `<disabled>yes</disabled>` unless its section is in `enforce`.
   **Kill-switch:** flip the block back to `<disabled>yes</disabled>` —
   no regeneration, effective on agent restart. The process-kill script
   (`wazuh/active-response/bin/sbob-<name>-process-kill.sh`) must be
   deployed to each AGENT's `/var/ossec/active-response/bin/` (700, root);
   `scripts/sync-manager.sh` stages it on the manager as the
   distribution source. Declare the command in the manager
   `ossec.conf` per the generated `wazuh/manager/sbob/<name>-enforce.md`.
3. **Enforcement telemetry.** Every block event is itself an alert: the
   script writes JSON to `/var/ossec/logs/sbob-enforce.log` on the agent,
   the generated `json` localfile block ships it, and rule (11,1)
   (`<id>_redis_enforce.xml`, id 100111 for redis) fires on
   `process-kill`/`-revert`/`-failed`/`firewall-drop` actions. Watch this
   rule during any enforcement rollout: `-failed` or `-revert` bursts mean
   the SBoB is under-declared or the rollout is being reverted.
4. **seccomp.** k8s: apply `enforcement/sbob/<name>/seccomp/<name>.json`
   as an OCI profile (kubelet `seccomp` root or a CSI-managed profile),
   reference it from the pod `securityContext`; `containerAllowed: true`
   on a signature policy removes its syscalls, `processAllowed` is NOT
   honored here (container-global). Hosts: install
   `enforcement/sbob/<name>/systemd/<name>-seccomp.conf` as a unit
   drop-in and `systemctl daemon-reload && systemctl restart <unit>`.
   seccomp only ships when the global state is audit or enforce — flip
   the file default back to `monitor` to withdraw it.
5. **AppArmor (linux).** `apparmor_parser -r` the generated profile;
   it attaches to the first declared exec path and starts in `complain`
   unless a covered section enforces. `/data/*` entries broaden to
   `/data/**` (documented); open flags map coarsely (r/w/k/a).
6. **NetworkPolicy (k8s).** Both net sections enforcing → apply
   `networkpolicy/<name>.yaml` live (annotation `mode: enforce`).
   Anything less → the NP is annotated `mode: audit` and MUST NOT be
   applied live: apply as a Calico staged policy or validate with
   `kubectl apply --dry-run=server` only. Pods must carry the
   `sbob.k8sstormcenter.io/workload: <name>` label (podSelector
   convention). **np-diff:** feed the live policy's peers JSON via
   `--enforced-np`; the generated `<name>-np-diff.json` lists
   `missing-rule`/`extra-rule` drift and the CLI exits 1 on any drift —
   run it in CI against the cluster to keep declared and enforced in
   lockstep. dnsNames are not evaluable in NetworkPolicy (declare the
   resolver IP:port).
7. **AppLocker (windows).** Import
   `enforcement/sbob/<name>/applocker/<name>.xml` via GPO or Intune
   (EXE path rules only; args are not enforceable — the Wazuh bundle
   stays args-precise). `EnforcementMode` mirrors the state machine:
   NotConfigured (monitor) / AuditMode (8002/8003 events) / Enabled
   (8004 blocks).
8. **Enforcement pilot (exit criterion).** Run redis in global `audit`
   with the audit-form artifacts applied, watch rules 100011/100031/
   100041 plus telemetry 100111 for the declared window, then graduate
   sections to `enforce` one at a time. `labValidation` in
   `<name>-enforce.manifest.json` stays `pending` until the pilot
   completes in the lab.

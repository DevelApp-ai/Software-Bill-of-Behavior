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

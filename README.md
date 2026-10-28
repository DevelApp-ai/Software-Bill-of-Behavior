# Software-Bill-of-Behavior

**SBoB → Wazuh transpiler** — compile [Software Bill of Behavior](https://billofbehavior.com/bob/docs/spec/) (SBoB) workload manifests into Wazuh detection artifacts: audit rules, CDB allowlists, custom decoders, and drift rulesets.

Monitor **Linux**, **Windows**, and **Kubernetes** deployments from one declared behavioral contract. The design is specified in [docs/TDS.md](docs/TDS.md); implementation is tracked in [issue #1](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/1).

## Status

| Milestone | Scope | Issue |
| --- | --- | --- |
| M1 | Transpiler core: SBoB YAML parser, validator, IR, linter, deterministic rule-ID allocation, PCRE2 wildcard compiler, Linux/k8s-node codegen | [#2](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/2) |
| M2 | Windows Sysmon codegen (EIDs 1/3/11/22; args-drift heuristic, opens file-create partial) — implemented, lab validation pending | [#3](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/3) |
| M3 | Kubernetes attribution | [#4](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/4) |
| M4 | rulePolicies + coverage manifest + CI gates | [#5](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/5) |
| M5 | GitOps deployment + ops runbook | [#6](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/6) |
| M6 | Phase 2: Sigma/Sysmon, Velociraptor, MDE, Falco codegen | [#7](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/7) |
| M7 | Phase 3: enforcement | [#8](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/issues/8) |

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
   │ <name>.manifest.json              coverage notes               │
   │ checksums.txt                     sha256 inventory             │
   └───────────────────────────────────────────────────────────┘
```

Drift detection is allowlist-based: every observed `execve`/`open`/`connect` that is **not** declared in the SBoB raises a Wazuh alert. Allowlists are enforced with CDB list lookups (`not_match_key` / `not_address_match_key`) plus negated PCRE2 alternations for wildcarded entries — see [TDS §5](docs/TDS.md).

## Usage

Requires Node.js ≥ 22 (uses native TypeScript type stripping; **zero npm dependencies**).

```sh
# transpile a workload into a Wazuh bundle (linux target)
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle --registry docs/sbob-registry.yaml --skip-signature-verify

# windows target (Sysmon EIDs 1/3/11/22; requires Wazuh >= 4.4 and the shipped ruleset parent rule 61600)
node src/cli.ts transpile --sbob sbobs/redis.yaml --out dist/bundle-win --target windows --registry docs/sbob-registry.yaml --skip-signature-verify

# schema-validate only
node src/cli.ts validate --sbob sbobs/redis.yaml

# tests (unit + golden bundle comparison)
node --test test/*.test.ts
```

Workload rule IDs are derived deterministically from the slot registry (`docs/sbob-registry.yaml`):
`rule_id = 100000 + slot*100 + section_code*10 + variant` — see [TDS §6.1](docs/TDS.md).

## Repository layout

```
sbobs/                  example SBoB manifests
docs/TDS.md             technical design specification
docs/sbob-registry.yaml workload slot registry (deterministic rule IDs)
src/                    transpiler sources (zero-dependency TypeScript)
test/                   unit tests + golden bundle + lab corpus
scripts/                golden regeneration + wazuh-logtest lab harness
```

## Lab validation

Generated bundles carry a `LAB VALIDATION PENDING` banner until validated against a live Wazuh manager. Run `scripts/logtest-corpus.sh` (linux) or `scripts/logtest-corpus.sh windows` on a lab manager with the bundle installed: the benign corpus must stay silent and the drift corpus must fire the mapped drift rules (linux: 100011/100021/100031; windows: 100016/100006/100026/100036/100007).

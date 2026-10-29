# Phase-2 engine live lanes (CI)

The phase-2 engines (M6, [docs/engine-matrix.md](engine-matrix.md)) are validated on two levels: the unit/golden suites pin the generated artifacts byte-for-byte, and the live lanes in [`.github/workflows/engines-lab.yml`](../.github/workflows/engines-lab.yml) prove the artifacts against **the engines' own tooling** — the same disposable-lab pattern as the Wazuh [`lab-validate`](../.github/workflows/lab-validate.yml) matrix, per engine:

| engine | live lane | pinned tool | what it proves |
| --- | --- | --- | --- |
| sigma | `sigma check` on every generated rule | sigma-cli 4.0.0 | every rule is a schema-valid Sigma rule |
| logpoint | `sigma convert -t logpoint` through LogPoint's official pySigma backend (`logpoint_linux` + `logpoint_windows` pipelines) | pysigma-backend-logpoint 1.0.2 | the sigma bundle converts through LogPoint's own field taxonomy — the same mapping (`type`→`event_type`, `exe`/`name`→`path`) the native `--target logpoint` rules are pinned to |
| falco | `falco --validate` on the generated rules file | falcosecurity/falco:0.37.1 container (the image the generated DaemonSet pins) | the rules parse and validate against the Falco engine version deployments actually run |
| velociraptor | `velociraptor query -f` executes every sweep query extracted from the artifact (`scripts/extract-vql.ts`) | Velociraptor 0.77.3 release binary | the generated VQL parses and runs against live system state (`pslist()`/`netstat()` on the runner) |
| mde | golden-only | — | the KQL hunts are pinned by the unit suite; a live lane requires a Defender tenant and no CI-substitutable KQL syntax validator exists — documented gap, revisit when a tenant pilot lands |

The lanes run nightly (03:37 UTC, after the Wazuh lab-validate matrix), on `workflow_dispatch`, and on PRs carrying the **`engines-lab`** label — ordinary PRs stay fast.

Notes:

- LogPoint itself is a commercial SIEM (no container lane exists), so the LogPoint lane validates **through LogPoint's own conversion tooling** rather than a live instance; the native `--target logpoint` rules use exactly the field taxonomy that backend ships, and the lane is the cross-check that the mapping has not drifted.
- Engine manifests keep `labValidation: "pending"` — the banner/evidence machinery ([docs/lab-validation.yaml](lab-validation.yaml)) is Wazuh-manager-specific; extending the evidence format to engine lanes is a recorded follow-up.

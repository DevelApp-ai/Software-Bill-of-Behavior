# The sbob-diff-gate promotion demo (issue #22)

The `sbob-diff-gate` composite action ([`action.yml`](../action.yml)) is this
repo's CI form of the M8 release gate: it wraps `sbobctl diff`, writes the
delta report (machine-readable JSON + verdict markdown), uploads it as a
workflow artifact, comments it on the triggering PR when a token is given,
and propagates the `--fail-on` exit code.

This document is the standing record of the promotion-flow demo that closed
issue #22's exit criteria. The demo ran as **PR #27**
(`demo/promotion-diff-gate`): a PR from a `demo/promotion-*` branch, where the
**promotion-gate** job of
[`.github/workflows/diff-gate-demo.yml`](../.github/workflows/diff-gate-demo.yml)
runs the action on the drifted fixture pair
([`base.yaml`](../test/diffgate-fixtures/base.yaml) →
[`drifted.yaml`](../test/diffgate-fixtures/drifted.yaml)) and — exactly like a
real promotion — must fail red.

## The demonstrated evidence

PR #27's **promotion-gate** check failed as a promotion gate should
([run 40920040134](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/actions/runs/40920040134),
2026-10-29):

- **Δ = 45 — verdict MANDATORY** (immediate review: +5 class present), exit 1
  under the default `--fail-on mandatory`;
- the markdown delta report was commented on the PR by the action
  (`github-token` input) and the machine-readable JSON report was attached as
  the `sbob-diff-gate` workflow artifact;
- the scored delta is exactly the committed golden report
  ([`expected-report.json`](../test/diffgate-fixtures/expected-report.json)):

| section | change | entry | weight | note |
|---|---|---|---|---|
| capabilities | added | CAP_SYS_PTRACE | 5 | new Linux capability |
| egress | added | peer id:stripe-api: dns *.cdn.example.com. | 3 | external DNS name |
| egress | added | peer id:internal-metrics: dns metrics.internal.svc. | 2 | internal DNS name |
| egress | added | peer id:internal-metrics: port TCP/443 | 2 | |
| egress | added | peer id:stripe-api: port TCP/80 | 2 | |
| egress | added | peer id:unknown-egress: ip 203.0.113.7/32 | 2 | |
| egress | added | peer id:unknown-egress: port TCP/8443 | 2 | |
| execs | added | /tmp/payload | 4 | outside the package namespace |
| execs | added | /usr/bin/redis-check-aof | 1 | inside the package namespace |
| execs | removed | /bin/sh | 1 | |
| ingress | added | peer id:admin-vpn: ip 192.0.2.0/24 | 2 | |
| ingress | added | peer id:admin-vpn: port TCP/22 | 2 | |
| opens | added | /var/log/webcache/*.log | 2 | write-flag open path |
| opens | modified | /etc/resolv.conf | 2 | write flags added: O_WRONLY |
| opens | widened | /data/* | 2 | widens a prior pattern |
| opens | added | /etc/hosts | 1 | read-only open path |
| rulePolicies | added | module-load: processAllowed ldconfig | 5 | new signature-rule exemption |
| rulePolicies | added | namespace-change: processAllowed nsjail | 5 | new signature-rule exemption (new policy) |

**Δ = 45** — verdict **MANDATORY** (immediate review: +5 class present).
Reported but unweighted (v1): `endpoints: added outbound :8080/health`
(unweighted in v1 — not observable from Phase 1 telemetry).

## The contract as tests

The demo PR is closed; what it demonstrated is asserted continuously instead,
so the evidence cannot rot in an open PR:

- **`fixture-verify` job (every PR)** runs the composite action itself on the
  committed fixture pair: the clean pair (base vs base) must pass; the drifted
  pair must fail with `verdict=mandatory`, `score=45`, `exit-code=1` — asserted
  via `continue-on-error` + outcome checks, so ordinary PRs stay green while
  the exact values the demo demonstrated are re-proven on every PR.
- **[`test/diffgate.test.ts`](../test/diffgate.test.ts)** pins the gate output
  byte-for-byte against the golden report (Δ = 45, verdict mandatory,
  immediateReview, all 18 delta entries with their ladder weights) plus the
  threshold semantics (advisory ≥ 10, mandatory ≥ 25, any +5 class forces
  immediate review).
- **[`test/cli.test.ts`](../test/cli.test.ts)** pins the operator-facing
  exit-code contract: exit 1 on the drifted pair, exit 0 with `--fail-on none`,
  exit 1 with `--fail-on advisory`, exit 2 on an invalid level, and the
  `--report` JSON.

## Re-running the live demo

The red-check lane remains available on demand: push a branch named
`demo/promotion-*` and open a PR against `main`. The promotion-gate job runs
the action with `github-token`, so the PR gets the red MANDATORY check, the
delta-report comment and the JSON artifact. Close the demo PR afterwards —
this document is the durable record, not an open PR.

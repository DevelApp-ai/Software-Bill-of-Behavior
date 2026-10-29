#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Lab validation harness (M1/M2/M3/M4 exit criteria, issues #2/#3/#4/#5)
#
# Feeds the benign/drift corpora through a live Wazuh manager running the
# generated bundle, and asserts:
#
#   linux   (M1): benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100011 (exec), 100021 (open), 100031 (connect),
#                                   100060 (module-load sig), 100062 (ptrace sig)
#                                   [signature rules added in M4]
#   windows (M2): benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100016 (exec image), 100006 (args, TDS 7.3.4),
#                                   100026 (file create), 100036 (egress),
#                                   100007 (dns query, EID 22)
#   k8s     (M3): benign corpus  -> ZERO drift alerts (attribution info rules
#                                   100070/100071 MAY fire — they are level 0/3
#                                   attribution, not drift)
#                 drift corpus   -> 100011 (exec), 100021 (open), 100031 (connect),
#                                   100060 (module-load sig), 100062 (ptrace sig)
#                                   [signature rules added in M4];
#                                   attribution: 100071 (podmap not seeded) is
#                                   expected on a fresh install — seed the
#                                   podmap with the corpus pod uid via
#                                   scripts/sbob-podmap-refresh.sh (or append
#                                   "0f3c8ed9-9d6b-4a1c-b5f2-7c1e0a9d1234:cache-tier/redis"
#                                   plus the underscore spelling) and rerun to
#                                   watch 100071 fall silent (tier-1 resolved)
#
#   php     (PHP2Shell scenario, issue #23 / docs/php2shell-scenario.md):
#                 benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100111 (exec: /bin/sh from a hijacked
#                                   php-fpm worker, CVE-2026-109618),
#                                   100121 (open: webshell drop to /var/tmp),
#                                   100131 (connect: reverse shell/C2,
#                                   CVE-2026-109619),
#                                   100163 (memfd signature: fileless variant)
#                 The php case proves the SBoB point: entry vector unknown,
#                 post-exploit BEHAVIOR is still drift.
#
# Usage (on the lab Wazuh manager, or anywhere with wazuh-logtest):
#   ./scripts/logtest-corpus.sh [linux|windows|k8s|php]     # default: linux
#
# Requires: the bundle from `node src/cli.ts transpile --sbob sbobs/redis.yaml
# --out <dir> --target <linux|windows|k8s-node>` to be installed as a test
# ruleset the manager loads (rules/decoders/lists under etc/ossec.conf
# <ruleset> or the manager's active-response test instance). The windows
# target additionally requires the shipped ruleset (0595-win-sysmon_rules.xml,
# parent rule 61600) and Wazuh >= 4.4 (type="pcre2" field attribute). The k8s
# target additionally requires the docker-listener integration ruleset
# (0560-docker_integration_rules.xml, parent rule 87900) for rule 100074.
# wazuh-logtest reads the manager's live ruleset; it does not take a rules
# path argument.
#
# For detection testing in the Wazuh sense (JSON-asserted rule ids, session
# firedtimes continuity, and a sustained gate that proves the frequency
# children 8/120s by replaying the drift corpus 8x in one logtest session),
# use the API-driven variant: scripts/logtest-api.ts --target <target>.
# ---------------------------------------------------------------------------
set -euo pipefail

CORPUS_DIR="$(cd "$(dirname "$0")/.." && pwd)/test/corpus"
TARGET="${1:-linux}"

case "$TARGET" in
  linux)
    BENIGN="$CORPUS_DIR/redis-benign.audit"
    DRIFT="$CORPUS_DIR/redis-drift.audit"
    DRIFT_IDS=(100011 100021 100031 100060 100062)
    ;;
  windows)
    BENIGN="$CORPUS_DIR/redis-benign.win.jsonl"
    DRIFT="$CORPUS_DIR/redis-drift.win.jsonl"
    DRIFT_IDS=(100016 100006 100026 100036 100007)
    ;;
  k8s)
    BENIGN="$CORPUS_DIR/redis-benign.k8s.audit"
    DRIFT="$CORPUS_DIR/redis-drift.k8s.audit"
    DRIFT_IDS=(100011 100021 100031 100060 100062)
    ATTR_IDS=(100070 100071 100073 100074)
    ;;
  php)
    # PHP2Shell scenario (CVE-2026-109618 / CVE-2026-109619) — transpile
    # sbobs/php-fpm.yaml (slot 1) and install it beside the redis bundle.
    BENIGN="$CORPUS_DIR/php-benign.audit"
    DRIFT="$CORPUS_DIR/php-drift.audit"
    DRIFT_IDS=(100111 100121 100131 100163)
    ;;
  *)
    echo "ERROR: unknown target \"$TARGET\" (expected linux, windows, k8s or php)" >&2
    exit 2
    ;;
esac

command -v wazuh-logtest >/dev/null 2>&1 || {
  echo "ERROR: wazuh-logtest not found. Run this on the lab Wazuh manager host." >&2
  exit 2
}

echo "== [$TARGET] benign corpus: expecting NO drift alerts =="
cat "$BENIGN" | wazuh-logtest 2>/dev/null | tee /tmp/sbob-benign.out || true
for id in "${DRIFT_IDS[@]}"; do
  if grep -q "Rule id: $id" /tmp/sbob-benign.out; then
    echo "FAIL: benign corpus fired drift rule $id — see /tmp/sbob-benign.out" >&2
    case "$TARGET" in
      linux)
        echo "      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading" >&2 ;;
      php)
        echo "      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading" >&2
        echo "      (php-fpm bundle: slot 1 — rules 1001xx; see docs/php2shell-scenario.md)" >&2 ;;
      windows)
        echo "      check the shipped sysmon parent rule 61600 is loaded and the" >&2
        echo "      eventchannel decoder emits win.system.eventID / win.eventdata.*" >&2 ;;
      k8s)
        echo "      check the cgroup decoders (sbob-*-audit-cgroup*) and that the" >&2
        echo "      auditd cgroup= lines are intact" >&2 ;;
    esac
    exit 1
  fi
done
echo "OK: benign corpus fired no drift rules"
if [ "$TARGET" = "k8s" ]; then
  grep -E 'Rule id: 1000(70|71|73|74)' /tmp/sbob-benign.out || true \
    | sed 's/^/  (attribution info, allowed): /'
fi

echo "== [$TARGET] drift corpus: expecting ${DRIFT_IDS[*]} =="
cat "$DRIFT" | wazuh-logtest 2>/dev/null | tee /tmp/sbob-drift.out || true
for id in "${DRIFT_IDS[@]}"; do
  if ! grep -q "Rule id: $id" /tmp/sbob-drift.out; then
    echo "FAIL: drift rule $id did not fire — see /tmp/sbob-drift.out" >&2
    case "$TARGET" in
      linux)
        echo "      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading" >&2 ;;
      php)
        echo "      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading" >&2
        echo "      (php-fpm bundle: slot 1 — rules 1001xx; see docs/php2shell-scenario.md)" >&2 ;;
      windows)
        echo "      check the shipped sysmon parent rule 61600 is loaded and the" >&2
        echo "      eventchannel decoder emits win.system.eventID / win.eventdata.*" >&2 ;;
      k8s)
        echo "      check decoder chain (sbob.key/exe/path/saddr fields), the cgroup" >&2
        echo "      decoders, and CDB list loading" >&2 ;;
    esac
    exit 1
  fi
  echo "OK: rule $id fired"
done

if [ "$TARGET" = "k8s" ]; then
  echo "== [k8s] attribution check (informational — not a hard gate) =="
  if grep -qE 'Rule id: 1000(70|71|73|74)' /tmp/sbob-drift.out; then
    echo "OK: attribution chain fired (see above). 100071 means the podmap does"
    echo "    not contain the corpus pod uid yet — run scripts/sbob-podmap-refresh.sh"
    echo "    (it emits both cgroup spellings), reload the manager, rerun and expect"
    echo "    100071 to fall silent (tier-1 attribution resolved)."
  else
    echo "NOTE: no attribution rule fired — expected when the podmap IS seeded"
    echo "      (tier-1 resolved: 100070 alone is level 0 and does not alert) or"
    echo "      when the cgroup= field is missing on the audit lines."
  fi
fi

echo
echo "PASS ($TARGET): lab validation succeeded — update the manifest labValidation field"
echo "      and close the remaining checklist item on the tracker issue."

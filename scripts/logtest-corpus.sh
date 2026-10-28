#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Lab validation harness (M1/M2 exit criteria, issues #2/#3)
#
# Feeds the benign/drift corpora through a live Wazuh manager running the
# generated bundle, and asserts:
#
#   linux   (M1): benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100011 (exec), 100021 (open), 100031 (connect)
#   windows (M2): benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100016 (exec image), 100006 (args, TDS 7.3.4),
#                                   100026 (file create), 100036 (egress),
#                                   100007 (dns query, EID 22)
#
# Usage (on the lab Wazuh manager, or anywhere with wazuh-logtest):
#   ./scripts/logtest-corpus.sh [linux|windows]     # default: linux
#
# Requires: the bundle from `node src/cli.ts transpile --sbob sbobs/redis.yaml
# --out <dir> --target <linux|windows>` to be installed as a test ruleset the
# manager loads (rules/decoders/lists under etc/ossec.conf <ruleset> or the
# manager's active-response test instance). The windows target additionally
# requires the shipped ruleset (0595-win-sysmon_rules.xml, parent rule 61600)
# and Wazuh >= 4.4 (type="pcre2" field attribute). wazuh-logtest reads the
# manager's live ruleset; it does not take a rules path argument.
# ---------------------------------------------------------------------------
set -euo pipefail

CORPUS_DIR="$(cd "$(dirname "$0")/.." && pwd)/test/corpus"
TARGET="${1:-linux}"

case "$TARGET" in
  linux)
    BENIGN="$CORPUS_DIR/redis-benign.audit"
    DRIFT="$CORPUS_DIR/redis-drift.audit"
    DRIFT_IDS=(100011 100021 100031)
    ;;
  windows)
    BENIGN="$CORPUS_DIR/redis-benign.win.jsonl"
    DRIFT="$CORPUS_DIR/redis-drift.win.jsonl"
    DRIFT_IDS=(100016 100006 100026 100036 100007)
    ;;
  *)
    echo "ERROR: unknown target \"$TARGET\" (expected linux or windows)" >&2
    exit 2
    ;;
esac

command -v wazuh-logtest >/dev/null 2>&1 || {
  echo "ERROR: wazuh-logtest not found. Run this on the lab Wazuh manager host." >&2
  exit 2
}

echo "== [$TARGET] benign corpus: expecting NO drift alerts =="
if cat "$BENIGN" | wazuh-logtest 2>/dev/null | tee /tmp/sbob-benign.out \
   | grep -E 'Rule id: 1000[0-9]{2}'; then
  echo "FAIL: benign events fired an sbob rule — see /tmp/sbob-benign.out" >&2
  exit 1
fi
echo "OK: benign corpus is silent"

echo "== [$TARGET] drift corpus: expecting ${DRIFT_IDS[*]} =="
cat "$DRIFT" | wazuh-logtest 2>/dev/null | tee /tmp/sbob-drift.out || true
for id in "${DRIFT_IDS[@]}"; do
  if ! grep -q "Rule id: $id" /tmp/sbob-drift.out; then
    echo "FAIL: drift rule $id did not fire — see /tmp/sbob-drift.out" >&2
    case "$TARGET" in
      linux)
        echo "      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading" >&2 ;;
      windows)
        echo "      check the shipped sysmon parent rule 61600 is loaded and the" >&2
        echo "      eventchannel decoder emits win.system.eventID / win.eventdata.*" >&2 ;;
    esac
    exit 1
  fi
  echo "OK: rule $id fired"
done

echo
echo "PASS ($TARGET): lab validation succeeded — update the manifest labValidation field"
echo "      and close the remaining checklist item on the tracker issue."

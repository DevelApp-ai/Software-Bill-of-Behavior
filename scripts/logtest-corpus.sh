#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Lab validation harness (M1 exit criteria, issue #2)
#
# Feeds the benign/drift audit corpus through a live Wazuh manager running the
# generated bundle, and asserts:
#   - benign corpus  -> ZERO drift alerts (no rule id >= 100011 fires)
#   - drift corpus   -> drift rules 100011 (exec), 100021 (open),
#                       100031 (connect) each fire at least once
#
# Usage (on the lab Wazuh manager, or anywhere with wazuh-logtest):
#   ./scripts/logtest-corpus.sh
#
# Requires: the bundle from `node src/cli.ts transpile --sbob sbobs/redis.yaml
# --out <dir>` to be installed as a test ruleset the manager loads
# (rules/decoders/lists under etc/ossec.conf <ruleset> or the manager's
# active-response test instance). wazuh-logtest reads the manager's live
# ruleset; it does not take a rules path argument.
# ---------------------------------------------------------------------------
set -euo pipefail

CORPUS_DIR="$(cd "$(dirname "$0")/.." && pwd)/test/corpus"
DRIFT_IDS=(100011 100021 100031)

command -v wazuh-logtest >/dev/null 2>&1 || {
  echo "ERROR: wazuh-logtest not found. Run this on the lab Wazuh manager host." >&2
  exit 2
}

echo "== benign corpus: expecting NO drift alerts =="
if cat "$CORPUS_DIR/redis-benign.audit" | wazuh-logtest 2>/dev/null | tee /tmp/sbob-benign.out \
   | grep -E 'Rule id: (10001[1-9]|10002[1-9]|10003[1-9]|10004[0-9])'; then
  echo "FAIL: benign events fired a drift rule — see /tmp/sbob-benign.out" >&2
  exit 1
fi
echo "OK: benign corpus is silent"

echo "== drift corpus: expecting 100011, 100021, 100031 =="
cat "$CORPUS_DIR/redis-drift.audit" | wazuh-logtest 2>/dev/null | tee /tmp/sbob-drift.out || true
for id in "${DRIFT_IDS[@]}"; do
  if ! grep -q "Rule id: $id" /tmp/sbob-drift.out; then
    echo "FAIL: drift rule $id did not fire — see /tmp/sbob-drift.out" >&2
    echo "      check decoder chain (sbob.key/exe/path/saddr fields) and CDB list loading" >&2
    exit 1
  fi
  echo "OK: rule $id fired"
done

echo
echo "PASS: lab validation succeeded — update the manifest labValidation field"
echo "      and close the remaining checklist item on issue #2."

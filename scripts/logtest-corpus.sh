#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Lab validation harness (M1/M2/M3/M4 exit criteria, issues #2/#3/#4/#5, #42)
#
# Feeds the benign/drift/sustained corpora through a live Wazuh manager running
# the generated bundle, and asserts (validated on wazuh-manager 4.14.6):
#
#   linux   (M1): benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100011 (exec), 100001 (sensitive-file open
#                                   overlay — the level-12 overlay outshadows
#                                   the level-9 100021 drift parent in the
#                                   logtest display, which shows only the
#                                   highest-level matched rule per line; the
#                                   corpus open IS /etc/shadow so 100001 is
#                                   the correct display id), 100031 (connect),
#                                   100060 (module-load sig), 100062 (ptrace)
#                 sustained       -> 100012 (execs), 100022 (opens — fires on
#                                   the undeclared rogue-open rounds, whose
#                                   winner is the 100021 parent), 100032
#                                   (egress), 100009 (repeated sensitive-file
#                                   open: the sustained child of the overlay
#                                   itself; firing it there is REQUIRED
#                                   because the overlay steals the winner
#                                   context from the 100021 parent — see the
#                                   winner-context note in src/codegen/)
#   windows (M2): benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100016 (exec image), 100006 (args, TDS 7.3.4),
#                                   100026 (file create), 100036 (egress),
#                                   100007 (dns query, EID 22)
#                 sustained       -> 100017, 100027, 100037 (8 passes of the
#                                   drift corpus in ONE logtest session)
#                 NOTE: the 4.14 wazuh-logtest CLI always pre-processes stdin
#                 as syslog-format agent events, so it cannot drive the
#                 eventchannel/JSON windows chain. This script replays the
#                 windows corpora through the logtest session socket directly
#                 (scripts/logtest-win-replay.py — same engine the manager
#                 runs, log_format=json). It requires the ROOT-ANCHOR
#                 VALIDATION TRANSFORM to be applied to the installed rules
#                 file beforehand (production file: '<if_sid>61600</if_sid>';
#                 validation copy: '<decoded_as>json</decoded_as>' — identical
#                 downstream conditions; see .github/workflows/lab-validate.yml
#                 which applies it at install time and restores afterwards).
#   k8s     (M3): benign corpus  -> ZERO drift alerts
#                 drift corpus   -> same ids as linux (same slot-0 band)
#                 sustained       -> same ids as linux; attribution is INERT
#                 on 4.14.6 (the shipped auditd decoder family preempts
#                 custom cgroup-attribution decoder roots, so tier-1 pod
#                 attribution runs manager-side only via the podmap list —
#                 informational rules 100070/100071/100073/100074 are allowed
#                 on both corpora and never gate)
#   php     (PHP2Shell scenario, issue #23 / docs/php2shell-scenario.md):
#                 benign corpus  -> ZERO drift alerts
#                 drift corpus   -> 100111 (exec: /bin/sh from a hijacked
#                                   php-fpm worker, CVE-2026-109618),
#                                   100121 (open: webshell drop to /var/tmp),
#                                   100131 (connect: reverse shell/C2,
#                                   CVE-2026-109619), 100163 (memfd sig)
#                 sustained       -> 100112, 100122, 100132, 100109
#                 The php case proves the SBoB point: entry vector unknown,
#                 post-exploit BEHAVIOR is still drift.
#
# Usage (on the lab Wazuh manager, or anywhere with wazuh-logtest):
#   ./scripts/logtest-corpus.sh [linux|windows|k8s|php]     # default: linux
#
# Requires: the bundle from `node src/cli.ts transpile --sbob sbobs/redis.yaml
# --out <dir> --target <linux|windows|k8s-node>` to be installed as a test
# ruleset the manager loads (rules/decoders/lists under etc/ossec.conf
# <ruleset> — every CDB list MUST be declared or the loader drops the rules
# that reference it, and /var/ossec/etc/rules/local_rules.xml must not carry
# a rule id inside the SBoB 100xxx band: stock 4.14.6 ships example rule
# 100001, which collides with the slot-0 band — see lab-validate.yml).
# The windows target additionally requires the shipped ruleset
# (0595-win-sysmon_rules.xml, parent rule 61600), python3, and the
# ROOT-ANCHOR VALIDATION TRANSFORM described above. The k8s target
# additionally requires the docker-listener integration ruleset
# (0560-docker_integration_rules.xml, parent rule 87900) for rule 100074.
# wazuh-logtest reads the manager's live ruleset; it does not take a rules
# path argument.
#
# Wazuh 4.14 logtest output spells matched rules as "\tid: 'NNNNNN'" on
# stderr (older engines printed "Rule id: NNNNNN" — both are grepped).
#
# For detection testing in the Wazuh sense (JSON-asserted rule ids + the same
# sustained gate via the PUT /logtest API), use scripts/logtest-api.ts.
# ---------------------------------------------------------------------------
set -euo pipefail

CORPUS_DIR="$(cd "$(dirname "$0")/.." && pwd)/test/corpus"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-linux}"

# matched-rule grep: accepts both the 4.14 spelling (id: 'NNNNNN') and the
# older "Rule id: NNNNNN" spelling; analysis goes to stderr in 4.14 -> 2>&1
fired_grep() { grep -qE "(Rule id: |[[:space:]]id: ')$1'|id=$1([^0-9]|$)" "$2"; }

case "$TARGET" in
  linux)
    BENIGN="$CORPUS_DIR/redis-benign.audit"
    DRIFT="$CORPUS_DIR/redis-drift.audit"
    # 100001 NOT 100021: the sensitive-file overlay (level 12) outshadows the
    # drift parent (level 9) in the display; the drift open is /etc/shadow.
    DRIFT_IDS=(100011 100001 100031 100060 100062)
    SUSTAINED="$CORPUS_DIR/redis-sustained.audit"
    SUSTAINED_IDS=(100012 100022 100032 100009)
    ;;
  windows)
    BENIGN="$CORPUS_DIR/redis-benign.win.jsonl"
    DRIFT="$CORPUS_DIR/redis-drift.win.jsonl"
    DRIFT_IDS=(100016 100006 100026 100036 100007)
    SUSTAINED=""                       # built below: 8 passes of the drift corpus
    SUSTAINED_IDS=(100017 100027 100037)
    ;;
  k8s)
    BENIGN="$CORPUS_DIR/redis-benign.k8s.audit"
    DRIFT="$CORPUS_DIR/redis-drift.k8s.audit"
    DRIFT_IDS=(100011 100001 100031 100060 100062)
    SUSTAINED="$CORPUS_DIR/redis-sustained.audit"
    SUSTAINED_IDS=(100012 100022 100032 100009)
    ATTR_IDS=(100070 100071 100073 100074)
    ;;
  php)
    # PHP2Shell scenario (CVE-2026-109618 / CVE-2026-109619) — transpile
    # sbobs/php-fpm.yaml (slot 1) and install it beside the redis bundle.
    BENIGN="$CORPUS_DIR/php-benign.audit"
    DRIFT="$CORPUS_DIR/php-drift.audit"
    DRIFT_IDS=(100111 100121 100131 100163)
    SUSTAINED="$CORPUS_DIR/php-sustained.audit"
    SUSTAINED_IDS=(100112 100122 100132 100109)
    ;;
  *)
    echo "ERROR: unknown target \"$TARGET\" (expected linux, windows, k8s or php)" >&2
    exit 2
    ;;
esac

if [ "$TARGET" = "windows" ]; then
  command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 not found — the windows target replays via" >&2
    echo "scripts/logtest-win-replay.py against the logtest session socket." >&2
    exit 2
  }
  DRIVER="$SCRIPT_DIR/logtest-win-replay.py"
  [ -f "$DRIVER" ] || { echo "ERROR: $DRIVER missing" >&2; exit 2; }
  # the root-anchor validation transform must have been applied at install
  # time (production: <if_sid>61600</if_sid> / validation: <decoded_as>json</decoded_as>)
  if ! grep -q '<decoded_as>json</decoded_as>' /var/ossec/etc/rules/*redis_windows*.xml 2>/dev/null; then
    echo "WARN: root-anchor validation transform not detected on the installed" >&2
    echo "      windows rules file — the replay will decode but match nothing." >&2
    echo "      (see the windows target in .github/workflows/lab-validate.yml)" >&2
  fi
  replay() { python3 "$DRIVER" "$1" 2>&1; }   # one logtest session per run
else
  command -v wazuh-logtest >/dev/null 2>&1 || {
    echo "ERROR: wazuh-logtest not found. Run this on the lab Wazuh manager host." >&2
    exit 2
  }
  replay() { cat "$1" | wazuh-logtest 2>&1; }   # one logtest session per run
fi

echo "== [$TARGET] benign corpus: expecting NO drift alerts =="
replay "$BENIGN" | tee /tmp/sbob-benign.out || true
for id in "${DRIFT_IDS[@]}"; do
  if fired_grep "$id" /tmp/sbob-benign.out; then
    echo "FAIL: benign corpus fired drift rule $id — see /tmp/sbob-benign.out" >&2
    case "$TARGET" in
      linux|php)
        echo "      check decoder chain (audit.key/exe/path fields) and CDB list declarations" >&2 ;;
      windows)
        echo "      check the sysmon parent chain and win.eventdata.* field conditions" >&2 ;;
      k8s)
        echo "      check decoder chain, CDB list declarations; attribution is INERT on 4.14.6" >&2 ;;
    esac
    exit 1
  fi
done
echo "OK: benign corpus fired no drift rules"
if [ "$TARGET" = "k8s" ]; then
  grep -E "(Rule id: |[[:space:]]id: ')1000(70|71|73|74)'" /tmp/sbob-benign.out || true \
    | sed 's/^/  (attribution info, allowed): /'
fi

echo "== [$TARGET] drift corpus: expecting ${DRIFT_IDS[*]} =="
replay "$DRIFT" | tee /tmp/sbob-drift.out || true
for id in "${DRIFT_IDS[@]}"; do
  if ! fired_grep "$id" /tmp/sbob-drift.out; then
    echo "FAIL: drift rule $id did not fire — see /tmp/sbob-drift.out" >&2
    case "$TARGET" in
      linux|php)
        echo "      check decoder chain (audit.key/exe/path fields) and CDB list declarations" >&2 ;;
      windows)
        echo "      check the sysmon parent chain and win.eventdata.* field conditions" >&2 ;;
      k8s)
        echo "      check decoder chain, CDB list declarations; attribution is INERT on 4.14.6" >&2 ;;
    esac
    exit 1
  fi
  echo "OK: rule $id fired"
done

echo "== [$TARGET] sustained corpus: expecting ${SUSTAINED_IDS[*]} (frequency 8/120s, one session) =="
if [ "$TARGET" = "windows" ]; then
  SUSTAINED=/tmp/sbob-win-sustained.jsonl
  : > "$SUSTAINED"
  for _ in 1 2 3 4 5 6 7 8; do cat "$DRIFT" >> "$SUSTAINED"; done
fi
if [ ! -f "$SUSTAINED" ]; then
  echo "FAIL: sustained corpus $SUSTAINED not found" >&2
  exit 1
fi
replay "$SUSTAINED" | tee /tmp/sbob-sustained.out || true
for id in "${SUSTAINED_IDS[@]}"; do
  if ! fired_grep "$id" /tmp/sbob-sustained.out; then
    echo "FAIL: sustained rule $id did not fire — see /tmp/sbob-sustained.out" >&2
    echo "      frequency children need 8 parent matches within 120s in ONE logtest" >&2
    echo "      session (wazuh 4.14: the parent must also WIN the matched-rule" >&2
    echo "      selection — the overlay-sustained child 100009/100109 covers the" >&2
    echo "      sensitive-file rounds exactly because the overlay steals the parent slot)" >&2
    exit 1
  fi
  echo "OK: sustained rule $id fired"
done

if [ "$TARGET" = "k8s" ]; then
  echo "== [k8s] attribution check (informational — INERT on 4.14.6, never a gate) =="
  if grep -qE "(Rule id: |[[:space:]]id: ')1000(70|71|73|74)'" /tmp/sbob-drift.out; then
    echo "OK: attribution chain fired. Tier-1 cgroup attribution is INERT on"
    echo "    4.14.6 (the shipped auditd decoder family preempts custom roots);"
    echo "    these rules document the design shape and stay level 0/informational."
  else
    echo "NOTE: no attribution rule fired — expected on 4.14.6 (attribution is"
    echo "      manager-side only via the podmap list; corpus cgroup fields do"
    echo "      not reach the rule engine through the shipped decoder family)."
  fi
fi

echo
echo "PASS ($TARGET): lab validation succeeded — update the manifest labValidation field"
echo "      and close the remaining checklist item on the tracker issue."

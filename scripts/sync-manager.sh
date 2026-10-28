#!/bin/sh
# sync-manager.sh — deploy a sbobctl bundle into the Wazuh manager layout (M5, TDS 10).
#
# Usage:
#   scripts/sync-manager.sh <bundle-dir> [--root /var/ossec] [--dry-run]
#
# Mapping (bundle → manager):
#   wazuh/rules/sbob/*.xml        → $ROOT/rules/sbob_<file>     (flattened — the Wazuh
#                                                                   rules loader does not recurse)
#   wazuh/decoders/sbob/*.xml     → $ROOT/decoders/sbob_<file>  (flattened)
#   wazuh/lists/sbob/**           → $ROOT/lists/sbob/**         (paths kept — rule <list>
#                                                                   src is lists-root-relative)
#   wazuh/agent-conf/sbob/<n>.xml → $ROOT/etc/shared/sbob-<n>/agent.conf
#                                   (concatenated with <n>-k8s.xml when both exist;
#                                   multiple wodle blocks are valid side-by-side)
#   wazuh/agent-conf/sbob/<n>-audit-digest.sh → $ROOT/etc/shared/sbob-<n>/
#   wazuh/active-response/bin/*.sh → $ROOT/active-response/bin/ (M7 —
#                                   manager copy = distribution source; the
#                                   agent rollout is in runbook §9)
#   wazuh/manager/**, manifests, checksums     → informational, not deployed
#
# The manager reloads rules/decoders/lists on restart (wazuh-control restart).
# audit.rules fragments are NOT hot-deployable — nodes need the audit rollout
# procedure from docs/runbook.md; the config-check rule (8,3) tells you which
# nodes still need it.
set -eu

BUNDLE=""
ROOT="/var/ossec"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --root)   ROOT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) if [ -n "$BUNDLE" ]; then echo "unexpected argument: $1" >&2; exit 2; fi
       BUNDLE="$1"; shift ;;
  esac
done

if [ -z "$BUNDLE" ] || [ ! -d "$BUNDLE" ]; then
  echo "usage: scripts/sync-manager.sh <bundle-dir> [--root /var/ossec] [--dry-run]" >&2
  exit 2
fi

# copy (or announce, when --dry-run) ------------------------------------------------------
# cp_deploy <src> <dst>   — dst is a file path
cp_deploy() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would copy: $1 -> $2"
  else
    mkdir -p "$(dirname "$2")"
    cp "$1" "$2"
    echo "copied:     $1 -> $2"
  fi
}

RULES="$BUNDLE/wazuh/rules/sbob"
DECODERS="$BUNDLE/wazuh/decoders/sbob"
LISTS="$BUNDLE/wazuh/lists"
AGENTCONF="$BUNDLE/wazuh/agent-conf/sbob"
ARBIN="$BUNDLE/wazuh/active-response/bin"

# 1. rules + decoders: flatten (the Wazuh loader does not recurse)
if [ -d "$RULES" ]; then
  for f in "$RULES"/*.xml; do
    [ -e "$f" ] || continue
    cp_deploy "$f" "$ROOT/rules/sbob_$(basename "$f")"
  done
fi
if [ -d "$DECODERS" ]; then
  for f in "$DECODERS"/*.xml; do
    [ -e "$f" ] || continue
    cp_deploy "$f" "$ROOT/decoders/sbob_$(basename "$f")"
  done
fi

# 2. CDB lists: keep relative paths (rule <list> src is lists-root-relative)
if [ -d "$LISTS" ]; then
  ( cd "$LISTS" && find sbob -type f 2>/dev/null ) | while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    cp_deploy "$LISTS/$rel" "$ROOT/lists/$rel"
  done
fi

# 3. agent-conf fragments: concatenate <n>.xml + <n>-k8s.xml into the group agent.conf
#    (<n>-k8s.xml is folded into the base fragment's agent.conf; a standalone
#    -k8s fragment — k8s-only deploy — becomes its own agent.conf)
if [ -d "$AGENTCONF" ]; then
  for f in "$AGENTCONF"/*.xml; do
    [ -e "$f" ] || continue
    base="$(basename "$f" .xml)"
    name="${base%-k8s}"
    # the -k8s fragment is handled with its base fragment (or standalone below)
    if [ "$name" != "$base" ] && [ -e "$AGENTCONF/$name.xml" ]; then
      continue
    fi
    group_dir="$ROOT/etc/shared/sbob-$name"
    agent_conf="$group_dir/agent.conf"
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "would write: $AGENTCONF/$name.xml (+ $name-k8s.xml when present) -> $agent_conf"
    else
      mkdir -p "$group_dir"
      cat "$f" > "$agent_conf"
      if [ -e "$AGENTCONF/$name-k8s.xml" ] && [ "$AGENTCONF/$name-k8s.xml" != "$f" ]; then
        printf '\n' >> "$agent_conf"
        cat "$AGENTCONF/$name-k8s.xml" >> "$agent_conf"
      fi
      echo "wrote:      $agent_conf (workload group sbob-$name)"
    fi
  done
  # digest scripts ride along in the same group shared dir
  for f in "$AGENTCONF"/*.sh; do
    [ -e "$f" ] || continue
    cp_deploy "$f" "$ROOT/etc/shared/sbob-$(basename "$f" | sed 's/-audit-digest\.sh$//')/$(basename "$f")"
  done
fi

# 3b. active-response scripts (M7, TDS 14.1): the manager's copy is the
#     distribution source; agents fetch them per the runbook §9 rollout
#     (they are NOT hot-deployable via agent.conf)
if [ -d "$ARBIN" ]; then
  for f in "$ARBIN"/*.sh; do
    [ -e "$f" ] || continue
    cp_deploy "$f" "$ROOT/active-response/bin/$(basename "$f")"
  done
fi

# 4. post-sync hint
echo ""
echo "Done. Restart the manager to load rules/decoders/lists:  wazuh-control restart"
echo "Then bind each node's agent to the sbob-<name> group (agent.conf) and roll out"
echo "the audit fragment per docs/runbook.md — audit rules are NOT hot-reloadable;"
echo "rule (8,3) config-check fires until each node's key set matches the bundle."

#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# sbob k8s podmap refresher (M3, issue #4)
#
# Rebuilds the sbob/k8s/podmap CDB list on a Kubernetes node:
#
#   key   = pod uid, in BOTH cgroup spellings (hex UUID):
#             <uid-with-dashes>      cgroup v1 + cgroup v2 dash-variant
#             <uid-with-underscores> cgroup v2/systemd (kubelet escapes dashes)
#           — CDB lookups are exact-match, so both forms are emitted per pod.
#   value = namespace/podname (triage only; Wazuh cannot inject list values
#           into alert fields — TDS 7.3.2 deviation)
#
# Backends, in order of preference:
#   1. crictl   (containerd/CRI-O nodes)   — kubeadm, most managed k8s
#   2. docker   (dockershim-era nodes)     — pod labels io.kubernetes.*
#
# Usage:
#   ./scripts/sbob-podmap-refresh.sh [output-path]   # default:
#       /var/ossec/etc/lists/sbob/k8s/podmap (manager-side path; run on the
#       manager or copy the file there — the LIST is read by the manager).
#       Run with SBOB_PODMAP_STDOUT=1 to print to stdout instead (no install).
#
# Schedule it (the podmap goes stale as pods churn; stale maps surface as
# attribution-stale alerts, rule <band>71):
#   systemd: OnCalendar=*:0/2 timer calling this script
#   cron:    */2 * * * * root /usr/local/bin/sbob-podmap-refresh.sh
#
# After every refresh the manager must reload lists (CDB lists are cached):
#   # systemctl restart wazuh-manager        (or your equivalent reload path)
# ---------------------------------------------------------------------------
set -euo pipefail

PODMAP_PATH="${1:-/var/ossec/etc/lists/sbob/k8s/podmap}"

write_entries() {
  # reads "uid namespace name" TSV lines on stdin, writes CDB entries
  while read -r uid ns name; do
    [ -n "$uid" ] || continue
    printf '%s:%s/%s\n' "$uid" "$ns" "$name"
    printf '%s:%s/%s\n' "${uid//-/_}" "$ns" "$name"
  done
}

collect_crictl() {
  crictl pods -o go-template='{{range .items}}{{.metadata.uid}} {{.metadata.namespace}} {{.metadata.name}}{{"\n"}}{{end}}'
}

collect_docker() {
  for id in $(docker ps -q); do
    docker inspect --format '{{index .Config.Labels "io.kubernetes.pod.uid"}} {{index .Config.Labels "io.kubernetes.pod.namespace"}} {{index .Config.Labels "io.kubernetes.pod.name"}}' "$id"
  done | sort -u
}

if [ -n "${SBOB_PODMAP_STDOUT:-}" ]; then
  OUT="/dev/stdout"
  TMP=""
else
  TMP="$(mktemp)"
  OUT="$TMP"
  trap 'rm -f "$TMP"' EXIT
fi

{
  echo "# sbob k8s podmap — refreshed $(date -u +%Y-%m-%dT%H:%M:%SZ) by scripts/sbob-podmap-refresh.sh"
  echo "# key = pod uid (both cgroup spellings); value = namespace/podname"
  echo "# node runtime data — do not edit by hand; reload with: systemctl restart wazuh-manager"
} > "$OUT"

if command -v crictl >/dev/null 2>&1; then
  collect_crictl | write_entries >> "$OUT"
  BACKEND="crictl"
elif command -v docker >/dev/null 2>&1; then
  collect_docker | write_entries >> "$OUT"
  BACKEND="docker"
else
  echo "ERROR: neither crictl nor docker found — run this on a Kubernetes node." >&2
  exit 2
fi

COUNT=$(( $(grep -c -v '^#' "$OUT" || true) ))
echo "podmap: $COUNT CDB entries ($BACKEND backend)"

if [ -z "$TMP" ]; then
  : # stdout mode; nothing to install
else
  install -m 0640 "$TMP" "$PODMAP_PATH"
  echo "installed: $PODMAP_PATH"
  echo "REMINDER: reload lists on the manager (CDB lists are cached at load):"
  echo "  systemctl restart wazuh-manager"
fi

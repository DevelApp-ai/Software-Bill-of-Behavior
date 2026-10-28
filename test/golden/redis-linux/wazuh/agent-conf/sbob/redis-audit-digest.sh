#!/bin/sh
# sbob-audit-digest.sh — emit the sbob audit key-set digest for the config-check rule (M5, TDS 10.1).
# Output: 'sbob-audit-digest: <sha256>' consumed by the sbob-*-config-check decoder.
# The digest covers the sorted unique '-k sbob…' keys installed on this node;
# it is compared against the bundle's expected digest by rule (8,3) on the manager.
# Lab-validation caveat: confirm the auditctl -l key rendering (quoted vs bare)
# on the target OS during the pilot — see docs/runbook.md.
set -u
auditctl -l 2>/dev/null \
  | grep -oE -- '-k sbob[a-zA-Z0-9_.-]+' \
  | sed 's/^-k //' \
  | sort -u \
  | sha256sum \
  | awk '{print "sbob-audit-digest: " $1}'

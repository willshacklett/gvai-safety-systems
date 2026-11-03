#!/usr/bin/env bash
# One-time Lab-01 bootstrap for the READ-ONLY CI validation runner.
#
# Default is a DRY RUN that only prints what it would do. Pass --execute to apply.
# It creates ONE unprivileged system user (gvai-ci, no extra groups, no shell, no sudo), installs a
# root-owned read-only collector and a hardened (disabled) systemd unit.
# It never: enables/starts anything, touches gvai-* STOP-gate/backend/operator users or paths,
# changes firewall/DNS/ssh/credentials, installs Docker, edits sudoers, or handles secrets.
# The GitHub runner token is entered by the founder by hand (see docs); it is never in this file.
set -euo pipefail
umask 077

EXECUTE=0
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "${1:-}" == "--execute" ]] && EXECUTE=1
[[ $# -le 1 ]] || { echo "usage: $0 [--execute]" >&2; exit 2; }

CI_USER=gvai-ci
CI_HOME=/var/lib/gvai-ci
LIBEXEC=/usr/local/libexec/gvai-ci
UNIT=/etc/systemd/system/gvai-ci-runner.service

say() { printf '%s\n' "$*"; }
act() { if [[ $EXECUTE -eq 1 ]]; then "$@"; else say "[dry-run] $*"; fi; }

# Fail-closed preflight (read-only).
[[ $EUID -eq 0 ]] || { say "must run as root (use the DigitalOcean web console)"; exit 1; }
# shellcheck source=/dev/null
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == "24.04" ]] || { say "refusing: not Ubuntu 24.04"; exit 1; }
for f in lab01_readonly_collect.py gvai-ci-runner.service; do
  [[ -f "$SRC_DIR/$f" && ! -L "$SRC_DIR/$f" ]] || { say "missing or symlink: $f"; exit 1; }
done
if id "$CI_USER" >/dev/null 2>&1; then
  extra="$(id -nG "$CI_USER" | tr ' ' '\n' | grep -vx "$CI_USER" || true)"
  [[ -z "$extra" ]] || { say "refusing: $CI_USER already has extra groups: $extra"; exit 1; }
fi
for u in gvai-gate gvai-backend gvai-operator gvai-api gvai-proxy; do
  id -nG "$CI_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$u" && { say "refusing: $CI_USER in $u"; exit 1; }
done

if ! id "$CI_USER" >/dev/null 2>&1; then
  act useradd --system --user-group --home-dir "$CI_HOME" --no-create-home \
      --shell /usr/sbin/nologin "$CI_USER"
fi
act install -d -o "$CI_USER" -g "$CI_USER" -m 0700 "$CI_HOME" "$CI_HOME/runner"
act install -d -o root -g root -m 0755 "$LIBEXEC"
act install -o root -g root -m 0755 "$SRC_DIR/lab01_readonly_collect.py" "$LIBEXEC/lab01-readonly-collect"
act install -o root -g root -m 0644 "$SRC_DIR/gvai-ci-runner.service" "$UNIT"
say "installed collector sha256 (record this in the founder log):"
sha256sum "$SRC_DIR/lab01_readonly_collect.py"
say "NOT enabled or started. Next: docs/lab01_secure_deployment_pipeline_v1.md section 'One-time setup'."

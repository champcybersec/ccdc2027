#!/bin/sh
# deploy_team_ca.sh — trust the TEAM CA for specific users only, via a
# `cert-authority` line in their authorized_keys. POSIX sh. Run as root on the box.
#
# Why per-user and not TrustedUserCAKeys: that file belongs to the scoring PKI
# (rotated automatically) — editing it can break scoring or get overwritten.
#
#   sh deploy_team_ca.sh team_ca.pub root,blueadmin          # dry run
#   sh deploy_team_ca.sh team_ca.pub root,blueadmin --apply
#
# Patch OpenSSH first (CVE-2026-35414 involves the authorized_keys principals option);
# this script deliberately writes NO principals= option — certs must list the username.

set -eu
CAPUB=${1:?team_ca.pub}; USERS=${2:?comma list of users}; APPLY=0
[ "${3:-}" = "--apply" ] && APPLY=1
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
ssh-keygen -lf "$CAPUB" >/dev/null 2>&1 || { echo "not a valid public key: $CAPUB"; exit 1; }

LINE="cert-authority $(awk 'NF{print $1, $2; exit}' "$CAPUB") flowkey-team-ca"
echo "line: $LINE"

echo "$USERS" | tr ',' '\n' | while read -r u; do
  [ -n "$u" ] || continue
  ent=$(awk -F: -v u="$u" '$1==u' /etc/passwd)
  [ -n "$ent" ] || { echo "-- $u: no such local user (AD user? create home + use getent)"; continue; }
  uid=$(echo "$ent" | cut -d: -f3); gid=$(echo "$ent" | cut -d: -f4); h=$(echo "$ent" | cut -d: -f6)
  f="$h/.ssh/authorized_keys"
  if [ -f "$f" ] && grep -qF "$(echo "$LINE" | awk '{print $3}')" "$f"; then
    echo "-- $u: already present"; continue
  fi
  echo "-- $u: add to $f"
  if [ $APPLY -eq 1 ]; then
    mkdir -p "$h/.ssh"; chown "$uid:$gid" "$h/.ssh"; chmod 700 "$h/.ssh"
    [ -f "$f" ] && cp -p "$f" "$f.bak-$(date +%H%M%S)"
    command -v chattr >/dev/null 2>&1 && chattr -i -a "$f" 2>/dev/null || true
    printf '%s\n' "$LINE" >> "$f"; chown "$uid:$gid" "$f"; chmod 600 "$f"
  fi
done
[ $APPLY -eq 1 ] && echo "Test: ssh -i ~/.ssh/id_ed25519 <user>@<box> (cert alongside key) in a NEW session." || echo "Dry run. Add --apply."

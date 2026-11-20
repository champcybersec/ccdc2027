#!/bin/sh
# team_ca.sh — run on YOUR laptop/jump box, NOT on comp boxes.
# Makes a team SSH CA and signs short-lived certs for teammates.
# This is separate from the scoring PKI and never replaces it.
#
#   sh team_ca.sh init                       # creates ./team_ca and ./team_ca.pub (passphrase prompted)
#   sh team_ca.sh sign ~/.ssh/id_ed25519.pub root,blueadmin [+2h]
#                                            # -> ~/.ssh/id_ed25519-cert.pub, valid 2h
#   sh team_ca.sh show ~/.ssh/id_ed25519-cert.pub
#
# Principals = the usernames you'll log in as. With a `cert-authority` line in
# authorized_keys (deploy_team_ca.sh), the cert must list that account's username.

set -eu
DIR=${TEAM_CA_DIR:-.}
CA="$DIR/team_ca"

case "${1:-}" in
  init)
    [ -f "$CA" ] && { echo "$CA already exists"; exit 1; }
    if [ -n "${TEAM_CA_PASS+x}" ]; then
      ssh-keygen -q -t ed25519 -f "$CA" -C "flowkey-team-ca-$(date +%Y%m%d)" -N "$TEAM_CA_PASS"
    else
      ssh-keygen -t ed25519 -f "$CA" -C "flowkey-team-ca-$(date +%Y%m%d)"
    fi
    chmod 600 "$CA"
    echo "Team CA public key (give this to deploy_team_ca.sh):"; cat "$CA.pub"
    echo "Keep $CA off the comp network."
    ;;
  sign)
    PUB=${2:?pubkey}; PRIN=${3:?principals e.g. root,blueadmin}; VAL=${4:-+2h}
    ID="$(whoami)@$(hostname)-$(date +%H%M%S)"
    ssh-keygen -s "$CA" -I "$ID" -n "$PRIN" -V "$VAL" "$PUB"
    CERT="${PUB%.pub}-cert.pub"
    ssh-keygen -Lf "$CERT" | grep -E 'Key ID|Valid|Principals' -A1
    ;;
  show)
    ssh-keygen -Lf "${2:?cert}"
    ;;
  *) sed -n '2,13p' "$0"; exit 1;;
esac

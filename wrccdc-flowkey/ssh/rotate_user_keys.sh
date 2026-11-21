#!/bin/sh
# rotate_user_keys.sh — strip every authorized_keys line you didn't allow-list,
# then add the team key to the users you name. POSIX sh (Alpine OK). Run as root.
#
# NEVER touches /etc/ssh, TrustedUserCAKeys, principals files, host keys or certs.
# Scoring runs on the SSH CA — this script only edits per-user authorized_keys.
#
# DRY RUN by default. Add --apply to write. Backups go to /root/ssh-rotate-<time>/.
#
# Usage:
#   sh rotate_user_keys.sh -t team.pub -u root,blueadmin -k 'scoring|scorebot'           # dry run
#   sh rotate_user_keys.sh -t team.pub -u root,blueadmin -k 'scoring|scorebot' --apply
#
#   -t FILE   team public key(s) to install (one or more lines)
#   -u LIST   comma list of users who get the team key (others only get stripped)
#   -k REGEX  keep lines matching this extended regex (e.g. the scoring key's comment)
#   -f FILE   keep lines whose SHA256 fingerprint is listed in FILE (one per line)
#   --keep-ca keep `cert-authority` lines (default: keep them too, but flag — see below)
#   --drop-ca drop `cert-authority` lines you didn't allow-list with -k/-f
#   --force   allow --apply with no -k/-f (you are sure no scoring key lives in authorized_keys)

set -u
TEAM="" USERS="" KEEP_RE="" KEEP_FP="" APPLY=0 DROP_CA=0 FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -t) TEAM=$2; shift 2;;
    -u) USERS=$2; shift 2;;
    -k) KEEP_RE=$2; shift 2;;
    -f) KEEP_FP=$2; shift 2;;
    --apply) APPLY=1; shift;;
    --drop-ca) DROP_CA=1; shift;;
    --keep-ca) DROP_CA=0; shift;;
    --force) FORCE=1; shift;;
    -h|--help) sed -n '2,24p' "$0"; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
if [ -n "$TEAM" ]; then
  [ -f "$TEAM" ] || { echo "team key file not found: $TEAM"; exit 1; }
  ssh-keygen -lf "$TEAM" >/dev/null 2>&1 || { echo "team key file isn't a valid public key"; exit 1; }
fi
if [ $APPLY -eq 1 ] && [ -z "$KEEP_RE" ] && [ -z "$KEEP_FP" ] && [ $FORCE -eq 0 ]; then
  echo "Refusing --apply with no -k/-f: you'd delete a scoring key if one lives in authorized_keys."
  echo "Check ssh_audit.sh output first. If none does, re-run with --force."
  exit 1
fi

TS=$(date +%Y%m%d-%H%M%S)
BK=/root/ssh-rotate-$TS
[ $APPLY -eq 1 ] && mkdir -p "$BK" && chmod 700 "$BK"
[ $APPLY -eq 1 ] && echo "MODE: APPLY (backups -> $BK)" || echo "MODE: DRY RUN (add --apply to write)"

fp_of() { t=$(mktemp); printf '%s\n' "$1" > "$t"; ssh-keygen -lf "$t" 2>/dev/null | awk '{print $2}'; rm -f "$t"; }

in_users() { echo ",$USERS," | grep -q ",$1,"; }

keep_line() { # $1 = line ; returns 0 to keep
  l=$1
  [ -n "$KEEP_RE" ] && printf '%s\n' "$l" | grep -qE -- "$KEEP_RE" && return 0
  if [ -n "$KEEP_FP" ] && [ -f "$KEEP_FP" ]; then
    fp=$(fp_of "$l"); [ -n "$fp" ] && grep -qxF "$fp" "$KEEP_FP" && return 0
  fi
  if printf '%s\n' "$l" | grep -qE '^[^ ]*cert-authority'; then
    [ $DROP_CA -eq 0 ] && { echo "    [!] keeping cert-authority line (verify it's scoring/yours): $(printf '%s' "$l" | cut -c1-70)"; return 0; }
  fi
  return 1
}

AKF=$(sshd -T 2>/dev/null | awk 'tolower($1)=="authorizedkeysfile"{sub($1" ",""); print; exit}')
[ -z "$AKF" ] && AKF=".ssh/authorized_keys .ssh/authorized_keys2"

awk -F: '{print $1":"$3":"$4":"$6}' /etc/passwd | while IFS=: read -r u uid gid h; do
  [ -d "$h" ] || continue
  for pat in $AKF; do
    f=$(echo "$pat" | sed "s|%u|$u|g; s|%h|$h|g; s|%%|%|g")
    case "$f" in /*) ;; *) f="$h/$f";; esac
    add_team=0
    in_users "$u" && [ -n "$TEAM" ] && [ "$pat" = "$(echo "$AKF" | awk '{print $1}')" ] && add_team=1
    [ -f "$f" ] || [ $add_team -eq 1 ] || continue

    new=$(mktemp)
    kept=0 dropped=0
    if [ -f "$f" ]; then
      while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue;; esac
        if keep_line "$line"; then
          printf '%s\n' "$line" >> "$new"; kept=$((kept+1))
        else
          dropped=$((dropped+1))
          echo "    drop: $(fp_of "$line") $(printf '%s' "$line" | awk '{print $NF}')"
        fi
      done < "$f"
    fi
    if [ $add_team -eq 1 ]; then
      grep -v '^#' "$TEAM" | grep -v '^$' | while IFS= read -r tk; do
        grep -qxF "$tk" "$new" 2>/dev/null || printf '%s\n' "$tk" >> "$new"
      done
    fi
    echo "-- $u: $f  kept=$kept dropped=$dropped team_key=$( [ $add_team -eq 1 ] && echo yes || echo no )"

    if [ $APPLY -eq 1 ]; then
      if [ -f "$f" ]; then
        cp -p "$f" "$BK/$(echo "$f" | tr '/' '_')"
        # clear immutable bit red team may have set
        command -v chattr >/dev/null 2>&1 && chattr -i -a "$f" 2>/dev/null
      fi
      d=$(dirname "$f"); mkdir -p "$d"; chown "$uid:$gid" "$d"; chmod 700 "$d"
      cat "$new" > "$f"; chown "$uid:$gid" "$f"; chmod 600 "$f"
    fi
    rm -f "$new"
  done
done

echo
if [ $APPLY -eq 1 ]; then
  echo "Done. Restore one file: cp -p $BK/<_path_name> <path>"
  echo "NOW: test your login from another box in a NEW session, and check the scorer is still green."
else
  echo "Dry run only. Nothing changed."
fi

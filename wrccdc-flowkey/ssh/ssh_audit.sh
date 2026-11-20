#!/bin/sh
# ssh_audit.sh — READ-ONLY inventory of SSH trust on this box.
# POSIX sh (works on Alpine/busybox). Run as root. Changes nothing.
# Usage: sh ssh_audit.sh | tee /root/ssh_audit_$(hostname)_$(date +%H%M).txt

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

hr() { printf '\n===== %s =====\n' "$1"; }
flag() { printf '  [!] %s\n' "$1"; }

hr "host / version"
echo "$(hostname)  $(date)"
ssh -V 2>&1
echo "  CVE-2026-35414 (cert principals bypass): fixed upstream in 10.3; distros backport — check your distro's openssh advisory"

hr "effective sshd config (sshd -T)"
CFG=$(sshd -T 2>/dev/null)
if [ -z "$CFG" ]; then
  flag "sshd -T failed (config error?). Running sshd -t:"
  sshd -t
else
  echo "$CFG" | grep -Ei '^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxauthtries|allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|authorizedprincipalsfile|authorizedprincipalscommand|trustedusercakeys|revokedkeys|hostcertificate|hostkey|usepam|x11forwarding|allowtcpforwarding|permittunnel|gatewayports) '
fi

val() { echo "$CFG" | awk -v k="$1" 'tolower($1)==k {sub($1" ",""); print; exit}'; }

hr "SCORING TRUST — do not modify these"
CA=$(val trustedusercakeys)
if [ -n "$CA" ] && [ "$CA" != "none" ]; then
  echo "TrustedUserCAKeys: $CA"
  for f in $CA; do
    [ -f "$f" ] || { flag "missing CA file $f"; continue; }
    ls -l "$f"
    ssh-keygen -lf "$f" 2>/dev/null | sed 's/^/  CA fp: /'
  done
else
  echo "TrustedUserCAKeys: none"
fi
APF=$(val authorizedprincipalsfile)
echo "AuthorizedPrincipalsFile: ${APF:-none}"
if [ -n "$APF" ] && [ "$APF" != "none" ]; then
  # %u -> each user; show any that exist
  for u in $(awk -F: '{print $1}' /etc/passwd); do
    p=$(echo "$APF" | sed "s|%u|$u|g; s|%h|$(awk -F: -v u="$u" '$1==u{print $6}' /etc/passwd)|g")
    [ -f "$p" ] && { echo "  $u -> $p:"; sed 's/^/    /' "$p"; }
  done
fi
RK=$(val revokedkeys); echo "RevokedKeys: ${RK:-none}"
for hc in $(echo "$CFG" | awk 'tolower($1)=="hostcertificate"{print $2}'); do
  echo "HostCertificate: $hc"
  ssh-keygen -Lf "$hc" 2>/dev/null | grep -E 'Type|Key ID|Valid|Principals' -A1 | sed 's/^/  /'
done

hr "red flags"
AKC=$(val authorizedkeyscommand)
[ -n "$AKC" ] && [ "$AKC" != "none" ] && flag "AuthorizedKeysCommand set: $AKC  (classic persistence — verify it's legit, e.g. sss_ssh_authorizedkeys)"
APC=$(val authorizedprincipalscommand)
[ -n "$APC" ] && [ "$APC" != "none" ] && flag "AuthorizedPrincipalsCommand set: $APC  (verify)"
[ "$(val permitrootlogin)" = "yes" ] && flag "PermitRootLogin yes"
[ "$(val passwordauthentication)" = "yes" ] && flag "PasswordAuthentication yes"
grep -HnE '^[[:space:]]*(Match|Include)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | sed 's/^/  Match\/Include (read these): /'
echo "  newest files in /etc/ssh:"
ls -lt /etc/ssh 2>/dev/null | sed -n '2,8p' | sed 's/^/    /'

hr "rotation agent candidates (DO NOT KILL — scoring certs rotate every 5-10 min)"
grep -rIlsE 'ssh|cert|step|vault' /etc/cron* /var/spool/cron* /etc/periodic 2>/dev/null | sed 's/^/  cron: /'
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-timers --all --no-pager 2>/dev/null | grep -iE 'ssh|cert|step|vault|renew' | sed 's/^/  timer: /'
  systemctl list-units --type=service --no-pager 2>/dev/null | grep -iE 'cert|step|vault|renew|ssh' | sed 's/^/  svc: /'
fi
{ ps -eo pid,user,comm,args 2>/dev/null || ps -o pid,user,comm,args; } | awk 'NR>1 && tolower($3) ~ /step|vault|cert|renew|ca-agent/ {print "  proc: " substr($0,1,140)}'

hr "authorized_keys (every user)"
AKF=$(val authorizedkeysfile); echo "AuthorizedKeysFile: ${AKF:-.ssh/authorized_keys}"
awk -F: '{print $1":"$6}' /etc/passwd | while IFS=: read -r u h; do
  for pat in ${AKF:-.ssh/authorized_keys .ssh/authorized_keys2}; do
    f=$(echo "$pat" | sed "s|%u|$u|g; s|%h|$h|g; s|%%|%|g")
    case "$f" in /*) ;; *) f="$h/$f";; esac
    [ -f "$f" ] || continue
    echo "-- $u: $f ($(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1))"
    n=0
    while IFS= read -r line; do
      n=$((n+1))
      case "$line" in ''|'#'*) continue;; esac
      t=$(mktemp); echo "$line" > "$t"
      fp=$(ssh-keygen -lf "$t" 2>/dev/null | awk '{print $2, $NF}')
      rm -f "$t"
      opts=""
      echo "$line" | grep -qE '^[^ ]*(command=|from=|cert-authority|principals=|environment=|tunnel=|permitopen=)' && opts=" OPTIONS: $(echo "$line" | cut -c1-80)"
      echo "  #$n ${fp:-unparseable}$opts"
    done < "$f"
  done
done

hr "AD / sssd (everything is AD-integrated)"
command -v realm >/dev/null 2>&1 && realm list 2>/dev/null | grep -E 'domain-name|login-policy|permitted' | sed 's/^/  /'
[ -f /etc/sssd/sssd.conf ] && grep -E '^(access_provider|simple_allow|ad_access_filter|ldap_user_ssh_public_key|ad_gpo)' /etc/sssd/sssd.conf | sed 's/^/  sssd: /'
grep -rhsE '^%|domain' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^#' | sed 's/^/  sudoers: /'

echo; echo "done. Save this output before changing anything."

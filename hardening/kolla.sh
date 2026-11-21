#!/bin/sh
# =====================================================================
#  kolla  (192.168.220.30)  -  Alpine Linux  -  Fileshare
#  UPDATE + HARDENING SCRIPT
#
#  HOW TO RUN (as root), saving everything it prints to a log file:
#      sh kolla.sh 2>&1 | tee /root/kolla-hardening.log
#
#  WHAT IT DOES, IN ORDER:
#      1. Installs all OS updates
#      2. Lists user accounts so you can spot bad ones   (report only)
#      3. Hardens SSH (config is tested before restart)
#      4. Lists open ports and risky protocols           (report only)
#      5. Lists cron jobs and SSH keys                   (report only)
#      6. Hardens the service this box runs: Fileshare
#      7. Safer kernel network settings + file permissions
#      8. Turns on a firewall that allows ONLY the ports below
#
#  SAFE BY DESIGN: it never deletes users or stops the scored service,
#  it backs up every file before changing it, and it asks before the
#  firewall blocks anything that is currently listening.
# =====================================================================

# ---------------------------------------------------------------------
#  SETTINGS - CHECK THESE BEFORE YOU RUN
# ---------------------------------------------------------------------
# Ports the firewall will allow IN. Format: port/protocol, space separated.
# 22 = SSH, 139/445 = SMB (Samba), 111/2049 = NFS. Remove the ones this share does not use.
ALLOWED_PORTS="22/tcp 139/tcp 445/tcp 111/tcp 111/udp 2049/tcp 2049/udp"

APPLY_FIREWALL="yes"      # "no" = skip step 8 entirely
SSH_PERMIT_ROOT="no"      # "no" = block root over SSH (skipped if no sudo/wheel user exists)
ALLOW_GUEST="yes"         # "no" = turn off ALL guest/anonymous Samba access
                          #        (only if the scored share does not use guest access!)

# =====================================================================
#  HELPER FUNCTIONS  (you do not need to edit anything below this line)
# =====================================================================

# This script must run as root.
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root:  sudo sh $0"
    exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/root/hardening-backup-$STAMP"   # every file we change is copied here first
mkdir -p "$BACKUP_DIR"

say()  { printf '\n==== %s ====\n' "$1"; }   # section title
note() { printf '  [*] %s\n' "$1"; }         # normal message
warn() { printf '  [!] %s\n' "$1"; }         # something YOU should look at

# backup FILE  -> save a copy of FILE before changing it
backup() {
    if [ -e "$1" ]; then
        cp -a "$1" "$BACKUP_DIR/$(echo "$1" | tr '/' '_')"
        note "Backed up $1"
    fi
}

# restore FILE -> put the backed-up copy back (used when a config test fails)
restore() {
    cp -a "$BACKUP_DIR/$(echo "$1" | tr '/' '_')" "$1"
    warn "Config test FAILED, so $1 was put back the way it was."
}

# set_conf FILE KEY "NEW LINE"
#   If a line starting with KEY exists (even commented out with #), replace it.
#   Otherwise add NEW LINE to the end of FILE.
set_conf() {
    if grep -qE "^#?[[:space:]]*$2([[:space:]=]|$)" "$1"; then
        sed -i -E "s|^#?[[:space:]]*$2([[:space:]=].*)?$|$3|" "$1"
    else
        echo "$3" >> "$1"
    fi
}

# svc ACTION NAME  -> start/stop/restart/reload a service (systemd or Alpine OpenRC)
svc() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl "$1" "$2"
    else
        rc-service "$2" "$1"
    fi
}

# list_open_ports -> prints every port this machine listens on, like "22/tcp"
#                    (ports that only listen on localhost are left out)
list_open_ports() {
    if command -v ss >/dev/null 2>&1; then
        ss -Htuln | awk '{print $1, $5}'
    else
        netstat -tuln 2>/dev/null | awk 'NR>2 {print $1, $4}'
    fi | awk '{
        proto = $1; sub(/6$/, "", proto)          # tcp6 -> tcp
        addr  = $2; port = addr; sub(/.*:/, "", port)
        if (addr ~ /^(127\.|\[?::1\]?|localhost)/) next
        print port "/" proto
    }' | sort -u | sort -t/ -k1,1n
}

# firewall_safety_check -> warns if something is listening that the firewall
#                          is about to block, and asks before continuing.
firewall_safety_check() {
    NOT_ALLOWED=""
    for p in $(list_open_ports); do
        case " $ALLOWED_PORTS " in
            *" $p "*) ;;                              # allowed, fine
            *) NOT_ALLOWED="$NOT_ALLOWED $p" ;;
        esac
    done
    if [ -n "$NOT_ALLOWED" ]; then
        warn "These ports are LISTENING but are NOT in ALLOWED_PORTS:$NOT_ALLOWED"
        warn "If one of them is a scored service, answer n and add it to ALLOWED_PORTS."
        printf '  Block them and turn on the firewall? [y/N] '
        read -r answer
        if [ "$answer" != "y" ]; then
            note "Firewall skipped. Edit ALLOWED_PORTS at the top and run again."
            return 1
        fi
    fi
    return 0
}

# =====================================================================
#  STEP 1: Install all OS updates (apk)
# =====================================================================
say "STEP 1: Install OS updates"
note "Alpine version: $(cat /etc/alpine-release)"
note "Package repositories in use (the version in these URLs is your release branch):"
grep -v '^#' /etc/apk/repositories | sed 's/^/      /'
apk update
apk upgrade
note "To move to a NEWER Alpine release (e.g. 3.22 -> 3.23) see the 'Upgrading Alpine' link in README.md."

# =====================================================================
#  STEP 2: Review user accounts (REPORT ONLY - nothing is changed)
# =====================================================================
say "STEP 2: Review user accounts (report only)"
note "Accounts with UID 0 (ONLY 'root' should be listed):"
awk -F: '$3 == 0 {print "      " $1}' /etc/passwd
note "Accounts that can log in (they have a real shell):"
grep -Ev '(nologin|false|sync|shutdown|halt)$' /etc/passwd | cut -d: -f1 | sed 's/^/      /'
note "Accounts with an EMPTY password (should be none):"
awk -F: '$2 == "" {print "      " $1}' /etc/shadow
note "Admin groups (sudo / wheel / admin) and their members:"
grep -E '^(sudo|wheel|admin):' /etc/group | sed 's/^/      /'
note "To change a weak or default password:   passwd <username>"
note "To lock an account you don't recognise:  passwd -l <username>"

# =====================================================================
#  STEP 3: Harden SSH (OpenSSH server)
# =====================================================================
say "STEP 3: Harden SSH"
SSHD_CONFIG=/etc/ssh/sshd_config
if [ ! -f "$SSHD_CONFIG" ]; then
    note "OpenSSH server is not installed - skipping."
else
    backup "$SSHD_CONFIG"

    # Safety: only block root login if some other admin account exists,
    # otherwise you could lock yourself out.
    ROOT_LOGIN="$SSH_PERMIT_ROOT"
    ADMINS=$(grep -E '^(sudo|wheel|admin):' /etc/group | cut -d: -f4 | tr -d ',')
    if [ "$ROOT_LOGIN" = "no" ] && [ -z "$ADMINS" ]; then
        warn "No user is in the sudo/wheel group, so root SSH login is left alone."
        ROOT_LOGIN=""
    fi

    # The settings we want. One per line: KEY VALUE
    SETTINGS="PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no"
    if [ -n "$ROOT_LOGIN" ]; then
        SETTINGS="$SETTINGS
PermitRootLogin $ROOT_LOGIN"
    fi

    # Newer systems read extra files from sshd_config.d/ ; the FIRST value
    # sshd sees wins, so we name our file 00-... to be read first.
    if grep -qE '^Include[[:space:]]+/etc/ssh/sshd_config.d/' "$SSHD_CONFIG"; then
        echo "$SETTINGS" > /etc/ssh/sshd_config.d/00-hardening.conf
        note "Wrote /etc/ssh/sshd_config.d/00-hardening.conf"
    else
        echo "$SETTINGS" | while read -r key value; do
            set_conf "$SSHD_CONFIG" "$key" "$key $value"
        done
        note "Updated $SSHD_CONFIG"
    fi

    # Test the config BEFORE restarting so a typo can't kill SSH.
    if sshd -t; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd
        else
            rc-service sshd restart
        fi
        note "SSH restarted with the new settings."
    else
        restore "$SSHD_CONFIG"
        rm -f /etc/ssh/sshd_config.d/00-hardening.conf
    fi
fi

# =====================================================================
#  STEP 4: Look for risky protocols (REPORT ONLY - nothing is changed)
#  Covers the "Common Protocols" list: FTP, Telnet, SNMP, VNC, RDP,
#  SMTP/POP3/IMAP, DNS, NFS, SMB, OpenVPN, HTTP/HTTPS, SSH.
# =====================================================================
say "STEP 4: Check open ports and risky protocols (report only)"
OPEN_PORTS=$(list_open_ports)
note "Ports listening on the network right now:"
for p in $OPEN_PORTS; do echo "      $p"; done
note "Which program owns each port (use this to find the scored service):"
{ ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null; } | grep -vE '127\.0\.0\.|\[::1\]' | sed 's/^/      /'

for p in $OPEN_PORTS; do
    case "$p" in
        21/tcp)   warn "FTP (21) is open: passwords travel in plain text. Disable anonymous login." ;;
        23/tcp)   warn "TELNET (23) is open: plain text. Turn it off unless it is a scored service." ;;
        25/tcp|110/tcp|143/tcp)
                  warn "Mail port $p is open (SMTP/POP3/IMAP). Prefer the TLS ports (465/587, 995, 993)." ;;
        53/*)     warn "DNS ($p) is open: make sure it only answers recursive queries for your own network." ;;
        111/*|2049/*)
                  warn "NFS/rpcbind ($p) is open: check /etc/exports below." ;;
        139/tcp|445/tcp)
                  warn "SMB ($p) is open: SMBv1 should be off and guest access limited." ;;
        161/udp)  warn "SNMP (161) is open: make sure the community string is not public/private." ;;
        1194/*)   warn "OpenVPN ($p) is open: make sure it uses certificates + tls-crypt." ;;
        3389/tcp) warn "RDP (3389) is open." ;;
        590[0-9]/tcp)
                  warn "VNC ($p) is open: VNC is weakly encrypted, use a strong password or tunnel it over SSH." ;;
    esac
done

# SNMP with a default community string?
if [ -f /etc/snmp/snmpd.conf ] && grep -Eq '^[^#]*community[[:space:]]+(public|private)' /etc/snmp/snmpd.conf; then
    warn "SNMP uses a DEFAULT community (public/private) in /etc/snmp/snmpd.conf - change it."
fi
# FTP allowing anonymous login?
if grep -qs '^anonymous_enable=YES' /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; then
    warn "vsftpd allows ANONYMOUS login - set anonymous_enable=NO unless it is required."
fi
# NFS exports that trust everyone or keep root powers?
if [ -s /etc/exports ]; then
    note "NFS exports (/etc/exports):"
    grep -v '^#' /etc/exports | sed 's/^/      /'
    grep -q 'no_root_squash' /etc/exports && warn "An export uses no_root_squash: a remote root user is root on your files."
    grep -qE '[[:space:]]\*\(' /etc/exports && warn "An export is shared with '*' (everyone). Limit it to 192.168.220.0/24."
fi

# =====================================================================
#  STEP 5: Look for things an attacker may have left (REPORT ONLY)
# =====================================================================
say "STEP 5: Check cron jobs and SSH keys (report only)"
note "Scheduled jobs (cron). Anything you did not create is suspicious:"
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* /etc/crontabs/*; do
    [ -f "$f" ] || continue
    LINES=$(grep -Ev '^[[:space:]]*(#|$)' "$f")
    [ -n "$LINES" ] && { echo "      --- $f"; echo "$LINES" | sed 's/^/        /'; }
done
note "SSH authorized_keys files (each key can log in WITHOUT a password):"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] && echo "      $f  ($(grep -c . "$f") keys)"
done

# =====================================================================
#  STEP 6: Harden the file share (Samba = SMB, and NFS)
# =====================================================================
say "STEP 6: Harden the file share (Samba / NFS)"
SMB_CONF=/etc/samba/smb.conf
if [ -f "$SMB_CONF" ]; then
    backup "$SMB_CONF"

    # set_global "name = value" -> put this setting in [global]. If the
    # setting is already in the file, its value is replaced.
    set_global() {
        NAME=${1%% =*}
        if grep -qE "^[[:space:]]*${NAME}[[:space:]]*=" "$SMB_CONF"; then
            sed -i -E "s|^[[:space:]]*${NAME}[[:space:]]*=.*|   $1|" "$SMB_CONF"
        else
            awk -v line="   $1" '{print} /^\[global\]/ {print line}' "$SMB_CONF" > "$SMB_CONF.new" \
                && mv "$SMB_CONF.new" "$SMB_CONF"
        fi
        note "Set: $1"
    }
    set_global "server min protocol = SMB2"      # turns OFF SMBv1 (WannaCry/EternalBlue)
    set_global "ntlm auth = ntlmv2-only"          # refuse old, crackable NTLMv1 logins
    if [ "$ALLOW_GUEST" = "no" ]; then
        set_global "map to guest = never"         # no anonymous/guest access at all
        set_global "restrict anonymous = 2"
    fi

    # testparm checks the file for errors before we restart Samba.
    if testparm -s >/dev/null 2>&1; then
        svc restart samba 2>/dev/null || svc restart smb 2>/dev/null || svc restart smbd
    else
        restore "$SMB_CONF"
    fi

    note "Shares on this server (check 'guest ok' and 'writable' on each one):"
    testparm -s 2>/dev/null | grep -E '^\[|path|guest ok|writ|read only|valid users' | sed 's/^/      /'
    note "Samba user accounts (set a new password with: smbpasswd <user>):"
    pdbedit -L 2>/dev/null | sed 's/^/      /'
else
    note "Samba is not installed."
fi

if [ -s /etc/exports ]; then
    note "NFS is in use - the exports were checked in STEP 4."
    note "Safe NFS export example:  /srv/share 192.168.220.0/24(rw,sync,root_squash,no_subtree_check)"
    note "After editing /etc/exports run:  exportfs -ra"
fi

# =====================================================================
#  STEP 7: Safer kernel network settings + file permissions
# =====================================================================
say "STEP 7: Kernel network settings and file permissions"
# These block old network tricks (redirects, source routing, SYN floods).
# They do NOT turn off IP forwarding, so containers keep working.
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
kernel.dmesg_restrict = 1
EOF
sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null && note "Applied /etc/sysctl.d/99-hardening.conf"

# Password hash files must not be readable by normal users.
chmod 644 /etc/passwd /etc/group
chmod o-rwx /etc/shadow
[ -f /etc/gshadow ] && chmod o-rwx /etc/gshadow
note "Fixed permissions on /etc/passwd, /etc/group, /etc/shadow"

# =====================================================================
#  STEP 8: Firewall (iptables on Alpine) - block all except ALLOWED_PORTS
# =====================================================================
say "STEP 8: Firewall (iptables)"
if [ "$APPLY_FIREWALL" != "yes" ]; then
    note "APPLY_FIREWALL is not 'yes' - skipping."
elif firewall_safety_check; then
    apk add iptables ip6tables >/dev/null
    for IPT in iptables ip6tables; do
        if [ "$IPT" = "iptables" ]; then ICMP=icmp; else ICMP=ipv6-icmp; fi
        $IPT -P INPUT ACCEPT                 # don't cut ourselves off while rebuilding
        $IPT -F INPUT                        # clear old INPUT rules
        $IPT -A INPUT -i lo -j ACCEPT        # local traffic
        $IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        $IPT -A INPUT -p "$ICMP" -j ACCEPT   # ping (and IPv6 neighbour discovery)
        for p in $ALLOWED_PORTS; do
            $IPT -A INPUT -p "${p#*/}" --dport "${p%/*}" -j ACCEPT
        done
        $IPT -P INPUT DROP                   # everything else is dropped
        # Save the rules and load them at every boot.
        rc-update add "$IPT" default >/dev/null 2>&1
        rc-service "$IPT" save
    done
    iptables -L INPUT -n --line-numbers
fi

# =====================================================================
#  DONE
# =====================================================================
say "FINISHED"
note "Backups of every changed file are in: $BACKUP_DIR"
note "Things to do BY HAND now (see README.md for the how-to links):"
note "  1. Change every default/weak password you saw in STEP 2."
note "  2. Look at every [!] line above and decide if it needs fixing."
note "  3. Check the scored service still works from another machine."
note "  4. Reboot if STEP 1 said a reboot is needed (at a safe time)."

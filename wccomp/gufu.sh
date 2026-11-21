#!/bin/sh
# =====================================================================
#  gufu  (192.168.220.100)  -  Rocky Linux  -  Gitea
#  UPDATE + HARDENING SCRIPT
#
#  HOW TO RUN (as root), saving everything it prints to a log file:
#      sh gufu.sh 2>&1 | tee /root/gufu-hardening.log
#
#  WHAT IT DOES, IN ORDER:
#      1. Installs all OS updates
#      2. Lists user accounts so you can spot bad ones   (report only)
#      3. Hardens SSH (config is tested before restart)
#      4. Lists open ports and risky protocols           (report only)
#      5. Lists cron jobs and SSH keys                   (report only)
#      6. Hardens the service this box runs: Gitea
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
# 22 = SSH (also git over SSH), 3000 = Gitea web (default), 80/443 if a reverse proxy is in front.
ALLOWED_PORTS="22/tcp 80/tcp 443/tcp 3000/tcp"

APPLY_FIREWALL="yes"      # "no" = skip step 8 entirely
SSH_PERMIT_ROOT="no"      # "no" = block root over SSH (skipped if no sudo/wheel user exists)
GITEA_NEW_VERSION=""      # e.g. "1.25.2" to download + install that Gitea release. "" = don't update Gitea.
DISABLE_REGISTRATION="no" # "yes" = strangers can't sign up (leave "no" if scoring creates accounts)

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
#  STEP 1: Install all OS updates (dnf)
# =====================================================================
say "STEP 1: Install OS updates"
cat /etc/redhat-release 2>/dev/null || cat /etc/fedora-release 2>/dev/null
dnf -y upgrade --refresh
# Exit code 1 from needs-restarting means a reboot is needed.
if ! dnf needs-restarting -r >/dev/null 2>&1; then
    warn "A REBOOT may be needed to finish updates (new kernel or libraries). Reboot when it is safe."
fi

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
#  STEP 6: Update + harden Gitea
# =====================================================================
say "STEP 6: Update and harden Gitea"

# ---- SELinux should be Enforcing on Rocky (report only; switching it on
#      cold can break Gitea, so do it by hand and test).
note "SELinux mode: $(getenforce 2>/dev/null || echo 'not installed')"

# ---- Find Gitea
GITEA_BIN=$(command -v gitea 2>/dev/null || echo /usr/local/bin/gitea)
GITEA_INI=""
for f in /etc/gitea/app.ini /var/lib/gitea/custom/conf/app.ini /home/git/gitea/custom/conf/app.ini; do
    [ -f "$f" ] && GITEA_INI="$f" && break
done
if [ -x "$GITEA_BIN" ]; then
    note "Gitea binary: $GITEA_BIN  ($($GITEA_BIN --version 2>/dev/null))"
else
    warn "Gitea binary not found. If Gitea runs in Docker/Podman, update it with: docker compose pull && docker compose up -d"
fi

# ---- Optional: update the Gitea binary (official method: replace the binary)
#      Set GITEA_NEW_VERSION at the top, e.g. "1.25.2". Latest: https://dl.gitea.com/gitea/
#      Take a backup first:  sudo -u git gitea dump -c <app.ini>   (see README.md)
if [ -n "$GITEA_NEW_VERSION" ] && [ -x "$GITEA_BIN" ]; then
    URL="https://dl.gitea.com/gitea/$GITEA_NEW_VERSION/gitea-$GITEA_NEW_VERSION-linux-amd64"
    note "Downloading $URL"
    if curl -fsSL -o /tmp/gitea.new "$URL" && curl -fsSL -o /tmp/gitea.new.sha256 "$URL.sha256"; then
        # The .sha256 file holds the expected checksum: make sure the download is not corrupt/tampered.
        if [ "$(sha256sum /tmp/gitea.new | cut -d' ' -f1)" = "$(cut -d' ' -f1 /tmp/gitea.new.sha256)" ]; then
            svc stop gitea
            cp -a "$GITEA_BIN" "$BACKUP_DIR/gitea.old"       # old binary, in case you need to roll back
            install -m 755 /tmp/gitea.new "$GITEA_BIN"
            restorecon "$GITEA_BIN" 2>/dev/null               # fix the SELinux label
            svc start gitea
            note "Gitea is now: $($GITEA_BIN --version)"
        else
            warn "Checksum did NOT match - the new binary was NOT installed."
        fi
    else
        warn "Download failed - Gitea was not updated."
    fi
fi

# ---- Harden app.ini
if [ -n "$GITEA_INI" ]; then
    note "Gitea config: $GITEA_INI"
    backup "$GITEA_INI"
    # set_ini KEY VALUE -> only changes a key that already exists (so it stays in the right [section])
    set_ini() {
        if grep -qE "^[[:space:]]*$1[[:space:]]*=" "$GITEA_INI"; then
            sed -i -E "s|^[[:space:]]*$1[[:space:]]*=.*|$1 = $2|" "$GITEA_INI"
            note "Set $1 = $2"
        else
            warn "$1 is not in app.ini - add '$1 = $2' under the right [section] by hand (see README.md)."
        fi
    }
    set_ini INSTALL_LOCK true                    # stops anyone re-running the web installer
    set_ini RUN_MODE prod                        # no debug pages
    if [ "$DISABLE_REGISTRATION" = "yes" ]; then
        set_ini DISABLE_REGISTRATION true        # strangers can't create accounts
    fi
    note "Current security-related settings:"
    grep -E '^(INSTALL_LOCK|RUN_MODE|DISABLE_REGISTRATION|REQUIRE_SIGNIN_VIEW|ROOT_URL|HTTP_PORT|DISABLE_SSH)' "$GITEA_INI" | sed 's/^/      /'
    chmod 640 "$GITEA_INI"
    svc restart gitea && note "Gitea restarted."
    note "Also: log in as the Gitea admin and check Site Administration > User Accounts for users you don't know."
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
#  STEP 8: Firewall (firewalld) - block everything except ALLOWED_PORTS
# =====================================================================
say "STEP 8: Firewall (firewalld)"
if [ "$APPLY_FIREWALL" != "yes" ]; then
    note "APPLY_FIREWALL is not 'yes' - skipping."
elif firewall_safety_check; then
    command -v firewall-cmd >/dev/null 2>&1 || dnf -y install firewalld
    systemctl enable --now firewalld
    ZONE=$(firewall-cmd --get-default-zone)
    note "Using firewall zone: $ZONE"
    # Remove everything the zone currently allows...
    for s in $(firewall-cmd --permanent --zone="$ZONE" --list-services); do
        firewall-cmd --permanent --zone="$ZONE" --remove-service="$s" >/dev/null
    done
    for p in $(firewall-cmd --permanent --zone="$ZONE" --list-ports); do
        firewall-cmd --permanent --zone="$ZONE" --remove-port="$p" >/dev/null
    done
    # ...then allow only our list.
    for p in $ALLOWED_PORTS; do
        firewall-cmd --permanent --zone="$ZONE" --add-port="$p" >/dev/null
    done
    firewall-cmd --reload
    firewall-cmd --zone="$ZONE" --list-all
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

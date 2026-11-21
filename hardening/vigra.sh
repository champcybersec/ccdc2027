#!/bin/sh
# =====================================================================
#  vigra  (192.168.220.2)  -  OpenWRT  -  Router
#  UPDATE + HARDENING SCRIPT
#
#  HOW TO RUN (as root on the router), saving the output to a log file:
#      sh vigra.sh 2>&1 | tee /root/vigra-hardening.log
#
#  WHAT IT DOES, IN ORDER:
#      1. Refreshes the package list and shows what can be updated
#      2. Checks the root password
#      3. Locks SSH (Dropbear) and the web UI (LuCI) to the inside network
#      4. Makes sure the WAN firewall zone blocks incoming traffic
#         and LISTS your port forwards (it never deletes them)
#      5. Turns off UPnP and lists risky services
#      6. Lists cron jobs, SSH keys and startup commands  (report only)
#
#  WHY THE ROUTER IS DIFFERENT: if the router breaks, EVERY service
#  behind it goes down. This script never touches port forwards, never
#  flashes firmware, and does not mass-upgrade packages by default.
#  Every changed config file is backed up first.
# =====================================================================

# ---------------------------------------------------------------------
#  SETTINGS - CHECK THESE BEFORE YOU RUN
# ---------------------------------------------------------------------
LAN_NAME="lan"            # name of the inside network in /etc/config/network
LOCK_ADMIN_TO_LAN="yes"   # "yes" = SSH + web UI only answer on the inside (192.168.220.x)
                          # set "no" if you manage the router from the 10.100.x.x side!
UPGRADE_PACKAGES="no"     # "yes" = upgrade every package that has an update.
                          # OpenWRT docs warn against this (can fill flash / break things);
                          # firmware updates should use sysupgrade (see README.md).
DISABLE_UPNP="yes"        # "yes" = stop UPnP, so inside machines can't open ports on the WAN

# =====================================================================
#  HELPER FUNCTIONS  (you do not need to edit anything below this line)
# =====================================================================
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/root/hardening-backup-$STAMP"
mkdir -p "$BACKUP_DIR"
cp -a /etc/config "$BACKUP_DIR/"          # every uci config file, before any change

say()  { printf '\n==== %s ====\n' "$1"; }
note() { printf '  [*] %s\n' "$1"; }
warn() { printf '  [!] %s\n' "$1"; }

note "All of /etc/config was backed up to $BACKUP_DIR"
note "To undo everything:  cp $BACKUP_DIR/config/* /etc/config/ && reboot"

# =====================================================================
#  STEP 1: Updates
# =====================================================================
say "STEP 1: Package updates"
. /etc/openwrt_release
note "Firmware: $DISTRIB_DESCRIPTION"
note "Check https://openwrt.org/ for a newer release; install it with sysupgrade (see README.md)."

# OpenWRT 25.x uses 'apk'; older releases use 'opkg'.
if command -v apk >/dev/null 2>&1; then
    apk update
    UPGRADABLE=$(apk list --upgradable 2>/dev/null)
else
    opkg update
    UPGRADABLE=$(opkg list-upgradable)
fi

if [ -z "$UPGRADABLE" ]; then
    note "All packages are up to date."
else
    note "Packages with updates:"
    echo "$UPGRADABLE" | sed 's/^/      /'
    if [ "$UPGRADE_PACKAGES" = "yes" ]; then
        if command -v apk >/dev/null 2>&1; then
            apk upgrade
        else
            echo "$UPGRADABLE" | cut -d' ' -f1 | xargs opkg upgrade
        fi
    else
        note "Not upgrading (UPGRADE_PACKAGES=no). To upgrade ONE package:  opkg upgrade <name>  (or apk upgrade <name>)"
    fi
fi

# =====================================================================
#  STEP 2: Root password
# =====================================================================
say "STEP 2: Root password"
ROOT_HASH=$(grep '^root:' /etc/shadow | cut -d: -f2)
if [ -z "$ROOT_HASH" ]; then
    warn "root has NO PASSWORD. Set one right now with:  passwd"
else
    note "root has a password. If it is a default/shared one, change it with:  passwd"
fi
note "Other accounts that can log in (should normally be none on a router):"
grep -Ev '(nologin|false)$' /etc/passwd | cut -d: -f1 | grep -v '^root$' | sed 's/^/      /'

# =====================================================================
#  STEP 3: SSH (Dropbear) and web UI (uhttpd / LuCI)
# =====================================================================
say "STEP 3: Lock down SSH and the web UI"
LAN_IP=$(uci -q get network.$LAN_NAME.ipaddr | cut -d/ -f1)
if [ "$LOCK_ADMIN_TO_LAN" = "yes" ] && [ -z "$LAN_IP" ]; then
    warn "Could not find the '$LAN_NAME' network - not locking admin access."
    LOCK_ADMIN_TO_LAN="no"
fi

# Dropbear (SSH)
uci set dropbear.@dropbear[0].GatewayPorts='off'      # no SSH port forwarding to outsiders
if [ "$LOCK_ADMIN_TO_LAN" = "yes" ]; then
    uci set dropbear.@dropbear[0].Interface="$LAN_NAME"
    note "SSH now only listens on the $LAN_NAME network ($LAN_IP)"
fi
uci commit dropbear
/etc/init.d/dropbear restart

# uhttpd (LuCI web UI)
if uci -q get uhttpd.main >/dev/null; then
    if [ -n "$(uci -q get uhttpd.main.listen_https)" ]; then
        uci set uhttpd.main.redirect_https='1'           # send http:// to https://
        note "Web UI: http is redirected to https"
    else
        warn "Web UI has no HTTPS. Install it with: opkg install luci-ssl (or apk add luci-ssl)"
    fi
    if [ "$LOCK_ADMIN_TO_LAN" = "yes" ]; then
        uci -q delete uhttpd.main.listen_http
        uci -q delete uhttpd.main.listen_https
        uci add_list uhttpd.main.listen_http="$LAN_IP:80"
        uci add_list uhttpd.main.listen_https="$LAN_IP:443"
        note "Web UI now only listens on $LAN_IP"
    fi
    uci commit uhttpd
    /etc/init.d/uhttpd restart
fi

# =====================================================================
#  STEP 4: Firewall
# =====================================================================
say "STEP 4: Firewall"
# Find the WAN zone (looks like "@zone[1]").
WAN_ZONE=$(uci show firewall | grep "\.name='wan'" | cut -d. -f2)
if [ -n "$WAN_ZONE" ]; then
    uci set firewall."$WAN_ZONE".input='REJECT'       # nothing from outside reaches the router itself...
    uci set firewall."$WAN_ZONE".forward='REJECT'     # ...or the inside, except your port forwards
    note "WAN zone: input=REJECT, forward=REJECT"
else
    warn "No firewall zone called 'wan' found - check Network > Firewall in LuCI."
fi
uci set firewall.@defaults[0].syn_flood='1'           # SYN-flood protection
uci set firewall.@defaults[0].drop_invalid='1'        # drop broken/invalid packets
uci commit firewall
/etc/init.d/firewall reload

note "Port forwards (WAN -> inside). These are probably how scored services are reached. NOT changed:"
for s in $(uci show firewall | grep '=redirect$' | cut -d= -f1); do
    echo "      $(uci -q get "$s".name): WAN port $(uci -q get "$s".src_dport) -> $(uci -q get "$s".dest_ip):$(uci -q get "$s".dest_port)"
done
note "Rules that let the WAN reach the router itself (check each one is needed):"
for s in $(uci show firewall | grep '=rule$' | cut -d= -f1); do
    if [ "$(uci -q get "$s".src)" = "wan" ] && [ -z "$(uci -q get "$s".dest)" ] && [ "$(uci -q get "$s".target)" = "ACCEPT" ]; then
        echo "      $(uci -q get "$s".name)  proto=$(uci -q get "$s".proto)  port=$(uci -q get "$s".dest_port)"
    fi
done

# =====================================================================
#  STEP 5: UPnP and risky services
# =====================================================================
say "STEP 5: UPnP and risky services"
if [ -x /etc/init.d/miniupnpd ]; then
    if [ "$DISABLE_UPNP" = "yes" ]; then
        /etc/init.d/miniupnpd stop
        /etc/init.d/miniupnpd disable
        note "UPnP (miniupnpd) stopped and disabled."
    else
        warn "UPnP is installed: any inside machine (or malware) can open ports on the WAN."
    fi
fi
[ -x /etc/init.d/telnet ] && warn "Telnet is installed: run  /etc/init.d/telnet disable && /etc/init.d/telnet stop"
if [ -f /etc/config/snmpd ] && grep -Eq "community.*'(public|private)'" /etc/config/snmpd; then
    warn "SNMP uses a default community (public/private) - change it in /etc/config/snmpd"
fi
note "Ports the router listens on:"
netstat -tuln 2>/dev/null | awk 'NR>2 {print "      " $1 "  " $4}'

# =====================================================================
#  STEP 6: Things an attacker may have left (REPORT ONLY)
# =====================================================================
say "STEP 6: Cron jobs, SSH keys, startup commands (report only)"
note "Cron jobs (/etc/crontabs/root):"
grep -Ev '^[[:space:]]*(#|$)' /etc/crontabs/root 2>/dev/null | sed 's/^/      /'
note "SSH keys that can log in without a password (/etc/dropbear/authorized_keys):"
grep -c . /etc/dropbear/authorized_keys 2>/dev/null | sed 's/^/      keys: /'
note "Commands run at boot (/etc/rc.local):"
grep -Ev '^[[:space:]]*(#|$)|^exit 0' /etc/rc.local 2>/dev/null | sed 's/^/      /'

# =====================================================================
#  DONE
# =====================================================================
say "FINISHED"
note "Backup of /etc/config: $BACKUP_DIR"
note "Now: change the root password if needed (passwd), read every [!] line,"
note "and test that each scored service still works from outside AND inside."

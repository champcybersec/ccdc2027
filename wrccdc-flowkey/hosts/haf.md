# Haf .67 — Lubuntu 22, Wabbit (proprietary)

**CVEs:** No public CVEs for Wabbit · Copy Fail · DirtyClone · Pack2TheRoot · udisks2

## Fingerprint Wabbit (own box only)

1. `nmap -sV -sC -p- -T4 192.168.220.67` — every port + banners.
2. `nmap -sU --top-ports 50 192.168.220.67`; `-sV --version-intensity 9` on odd ports.
3. On the box: `ss -tulpn`, `ps -ef | grep -i wabbit`, `systemctl cat <unit>` — find binary, config, web root, run-as user.
4. `searchsploit <banner>` + web search the exact version. Web UI → note framework, headers, `/robots.txt`.
5. Metasploit for safe checks only: `db_nmap -sV`, matching `auxiliary/scanner/*` version/login modules (default creds, dir listing, verbose errors). No exploit modules against the live scored service — test on a clone.

## Harden

- Default creds changed; bind to LAN/localhost if remote isn't scored; firewall to scored port only.
- Run as a non-root service user; debug/verbose errors off.
- Desktop extras: `systemctl mask --now packagekit udisks2 cups avahi-daemon`.
- "Wabbit" is old slang for a fork bomb → nproc limits in `/etc/security/limits.conf`.
- Re-scan and diff — fewer open ports is the goal.

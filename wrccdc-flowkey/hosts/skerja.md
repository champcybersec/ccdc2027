# Skerja .97 — Alpine 3.23, Employee + Customer Tickets

**CVEs:** PHP2Shell (likely PHP helpdesk) · Copy Fail · DirtyClone

- `apk upgrade` for fixed PHP if a mirror is reachable; otherwise php.ini block in [kvigindis.md](kvigindis.md).
- Rotate helpdesk admin + staff; remove staff accounts you don't recognize.
- OpenRC persistence: `rc-status`, `rc-update show`, `/etc/local.d/*.start`, `/etc/periodic/*`.
- Firewall: iptables or awall, then `rc-update add iptables`.

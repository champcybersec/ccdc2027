# First 15 minutes — every box

Check the packet first: some events ban IP changes, blocking the scorer, or deleting scorer accounts. Someone joins VC and does the check-in.

0. **Proxmox snapshot** every VM (if allowed) and keep its console open. That's your undo button.
1. **Users** — Linux: `awk -F: '$3>=1000||$3==0' /etc/passwd`, `getent group sudo wheel`, `cat /etc/sudoers /etc/sudoers.d/*`. Windows: `net user`, `net localgroup administrators` ([../windows/Acct_Check.ps1](../windows/Acct_Check.ps1)).
2. **Rotate every password** except the scoring account — root, admins, domain, service, app, DB. Track on the team sheet, not on the box ([../windows/bulkpass.ps1](../windows/bulkpass.ps1)). Lock unknown users: [../linux/lock_user.sh](../linux/lock_user.sh). Everything is AD-integrated, so coordinate AD resets with the Vattar owner.
3. **SSH** — follow [SSH.md](SSH.md): `ssh/ssh_audit.sh`, patch OpenSSH, `ssh/rotate_user_keys.sh` (keeps the scoring key, adds the team key). **Never touch `TrustedUserCAKeys`, principals, host keys/certs, or the cert-rotation agent.**
4. **Snapshot state** — `ss -tulpn`, `ps auxf`, crontabs ([../linux/cron/list_cronjobs.sh](../linux/cron/list_cronjobs.sh)), `systemctl list-units --state=running`, `systemctl list-timers`. Windows: `netstat -ano`, `Get-ScheduledTask`, `Get-Service`.
5. **Firewall, default deny inbound** — [../linux/ufw_setup_debian.sh](../linux/ufw_setup_debian.sh) / [../linux/ufw_setup_rpm.sh](../linux/ufw_setup_rpm.sh); Alpine: iptables/awall; Windows: `netsh advfirewall set allprofiles state on`. Keep 22 open (scored), plus scored services, NetBird and Wazuh agent traffic (1514/1515 to the manager).
6. **Kernel LPE mitigations** — Copy Fail + DirtyClone module blocks; mask `packagekit`/`udisks2` on servers (see [CVE-CHECKLIST.md](CVE-CHECKLIST.md)).
7. **Backups** — `tar czf /root/bk-$(hostname).tgz /etc /var/www`, `mysqldump --all-databases > /root/db.sql`; web content is required. Copy one set off-box.
8. **Patch** — `apt upgrade` / `dnf upgrade --refresh` / `apk upgrade` / Windows CU. Reboot only if you can verify the service after (Proxmox console if it hangs).
9. **Wazuh** — confirm this box's agent is reporting.
10. **Verify scoring** from another box after every change.

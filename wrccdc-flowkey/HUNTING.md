# Hunting — every 30–45 min

Diff against your FIRST-15 snapshot. Copy Fail / DirtyClone change files only in memory, so hash checks miss them — watch processes.

- **Web server spawning shells** (PHP2Shell, wp2shell, Gitea): `ps -ef --forest | grep -E 'php-fpm|apache2|httpd|nginx|gitea' -A3`. A `sh`/`bash`/`curl`/`wget`/`nc`/`python` child = popped.
- **New web files**: `find /var/www /srv -type f -mmin -60 \( -name '*.php' -o -name '*.phtml' -o -name '*.aspx' \)`; wp2shell drops `temp-write-test-*` in `wp-content/`. Also [../linux/list_edited_files.sh](../linux/list_edited_files.sh).
- **Logs**: `grep -E 'batch/v1|rest_route' access.log`; `grep diffpatch` in Gitea logs; User-Agents `wp2shell`, `rezwp2shell`.
- **Windows events**: 4720 user created · 4728/4732/4756 added to group · 4769 RC4 (kerberoast) · 7045 new service · 4698 new task.
- **Wazuh first**: agents reporting on every box; FIM on `/etc/ssh`, `/etc/sudoers*`, `/etc/passwd`, `/etc/sssd`, every `authorized_keys`, `/etc/cron*`, web roots; alerts for new users, sudo, auth from odd IPs. Rotate the Wazuh admin password.
- **Persistence** (never kill the scoring cert-rotation agent from `ssh_audit.sh`): new cron/timers/units, `/etc/ld.so.preload`, `.bashrc`/`.profile`, PAM (`ls -la /lib*/security/`, `rpm -Va pam` / `debsums -c`), new SUID (`find / -perm -4000 -newer /etc/hostname`), `authorized_keys`, Run keys, WMI subs.
- **Network**: `ss -tnp state established` (or [../linux/lsof_checks.sh](../linux/lsof_checks.sh)); block odd callbacks on the box and at Vigra.
- **If popped**: keep service up → kill session → remove persistence → rotate creds it held → patch the entry point → incident report.

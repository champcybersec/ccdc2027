# Flókið update and hardening guide

One script per machine on the Flókið network (`192.168.220.0/24`), plus the official
documentation for every OS, service and protocol, so you can do every step by hand too.

## Summary

| IP | Host | OS | Service | Script | Firewall it sets |
|---|---|---|---|---|---|
| .2 | vigra | OpenWRT | Router | [`vigra.sh`](vigra.sh) | WAN zone input/forward = REJECT (port forwards untouched) |
| .30 | kolla | Alpine Linux | Fileshare (SMB/NFS) | [`kolla.sh`](kolla.sh) | iptables: 22, 139, 445, 111, 2049 |
| .10 | borgar | Windows Server 2022 | Food ordering (IIS) | [`borgar.ps1`](borgar.ps1) | Windows Firewall: 80, 443, 3389 |
| .100 | gufu | Rocky Linux | Gitea | [`gufu.sh`](gufu.sh) | firewalld: 22, 80, 443, 3000 |
| .79 | vattar | Windows Server 2019 | Active Directory | [`vattar.ps1`](vattar.ps1) | Windows Firewall: built-in AD/DNS/Kerberos/RDP rules |
| .67 | haf | Lubuntu 22.04 | Wabbit | [`haf.sh`](haf.sh) | ufw: 22, 80, 443 + **Wabbit's port (find it first)** |
| .44 | kvigindis | Ubuntu 24.04 | Furniture help site | [`kvigindis.sh`](kvigindis.sh) | ufw: 22, 80, 443 |
| .97 | skerja | Alpine 3.23 | Tickets site | [`skerja.sh`](skerja.sh) | iptables: 22, 80, 443 |
| .231 | thorska | Fedora 44 | Home Manager (Home Assistant) | [`thorska.sh`](thorska.sh) | firewalld: 22, 8123 |
| .222 | djupi | Linux Mint 22.3 | Point of sale | [`djupi.sh`](djupi.sh) | ufw: 22, 80, 443 + **POS port (find it first)** |

### What every Linux script does (same 8 steps everywhere)

1. **Update** the OS (`apt`, `dnf` or `apk`). On apt it keeps your existing config files.
2. **Users** (report only): UID-0 accounts, accounts that can log in, empty passwords, sudo/wheel members.
3. **SSH**: `PermitEmptyPasswords no`, `MaxAuthTries 4`, `LoginGraceTime 30`, `X11Forwarding no`,
   and `PermitRootLogin no` *only if* another sudo/wheel user exists. The config is tested with
   `sshd -t` before restart, and put back if the test fails.
4. **Protocols** (report only): every open port and the program behind it, with warnings for FTP,
   Telnet, SNMP (default community), VNC, RDP, mail, DNS, NFS (`no_root_squash`, `*`), SMB, OpenVPN.
5. **Leftovers** (report only): cron jobs and `authorized_keys` files.
6. **The service** (web server, Samba/NFS, Gitea or Home Assistant). See the table below.
7. **Kernel/permissions**: `/etc/sysctl.d/99-hardening.conf` (no ICMP redirects, SYN cookies, no
   source routing), and `/etc/shadow` not readable by other users. IP forwarding is left alone so
   containers keep working.
8. **Firewall**: allows only `ALLOWED_PORTS`. **Before blocking, it lists anything listening that is
   not in the list and asks you `[y/N]`**, so you can't accidentally block a scored service.

### What the service step (6) does per host

| Host | Step 6 |
|---|---|
| kvigindis, skerja, haf, djupi | Apache: `ServerTokens Prod`, `ServerSignature Off`, `TraceEnable Off`. nginx: `server_tokens off`. PHP: `expose_php = Off`. Each config is tested before reload. Warns if MySQL/PostgreSQL is reachable from the network. |
| kolla | Samba: `server min protocol = SMB2` (SMBv1 off), `ntlm auth = ntlmv2-only`, optional no-guest. Tested with `testparm`. Lists shares and Samba users. Gives a safe `/etc/exports` example. |
| gufu | Reports SELinux mode. Optionally updates the Gitea binary with checksum check (`GITEA_NEW_VERSION`). Sets `INSTALL_LOCK = true`, `RUN_MODE = prod`, optional `DISABLE_REGISTRATION`. |
| thorska | Finds Home Assistant (Docker/Podman or Core venv) and updates it. Warns if login ban is off or `trusted_networks` is set. |

### Windows scripts

| Step | borgar (IIS) | vattar (Domain Controller) |
|---|---|---|
| 1 | Windows Update (built-in API) + Defender signatures, warns about Defender exclusions | same |
| 2 | Local admins and users, disables Guest | Domain/Enterprise/Schema Admins, newest accounts, fixes "no Kerberos pre-auth" and "password not required", lists Kerberoastable SPN accounts, password policy, disables Guest |
| 3 | SMBv1 off + signing required, NTLMv2 only, no anonymous enumeration, WDigest off, LLMNR off, RDP needs NLA, AutoRun off, PowerShell logging, logon auditing, risky services report (Telnet, FTP, SNMP, VNC, OpenVPN, SMTP) | same |
| 4 | Open ports with process names, non-Microsoft scheduled tasks, Run keys (report only) | same |
| 5 | IIS: config backup, no directory browsing, no `Server`/`X-Powered-By` headers, TRACE blocked, LocalSystem app pools and WebDAV flagged; .NET strong crypto; optional TLS 1.0/1.1 off | Print Spooler off, secure DNS dynamic updates, restricted zone transfers, LDAP signing check (enforcing is off by default because it can break apps that log in to AD) |
| 6 | Firewall on, allow `$AllowedTcpPorts` | Firewall on with Windows' built-in AD/DNS/Kerberos/RDP rule groups |


**Backups and undo:**
* Linux: every changed file is in `/root/hardening-backup-<date>/` (the path `/etc/ssh/sshd_config` is saved as `_etc_ssh_sshd_config`). Copy it back and restart the service.
* OpenWRT: all of `/etc/config` is copied first. To undo: `cp /root/hardening-backup-<date>/config/* /etc/config/ && reboot`.
* Windows: `C:\HardeningBackup-<date>\` holds the firewall export (`netsh advfirewall import <file>`), the LSA registry key (`reg import <file>`) and the security policy. IIS also has its own backup, restored with `appcmd restore backup "Hardening-<date>"`.

**The scripts never delete users, change passwords or stop the scored service.** That part is
yours to do by hand. After every script, test the service from another machine.

## Manual checklist (things a script can't safely do for you)

1. Change every default or weak password: local, domain, Samba (`smbpasswd`), Gitea admin, Home Assistant, router root, database `root`/`sa`, web app admin.
2. Remove or disable accounts you don't recognise (the reports show them).
3. Remove SSH keys and cron jobs you don't recognise.
4. Update the **applications** themselves (the furniture site, ticket system, POS, Wabbit) using their own docs.
5. Reboot where a script said a reboot is needed, at a safe time.
6. Re-check the scored services from inside **and** from the `10.100.XX.0/24` side.

---

## Documentation links

### Operating systems

**OpenWRT (vigra)**
* Upgrading firmware with sysupgrade: https://openwrt.org/docs/guide-user/installation/generic.sysupgrade
* Attended sysupgrade (easier upgrades that keep your packages): https://openwrt.org/docs/guide-user/installation/attended.sysupgrade
* opkg package manager (OpenWRT 24.x and older): https://openwrt.org/docs/guide-user/additional-software/opkg
* opkg to apk cheat sheet (OpenWRT 25.x uses apk): https://openwrt.org/docs/guide-user/additional-software/opkg-to-apk-cheatsheet
* Secure access to the router (SSH keys, LuCI over HTTPS): https://openwrt.org/docs/guide-user/security/secure.access
* Dropbear SSH config: https://openwrt.org/docs/guide-user/base-system/dropbear
* Firewall overview: https://openwrt.org/docs/guide-user/firewall/overview

**Alpine Linux (kolla, skerja)**
* apk package manager: https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper
* Upgrading to a newer Alpine release: https://wiki.alpinelinux.org/wiki/Upgrading_Alpine
* iptables on Alpine: https://wiki.alpinelinux.org/wiki/Iptables
* Alpine security issue tracker: https://security.alpinelinux.org/

**Ubuntu 24.04 (kvigindis) and Lubuntu 22.04 (haf)** (Lubuntu is Ubuntu, so the same docs apply)
* Package management (apt): https://documentation.ubuntu.com/server/how-to/software/package-management/
* Automatic security updates: https://documentation.ubuntu.com/server/how-to/software/automatic-updates/
* Firewall (ufw): https://documentation.ubuntu.com/server/how-to/security/firewalls/
* OpenSSH server: https://documentation.ubuntu.com/server/how-to/security/openssh-server/
* Ubuntu security notices: https://ubuntu.com/security/notices
* Lubuntu manual: https://manual.lubuntu.me/stable/

**Linux Mint 22.3 (djupi)**
* Update Manager: https://linuxmint-user-guide.readthedocs.io/en/latest/mintupdate.html
* Mint is based on Ubuntu 24.04, so the Ubuntu apt and ufw links above also apply.

**Rocky Linux (gufu)**
* Security guides: https://docs.rockylinux.org/guides/security/
* Software management (dnf): https://docs.rockylinux.org/books/admin_guide/13-softwares/
* firewalld for beginners: https://docs.rockylinux.org/guides/security/firewalld-beginners/
* SELinux: https://docs.rockylinux.org/guides/security/learning_selinux/

**Fedora 44 (thorska)**
* dnf: https://docs.fedoraproject.org/en-US/quick-docs/dnf/
* Upgrading to a new Fedora release: https://docs.fedoraproject.org/en-US/quick-docs/upgrading-fedora-offline/
* firewalld: https://docs.fedoraproject.org/en-US/quick-docs/firewalld/
* SELinux: https://docs.fedoraproject.org/en-US/quick-docs/selinux-getting-started/

**Windows Server 2019 / 2022 (vattar, borgar)**
* Windows Update overview: https://learn.microsoft.com/en-us/windows/deployment/update/
* Security baselines (Microsoft's recommended settings): https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
* Windows Firewall: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/
* Microsoft Defender Antivirus: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows
* TLS registry settings: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

### Services

**Active Directory (vattar)**
* Best practices for securing AD: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
* LDAP signing: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/enable-ldap-signing-in-windows-server
* ActiveDirectory PowerShell module: https://learn.microsoft.com/en-us/powershell/module/activedirectory/

**IIS / food ordering (borgar)**
* IIS documentation: https://learn.microsoft.com/en-us/iis/
* SQL Server security (if the app uses SQL Server): https://learn.microsoft.com/en-us/sql/sql-server/install/security-considerations-for-a-sql-server-installation

**Gitea (gufu)**
* Upgrading Gitea: https://docs.gitea.com/installation/upgrade-from-gitea
* Backup and restore (`gitea dump`): https://docs.gitea.com/administration/backup-and-restore
* app.ini settings (config cheat sheet): https://docs.gitea.com/administration/config-cheat-sheet
* Gitea downloads: https://dl.gitea.com/gitea/

**Home Assistant (thorska)**
* Securing Home Assistant: https://www.home-assistant.io/docs/configuration/securing/
* HTTP settings (`ip_ban_enabled`, `login_attempts_threshold`): https://www.home-assistant.io/integrations/http/
* Updating a container install: https://www.home-assistant.io/common-tasks/container/

**Web servers and apps (kvigindis, skerja, djupi, haf)**
* Apache security tips: https://httpd.apache.org/docs/2.4/misc/security_tips.html
* nginx HTTPS setup: https://nginx.org/en/docs/http/configuring_https_servers.html
* Mozilla SSL config generator (good TLS settings for Apache/nginx/IIS): https://ssl-config.mozilla.org/
* PHP security: https://www.php.net/manual/en/security.php

**File sharing (kolla)**
* smb.conf reference: https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html
* Samba wiki: https://wiki.samba.org/index.php/Main_Page
* Samba on Alpine: https://wiki.alpinelinux.org/wiki/Setting_up_a_Samba_server
* NFS on Alpine: https://wiki.alpinelinux.org/wiki/Setting_up_an_NFS_server
* SMBv1/v2/v3 on Windows: https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3

### Common protocols

| Protocol | Port(s) | What to do | Docs |
|---|---|---|---|
| SSH | 22/tcp | No empty passwords, limit root, use keys | https://man.openbsd.org/sshd_config |
| RDP | 3389/tcp | Require NLA, strong passwords, only allow if needed | https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines |
| SNMP | 161/udp | Change `public`/`private`, prefer SNMPv3 | https://www.net-snmp.org/docs/man/snmpd.conf.html |
| SMTP | 25, 465, 587/tcp | Require TLS, no open relay | https://www.postfix.org/TLS_README.html |
| IMAP / POP3 | 143, 993 / 110, 995/tcp | Use the TLS ports (993/995) | https://doc.dovecot.org/ |
| VNC | 5900+/tcp | Strong password, tunnel over SSH | https://tigervnc.org/ |
| OpenVPN | 1194/udp | Certificates + `tls-crypt` | https://openvpn.net/community-resources/hardening-openvpn-security/ |
| HTTP/HTTPS | 80, 443/tcp | Redirect to HTTPS, hide versions, modern TLS | https://ssl-config.mozilla.org/ |
| Telnet | 23/tcp | Turn off; use SSH | Not needed when SSH is used |
| DNS | 53/tcp+udp | No open recursion, restrict zone transfers | https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-overview |
| NFS | 111, 2049 | Limit to your subnet, keep `root_squash` | https://linux.die.net/man/5/exports |
| SMB | 139, 445/tcp | SMBv1 off, signing on, limit guest | https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html |
| FTP | 21/tcp | No anonymous login; use SFTP/FTPS | https://security.appspot.com/vsftpd/vsftpd_conf.html |

### General references

* CIS Benchmarks (step-by-step hardening for every OS above): https://www.cisecurity.org/cis-benchmarks
* CISA Known Exploited Vulnerabilities (patch these first): https://www.cisa.gov/known-exploited-vulnerabilities-catalog
* NIST National Vulnerability Database: https://nvd.nist.gov/

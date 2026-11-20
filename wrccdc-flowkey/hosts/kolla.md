# Kolla .30 — Alpine, Fileshare

**CVEs:** Copy Fail · DirtyClone (mainly a misconfig box)

- Identify: Samba, NFS, or FTP (`ss -tulpn`).
- Samba `smb.conf`: `map to guest = never`, remove guest shares, `server min protocol = SMB2`; `smbpasswd` every user.
- NFS `/etc/exports`: no `no_root_squash`, no `*` wildcards; `exportfs -ra`.
- FTP: no anonymous login.
- Share mounts `noexec`; watch for script/webshell drops that other services might serve.

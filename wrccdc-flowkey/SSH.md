# SSH plan (scoring-safe)

SSH is the primary scored service on every box except Vigra. Scoring logs in with **SSH certificates** from the comp's PKI, rotated automatically every 5–10 min. Scoring auth must stay the same; you may add your own keys.

## Never touch

- `TrustedUserCAKeys` and the CA file it points to
- `AuthorizedPrincipalsFile` / principals files
- `HostCertificate`, host keys
- The cert-rotation agent (cron/timer/service). Find it in the audit and write it down so hunting never kills it.

## Steps per box

1. Proxmox snapshot (if allowed). Keep the Proxmox console open as your fallback.
2. `sh ssh/ssh_audit.sh | tee /root/ssh_audit_$(hostname).txt` — read-only. Note the CA, principals, rotation agent, every `authorized_keys` line, red flags.
3. Patch OpenSSH (CVE-2026-35414 is live here because a CA is trusted): `apt install --only-upgrade openssh-server` / `dnf upgrade openssh` / `apk upgrade openssh`. `sshd -t` then reload.
4. Rotate user keys — dry run, read it, then apply:
   ```
   sh ssh/rotate_user_keys.sh -t team.pub -u root,<admin> -k '<scoring key comment>' --drop-ca
   sh ssh/rotate_user_keys.sh -t team.pub -u root,<admin> -k '<scoring key comment>' --drop-ca --apply
   ```
   Keeps only allow-listed lines (`-k` regex or `-f` fingerprint file), adds the team key, clears `chattr +i`, backs up to `/root/ssh-rotate-<time>/`. Refuses `--apply` without an allow-list unless `--force`. Use `--keep-ca` instead of `--drop-ca` if the audit shows the scoring CA as a `cert-authority` line.
5. Optional team certs (short-lived, stolen ones expire):
   ```
   # laptop (never on the comp network)
   sh ssh/team_ca.sh init
   sh ssh/team_ca.sh sign ~/.ssh/id_ed25519.pub <admin> +2h
   # box
   sh ssh/deploy_team_ca.sh team_ca.pub <admin> --apply
   ```
   Adds a `cert-authority` line to that user's `authorized_keys` only — the scoring CA file is never edited. Cert principals must equal the username.
6. sshd hardening that doesn't break scoring: `PermitRootLogin prohibit-password` (or `no` if scoring isn't root), `PasswordAuthentication no` once your keys work, `MaxAuthTries 3`. If you add `AllowUsers`, include the scoring user.
7. Test from another box in a NEW session, confirm the scorer is green, then close the old session.

## AD-integrated boxes

- Check `realm list` and `/etc/sssd/sssd.conf` (`access_provider`, `simple_allow_groups`, `ad_access_filter`). Restrict logins to your admin group: `realm permit -g '<team group>'` (keep the scoring account allowed).
- `ldap_user_ssh_public_key` in sssd + `AuthorizedKeysCommand sss_ssh_authorizedkeys` = SSH keys stored in AD. Audit those in AD too.
- Don't change the scoring account's password.

## Host keys

Leave them unless the White/Black team says otherwise: regenerating breaks `HostCertificate` and any scorer pinning.

## Tested

Against a mock box (OpenSSH 9.6, CA + principals): scorer cert still logs in after rotation · red CA cert and red key denied · team cert works for its user only, expired cert denied · `/etc/ssh` byte-identical before/after.

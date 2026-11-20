# WRCCDC — Flókið (Flow-Key)

Blue team prep for the Flókið environment. Internal `192.168.220.0/24`, external (dev4) `10.100.XX.0/24`, router `vigra`.

| File | Use it for |
| --- | --- |
| [SSH.md](SSH.md) + [ssh/](ssh/) | Scoring-safe SSH audit, key rotation, team certs |
| [CVE-CHECKLIST.md](CVE-CHECKLIST.md) | Tick off each CVE once patched or mitigated |
| [FIRST-15.md](FIRST-15.md) | Steps for every box at the start |
| [HUNTING.md](HUNTING.md) | Recurring checks during the comp |
| [hosts/](hosts/) | Per-host CVEs + hardening |

## Comp facts (info call)

- Noon–8 PM. Someone in VC always — missed check-ins cost points. `/link` in Discord.
- NetBird into the comp (or the no-VPN link in the portal). Proxmox console on almost every box.
- **SSH is the primary scored service on every box except the router.** Scoring uses SSH certs from a full PKI, rotated every 5–10 min. Scoring auth must stay the same; add your own keys. **Never remove `TrustedUserCAKeys`.**
- Cert scripts are scored heavily → [ssh/](ssh/).
- Everything is AD-integrated: AD compromise = every Linux box.
- Wazuh is on one box, ours only, out of red's scope.
- Back up web content. 12–20 injects. Ticket portal. Incident reports earn points back.

## Hosts

| Host | IP | OS | Service | Notes |
| --- | --- | --- | --- | --- |
| [Vigra](hosts/vigra.md) | .2 | OpenWrt | Router | odhcpd RCE |
| [Borgar](hosts/borgar.md) | .10 | Server 2022 | Food Ordering | LDAP RCE, PHP? |
| [Kolla](hosts/kolla.md) | .30 | Alpine | Fileshare | Guest shares |
| [Kvígindis](hosts/kvigindis.md) | .44 | Ubuntu 24.04 | Furniture Help Site | wp2shell, PHP2Shell |
| [Haf](hosts/haf.md) | .67 | Lubuntu 22 | Wabbit (proprietary) | Fingerprint it |
| [Vattar](hosts/vattar.md) | .79 | Server 2019 | AD DC | Netlogon RCE |
| [Skerja](hosts/skerja.md) | .97 | Alpine 3.23 | Tickets | PHP2Shell |
| [Gufu](hosts/gufu.md) | .100 | Rocky | Gitea | CVE-2026-60004 |
| [Thorska](hosts/thorska.md) | .231 | Fedora 44 | Home Manager | Pack2TheRoot |
| [Djupi](hosts/djupi.md) | ? | Mint 22.3 | POS | IP cut off in diagram |

## Priority order

1. Proxmox snapshots, rotate creds, SSH audit + key rotation ([FIRST-15.md](FIRST-15.md), [SSH.md](SSH.md)).
2. P1: Netlogon, PHP2Shell, wp2shell, Gitea, odhcpd, OpenSSH CVE-2026-35414.
3. P2 local root: Copy Fail, DirtyClone, Pack2TheRoot (offline mitigations work without patching).
4. Hunt every 30–45 min ([HUNTING.md](HUNTING.md)).

App guesses (WordPress, PHP, etc.) are unconfirmed — check each box on the day.

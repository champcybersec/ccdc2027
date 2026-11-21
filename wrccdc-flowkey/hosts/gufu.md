# Gufu .100 — Rocky Linux, Gitea

**CVEs:** CVE-2026-60004 diffpatch RCE (1.17–1.27.0, fixed 1.27.1) · Copy Fail · DirtyClone

- Version: `gitea --version` or page footer. Swap in the 1.27.1+ binary if you can get it.
- `app.ini`:
  - `[service] DISABLE_REGISTRATION = true` (+ `REQUIRE_SIGNIN_VIEW = true` if scoring allows)
  - `[repository] MAX_CREATION_LIMIT = 0` for non-admins
- Restart Gitea. Admin panel: disable unknown users, revoke tokens, untick "may create git hooks", rotate admin password + `SECRET_KEY`/`INTERNAL_TOKEN`.
- Planted hooks: `find <repo-root> -path '*hooks*' -type f -newer /etc/hostname`. Check webhooks + Actions runners.
- Exploit endpoint to watch in logs: `POST /api/v1/repos/{owner}/{repo}/diffpatch`.
- `getenforce` = Enforcing; firewalld allows only 22 + Gitea port.

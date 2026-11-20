# Borgar .10 — Server 2022, Food Ordering

**CVEs:** CVE-2026-119958 LDAP (Nov 2026 CU) · if PHP: PHP2Shell, CVE-2024-4577 php-cgi

- Identify stack: IIS/ASP.NET, PHP on IIS, or XAMPP.
- PHP → upgrade or `session.upload_progress.enabled = Off`; see [kvigindis.md](kvigindis.md) php.ini block.
- Rotate app DB + admin creds. Hunt web root for `.aspx`/`.php` newer than the image.
- RDP: NLA on, 3389 to team IPs only.
- Defender + tamper protection on; `Get-MpPreference | select Exclusion*` for planted exclusions ([../../windows/defender.ps1](../../windows/defender.ps1)).

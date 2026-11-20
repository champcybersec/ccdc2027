# Vattar .79 — Server 2019 AD DC

**CVEs:** CVE-2026-41089 Netlogon (KB5087538) · CVE-2026-119958 LDAP RCE (Nov 2026 CU)

- Patch Netlogon first if updates can be staged; else firewall 135/445/389/636/dynamic RPC to domain members only.
- Reset `krbtgt` **twice** (wait for replication between). Reset Administrator + all DA/EA.
- Audit groups: Domain/Enterprise/Schema Admins, Administrators, Account/Backup Operators, DnsAdmins, GP Creator Owners.
- Roast/delegation: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`; long passwords on SPN accounts; check `TrustedForDelegation`, AdminSDHolder, DCSync rights.
- AD CS present → Locksmith/Certify for ESC1–8; turn off `EDITF_ATTRIBUTESUBJECTALTNAME2`.
- GPO: SMB + LDAP signing, channel binding, no SMBv1/NTLMv1/LLMNR/NBT-NS. Stop Print Spooler.
- SYSVOL: grep for `cpassword`; review logon/startup scripts.
- Defender: [../../windows/defender.ps1](../../windows/defender.ps1).

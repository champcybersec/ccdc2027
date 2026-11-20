# Thorska .231 — Fedora 44, Home Manager

**CVEs:** Pack2TheRoot · udisks2 · Copy Fail · DirtyClone

- Identify "Home Manager" (web app? Home Assistant? Python service?) and lock its admin login.
- `systemctl mask --now packagekit udisks2`.
- `dnf upgrade --refresh` for a fixed kernel if a mirror is reachable.
- SELinux enforcing; firewalld zone `drop` + explicit scored services ([../../linux/ufw_setup_rpm.sh](../../linux/ufw_setup_rpm.sh) if you prefer ufw).

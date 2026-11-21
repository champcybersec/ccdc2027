# Djupi (IP ?) — Linux Mint 22.3, POS

**CVEs:** Pack2TheRoot · udisks2 · Copy Fail · DirtyClone · PHP2Shell if PHP-based

- IP was cut off in the diagram — confirm on the day.
- Back up the POS DB first (customer-data injects); rotate its DB user.
- `systemctl mask --now packagekit udisks2 cups avahi-daemon`.
- LightDM: remove `autologin-user`; check `~/.config/autostart` ([../../linux/xdg-autostart.sh](../../linux/xdg-autostart.sh)).
- Firewall: [../../linux/ufw_setup_debian.sh](../../linux/ufw_setup_debian.sh).

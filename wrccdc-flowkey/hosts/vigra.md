# Vigra .2 — OpenWrt router

Not SSH-scored (the only box that isn't) — you can lock dropbear down hard.

**CVEs:** CVE-2026-53921 odhcpd (fixed 24.10.8) · CVE-2026-30871/-30872 umdns/DNS (fixed 24.10.6 / 25.12.1)

- `cat /etc/openwrt_release` — check version against the fixes above.
- `passwd` root.
- Dropbear + LuCI on LAN only: `uci set dropbear.@dropbear[0].Interface='lan'; uci commit`; uhttpd `listen_http`/`listen_https` → `192.168.220.2`.
- IPv6 not scored → `/etc/init.d/odhcpd stop; /etc/init.d/odhcpd disable`. Stop `umdns` if present.
- `/etc/config/firewall`: remove port forwards you didn't expect; forward only scored services from dev4; WAN input drop.
- Check `/etc/rc.local`, `/etc/crontabs/root`, `/etc/dropbear/authorized_keys`.

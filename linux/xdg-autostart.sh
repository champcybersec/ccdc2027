for d in ~/.config/autostart /etc/xdg/autostart; do for f in "$d"/*.desktop; do [ -e "$f" ] && echo "Detected: $f"; done; done 2>/dev/null

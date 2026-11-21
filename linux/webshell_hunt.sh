#!/usr/bin/env bash
# webshell_hunt.sh - enumerate web services on a Linux host and hunt for webshells.
#
# Read-only: nothing on the host is modified. Run it on systems you administer.
# Run as root; without root, other users' processes, sockets and files are hidden.
#
# What it does
#   A. Services  - every listening TCP port (read from /proc, so no ss/netstat
#                  needed), the owning process, and an HTTP + HTTPS probe of each
#                  port; installed/running web daemons; document roots.
#   B. Files     - webshell/dropper signatures, obfuscation, scripts in upload
#                  directories, disguised extensions, hidden scripts, handler
#                  overrides, recent changes, web-user files in temp dirs.
#   C. Processes - shells spawned by web users, reverse-shell connections, cron.
#
# Usage
#   sudo ./webshell_hunt.sh [extra_web_root ...]
#   sudo ./webshell_hunt.sh /opt/app/public | tee report.txt
#
# Options (environment variables)
#   RECENT_DAYS=7     window for "recently changed" files
#   MAX_MB=25         files larger than this are not content-scanned (they are listed)
#   MAX_LINES=200     max lines printed per check
#   PROBE=1           0 = do not send HTTP requests to local ports
#   PROBE_TIMEOUT=3   seconds per probe
#   WEB_USERS="a b"   extra account names to treat as web-server users
#   NO_CURL=1         probe with bash /dev/tcp + openssl instead of curl
#
# Notes
#   - The probe sends one "GET /" over HTTP and one over HTTPS to each local
#     listening TCP port. Set PROBE=0 to skip it.
#   - Everything here is a heuristic: hits are leads to verify, and a clean run
#     does not prove the host is clean.
#   - Only this host's network/mount namespace is examined. Web roots inside
#     containers must be scanned from inside the container (or passed as paths).

set -u
export LC_ALL=C
umask 077

case "${1:-}" in
  -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

# ---- preflight --------------------------------------------------------------
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "error: bash 4 or newer is required" >&2; exit 2
fi
[ "$(uname -s)" = Linux ] || { echo "error: this script is for Linux" >&2; exit 2; }
[ -r /proc/net/tcp ] || { echo "error: /proc is not mounted or not readable" >&2; exit 2; }
find --version 2>/dev/null | grep -q GNU || { echo "error: GNU findutils is required" >&2; exit 2; }
for t in grep awk sed sort xargs readlink tr cut od head wc id; do
  command -v "$t" >/dev/null 2>&1 || { echo "error: required tool missing: $t" >&2; exit 2; }
done

RECENT_DAYS=${RECENT_DAYS:-7}
MAX_MB=${MAX_MB:-25}
MAX_LINES=${MAX_LINES:-200}
PROBE=${PROBE:-1}
PROBE_TIMEOUT=${PROBE_TIMEOUT:-3}
for v in RECENT_DAYS MAX_MB MAX_LINES PROBE_TIMEOUT; do
  case "${!v}" in
    ''|*[!0-9]*) echo "error: $v must be a positive integer" >&2; exit 2 ;;
  esac
  printf -v "$v" '%d' "$((10#${!v}))"
  [ "${!v}" -gt 0 ] || { echo "error: $v must be a positive integer" >&2; exit 2; }
done

HAVE_CURL=0
[ "${NO_CURL:-0}" != 1 ] && command -v curl >/dev/null 2>&1 && HAVE_CURL=1
HAVE_OPENSSL=0
command -v openssl >/dev/null 2>&1 && HAVE_OPENSSL=1
if command -v timeout >/dev/null 2>&1; then
  to() { timeout "$@"; }
else
  to() { shift; "$@"; }
fi

TMPD=$(mktemp -d) || exit 2
trap 'rm -rf "$TMPD"' EXIT
trap 'exit 130' INT TERM
PATS=$TMPD/patterns

# Byte order of this machine (needed to decode /proc/net/tcp addresses).
LE=0
[ "$(printf '\001\000' | od -An -td2 | tr -d ' \n')" = 1 ] && LE=1

# ---- constants --------------------------------------------------------------
# File extensions treated as server-side script files.
EXT='php[0-9]?|phtml|pht|phps|phar|inc|module|jsp|jspx|jspf|jsw|jsv|asp|aspx|ashx|asmx|ascx|asa|cer|cfm|cfc|cgi|pl|py|rb|sh|shtml'
# Process names (comm).
SHELL_RE='^(sh|bash|dash|zsh|ksh|ash|csh|tcsh|fish|busybox|nc|ncat|netcat|nc\.openbsd|nc\.traditional|socat|telnet|script)$'
INTERP_RE='^(perl[0-9.]*|python[0-9.]*|ruby[0-9.]*|php[0-9.]*|lua[0-9.]*|node|nodejs|deno|bun)$'
INLINE_RE='[[:space:]]-(c|e|r)([[:space:]]|$)'
# Daemons whose (non-root) owner is treated as a web-server account.
CORE_WEBD_RE='^(apache2|httpd|nginx|lighttpd|openresty|caddy|lshttpd|litespeed|lsphp[0-9]*|php-fpm[0-9.]*|php[0-9.]*-fpm[0-9.]*|h2o|hiawatha|cherokee)$'
# Anything that normally serves or proxies HTTP.
WEBD_RE='^(apache2|httpd|nginx|lighttpd|openresty|caddy|lshttpd|litespeed|lsphp[0-9]*|php-fpm[0-9.]*|php[0-9.]*-fpm[0-9.]*|h2o|hiawatha|cherokee|haproxy|varnishd|traefik|envoy|squid|gunicorn|uwsgi|uvicorn|hypercorn|daphne|puma|unicorn|passenger.*|java|tomcat[0-9]*|jsvc|dotnet|node|nodejs)$'

# ---- output helpers ---------------------------------------------------------
SUMMARY=()
hdr() { printf '\n==== %s ====\n' "$*"; }

# check "title" < <(command)  : print the command's output under a header,
# capped at MAX_LINES, and record the hit count for the summary.
check() {
  local title=$1 out n
  out=$(cat)
  hdr "$title"
  if [ -z "$out" ]; then
    echo "(nothing flagged)"
    return 0
  fi
  n=$(printf '%s\n' "$out" | wc -l)
  n=$((n + 0))
  printf '%s\n' "$out" | awk -v m="$MAX_LINES" \
    'NR <= m { print } END { if (NR > m) printf "... %d more line(s) not shown (raise MAX_LINES)\n", NR - m }'
  SUMMARY+=("$(printf '%6d  %s' "$n" "$title")")
}

in_tmp() {
  case "$1" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|/tmp|/var/tmp|/dev/shm|/run/shm) return 0 ;;
  esac
  return 1
}

# ---- process table (from /proc) ---------------------------------------------
declare -A P_USER P_PPID P_COMM P_CMD P_EXE P_CWD UID_NAME
PIDS=()

uid_name() {    # $1 = uid ; result in REPLY (cached)
  local u=$1 n
  if [ -z "${UID_NAME[$u]:-}" ]; then
    n=$(id -nu "$u" 2>/dev/null) || n=
    [ -n "$n" ] || n=$u
    UID_NAME[$u]=$n
  fi
  REPLY=${UID_NAME[$u]}
}

scan_procs() {
  local d pid k ruid euid comm st ppid cmd a
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ -r "$d/status" ] || continue
    euid=
    {
      while read -r k ruid euid _; do
        [ "$k" = "Uid:" ] && break
        euid=
      done < "$d/status"
    } 2>/dev/null
    [ -n "$euid" ] || continue
    comm=; st=; cmd=
    { IFS= read -r comm < "$d/comm"; } 2>/dev/null
    { IFS= read -r st < "$d/stat"; } 2>/dev/null
    st=${st##*) }
    ppid=
    read -r _ ppid _ <<<"$st"
    {
      while IFS= read -r -d '' a || [ -n "$a" ]; do
        cmd+="$a "
      done < "$d/cmdline"
    } 2>/dev/null
    cmd=${cmd% }
    cmd=${cmd//[[:cntrl:]]/?}
    uid_name "$euid"
    PIDS+=("$pid")
    P_USER[$pid]=$REPLY
    P_PPID[$pid]=${ppid:-?}
    P_COMM[$pid]=${comm:-?}
    P_CMD[$pid]=${cmd:0:300}
    P_EXE[$pid]=$(readlink "$d/exe" 2>/dev/null)
    P_CWD[$pid]=$(readlink "$d/cwd" 2>/dev/null)
  done
}

# ---- sockets (from /proc/net/tcp*) ------------------------------------------
declare -A INODE_PIDS
L_ADDR=(); L_PORT=(); L_PIDS=(); L_UID=(); L_HTTP=()
E_LOCAL=(); E_REMOTE=(); E_PIDS=()

map_socket_inodes() {
  local dir link pid ino
  while read -r dir link; do
    pid=${dir#/proc/}; pid=${pid%%/*}
    ino=${link#socket:[}; ino=${ino%]}
    case ",${INODE_PIDS[$ino]:-}," in
      *",$pid,"*) ;;
      *) INODE_PIDS[$ino]=${INODE_PIDS[$ino]:+${INODE_PIDS[$ino]},}$pid ;;
    esac
  done < <(find /proc/[0-9]*/fd -maxdepth 1 -type l -lname 'socket:*' -printf '%h %l\n' 2>/dev/null)
}

hex2ip4() {     # 8 hex digits -> dotted quad in REPLY
  local h=$1
  if [ "$LE" = 1 ]; then
    REPLY="$((16#${h:6:2})).$((16#${h:4:2})).$((16#${h:2:2})).$((16#${h:0:2}))"
  else
    REPLY="$((16#${h:0:2})).$((16#${h:2:2})).$((16#${h:4:2})).$((16#${h:6:2}))"
  fi
}

hex2ip6() {     # 32 hex digits -> IPv6 text in REPLY
  local h=$1 n= w i g out=
  for i in 0 8 16 24; do
    w=${h:$i:8}
    if [ "$LE" = 1 ]; then w=${w:6:2}${w:4:2}${w:2:2}${w:0:2}; fi
    n+=$w
  done
  n=${n,,}
  case "$n" in
    00000000000000000000000000000000) REPLY=::; return ;;
    00000000000000000000000000000001) REPLY=::1; return ;;
    00000000000000000000ffff*)
      w=${n:24:8}
      REPLY="::ffff:$((16#${w:0:2})).$((16#${w:2:2})).$((16#${w:4:2})).$((16#${w:6:2}))"
      return ;;
  esac
  for i in 0 4 8 12 16 20 24 28; do
    printf -v g '%x' "$((16#${n:$i:4}))"
    out+=${out:+:}$g
  done
  REPLY=$out
}

decode_endpoint() {     # "HEXADDR:HEXPORT" -> EP_ADDR, EP_PORT
  local a=${1%:*} p=${1##*:}
  EP_PORT=$((16#$p))
  if [ "${#a}" -eq 8 ]; then hex2ip4 "$a"; else hex2ip6 "$a"; fi
  EP_ADDR=$REPLY
}

scan_sockets() {
  local f laddr raddr st uid inode n la lp
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    while read -r _ laddr raddr st _ _ _ uid _ inode _; do
      case "$st" in
        0A)
          decode_endpoint "$laddr"
          n=${#L_ADDR[@]}
          L_ADDR[$n]=$EP_ADDR; L_PORT[$n]=$EP_PORT
          L_UID[$n]=$uid; L_PIDS[$n]=${INODE_PIDS[$inode]:-}; L_HTTP[$n]=
          ;;
        01)
          decode_endpoint "$laddr"; la=$EP_ADDR; lp=$EP_PORT
          decode_endpoint "$raddr"
          n=${#E_LOCAL[@]}
          E_LOCAL[$n]="$la:$lp"; E_REMOTE[$n]="$EP_ADDR:$EP_PORT"
          E_PIDS[$n]=${INODE_PIDS[$inode]:-}
          ;;
      esac
    done < "$f"
  done
}

# ---- HTTP probe -------------------------------------------------------------
probe_target() {    # listen address -> PT_RAW (for /dev/tcp), PT_URL (for URLs)
  local a=$1
  case "$a" in
    0.0.0.0|::ffff:0.0.0.0) PT_RAW=127.0.0.1 ;;
    ::) PT_RAW=::1 ;;
    ::ffff:*) PT_RAW=${a#::ffff:} ;;
    *) PT_RAW=$a ;;
  esac
  case "$PT_RAW" in
    *:*) PT_URL="[$PT_RAW]" ;;
    *) PT_URL=$PT_RAW ;;
  esac
}

fetch_headers() {   # scheme raw_host url_host port -> raw response on stdout
  local s=$1 raw=$2 uh=$3 port=$4
  local req='GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: webshell_hunt\r\nConnection: close\r\n\r\n'
  if [ "$HAVE_CURL" = 1 ]; then
    curl -sk --noproxy '*' --connect-timeout 2 -m "$PROBE_TIMEOUT" \
         -A webshell_hunt -o /dev/null -D - "$s://$uh:$port/"
  elif [ "$s" = http ]; then
    # shellcheck disable=SC2016
    to "$PROBE_TIMEOUT" bash -c \
      'exec 3<>"/dev/tcp/$1/$2" || exit 1; printf "$3" >&3; head -c 4096 <&3' \
      _ "$raw" "$port" "$req"
  elif [ "$HAVE_OPENSSL" = 1 ]; then
    # shellcheck disable=SC2059
    printf "$req" | to "$PROBE_TIMEOUT" openssl s_client -quiet -ign_eof -connect "$uh:$port" | head -c 4096
  fi
}

http_probe() {      # raw_host url_host port -> lines "scheme<TAB>status | headers"
  local raw=$1 uh=$2 port=$3 s sum
  for s in http https; do
    sum=$(fetch_headers "$s" "$raw" "$uh" "$port" 2>/dev/null </dev/null \
      | tr -d '\000\r' | head -n 40 | tr '\001-\011\013-\037\177' '?' \
      | awk 'NR == 1 { if ($0 !~ /^HTTP\/[0-9.]+ [0-9][0-9][0-9]/) exit; printf "%s", $0; ok = 1; next }
             /^$/ { exit }
             tolower($0) ~ /^(server|x-powered-by|location|www-authenticate):/ { printf " | %s", $0 }
             END { if (ok) print "" }' | cut -c1-300)
    [ -n "$sum" ] && printf '%s\t%s\n' "$s" "$sum"
  done
}

# ---- collect ----------------------------------------------------------------
scan_procs
map_socket_inodes
scan_sockets

if [ "$PROBE" = 1 ]; then
  # Probe ports in parallel (batches of 24) so silent ports do not add up.
  n=0
  for i in "${!L_ADDR[@]}"; do
    probe_target "${L_ADDR[$i]}"
    http_probe "$PT_RAW" "$PT_URL" "${L_PORT[$i]}" > "$TMPD/probe.$i" 2>/dev/null &
    n=$((n + 1))
    [ $((n % 24)) -eq 0 ] && wait
  done
  wait
  for i in "${!L_ADDR[@]}"; do
    [ -s "$TMPD/probe.$i" ] && L_HTTP[$i]=$(cat "$TMPD/probe.$i")
  done
fi

# Web-server accounts: well-known names that exist here, owners of running web
# daemons, and anything passed in WEB_USERS. root is never included.
declare -A WEBU
for u in www-data apache nginx httpd http www wwwrun lighttpd caddy nobody tomcat tomcat8 tomcat9 tomcat10 lsadm ${WEB_USERS:-}; do
  [ "$u" = root ] && continue
  id "$u" >/dev/null 2>&1 && WEBU[$u]=1
done
for pid in ${PIDS[@]+"${PIDS[@]}"}; do
  if [[ ${P_COMM[$pid]} =~ $CORE_WEBD_RE ]] && [ "${P_USER[$pid]}" != root ]; then
    WEBU[${P_USER[$pid]}]=1
  fi
done

# Document roots.
declare -A ROOT_SRC
ROOTS=()
add_root() {    # path, source label
  local d
  [ -n "$1" ] || return 0
  d=$(readlink -f -- "$1" 2>/dev/null) || return 0
  [ -d "$d" ] || return 0
  case "$d" in
    /|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*) return 0 ;;
  esac
  [ -n "${ROOT_SRC[$d]:-}" ] || ROOT_SRC[$d]=$2
}

for d in "$@"; do
  if [ -d "$d" ]; then add_root "$d" "argument"; else echo "warning: not a directory, skipped: $d" >&2; fi
done
for d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/share/caddy \
         /usr/local/apache2/htdocs /usr/local/nginx/html /usr/local/www /opt/lampp/htdocs \
         /usr/lib/cgi-bin /var/lib/tomcat*/webapps /opt/tomcat*/webapps \
         /usr/share/tomcat*/webapps /usr/local/tomcat/webapps \
         /home/*/public_html /home/*/www /home/*/htdocs; do
  add_root "$d" "common location"
done
CONF_DIRS=()
for d in /etc/nginx /etc/apache2 /etc/httpd /etc/lighttpd /etc/caddy /etc/openresty \
         /usr/local/nginx/conf /usr/local/apache2/conf /usr/local/etc/nginx \
         /usr/local/etc/apache24 /usr/local/openresty/nginx/conf /opt/lampp/etc; do
  [ -d "$d" ] && CONF_DIRS+=("$d")
done
if [ "${#CONF_DIRS[@]}" -gt 0 ]; then
  while IFS= read -r d; do
    add_root "$d" "server config"
  done < <(
    grep -RhsiE '^[[:space:]]*(root|documentroot|server\.document-root|alias|scriptalias)[[:space:]=]' "${CONF_DIRS[@]}" 2>/dev/null \
    | awk '
        function emit(s) {
          sub(/^[ \t]+/, "", s)
          if (s ~ /^"/)         { sub(/^"/, "", s);    sub(/".*$/, "", s) }
          else if (s ~ /^\047/) { sub(/^\047/, "", s); sub(/\047.*$/, "", s) }
          else                  { sub(/[ \t;].*$/, "", s) }
          sub(/;$/, "", s)
          if (s ~ /^\//) print s
        }
        {
          line = $0; sub(/^[ \t]+/, "", line); low = tolower(line)
          if (low ~ /^root[ \t]+\*[ \t]+/)                 { sub(/^[^ \t]+[ \t]+\*[ \t]+/, "", line); emit(line) }
          else if (low ~ /^(root|documentroot)[ \t]+/)     { sub(/^[^ \t]+[ \t]+/, "", line); emit(line) }
          else if (low ~ /^server\.document-root[ \t]*=/)  { sub(/^[^=]*=/, "", line); emit(line) }
          else if (low ~ /^(script)?alias[ \t]+/)          { sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]+/, "", line); emit(line) }
        }' | sort -u
  )
fi
# Working directories of processes that answered HTTP (app servers, dev servers).
for i in "${!L_ADDR[@]}"; do
  [ -n "${L_HTTP[$i]}" ] || continue
  IFS=, read -r -a parr <<<"${L_PIDS[$i]}"
  for pid in ${parr[@]+"${parr[@]}"}; do
    d=${P_CWD[$pid]:-}
    case "$d" in
      ''|/|/proc/*|/sys/*|/dev/*|/run/*|*' (deleted)') continue ;;
    esac
    [[ $d == /*/* ]] || continue
    add_root "$d" "cwd of HTTP process ${P_COMM[$pid]:-?} (pid $pid)"
  done
done
# Drop roots nested inside another root so nothing is scanned twice.
if [ "${#ROOT_SRC[@]}" -gt 0 ]; then
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    keep=1
    for r in ${ROOTS[@]+"${ROOTS[@]}"}; do
      case "$d" in "$r"/*) keep=0; break ;; esac
    done
    [ "$keep" = 1 ] && ROOTS+=("$d")
  done < <(printf '%s\n' "${!ROOT_SRC[@]}" | sort)
fi

# ============================================================================
# A. SERVICES
# ============================================================================
hdr "Host"
echo "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname) | $(uname -sr) | $(date '+%Y-%m-%d %H:%M:%S %Z')"
if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root. Processes, sockets and files owned by other"
  echo "         users are hidden, so results are incomplete. Re-run with sudo."
fi

hdr "A1. Listening TCP ports (all ports, with owning process and HTTP/HTTPS probe)"
LISTEN_FLAGS=0
if [ "${#L_ADDR[@]}" -eq 0 ]; then
  echo "(no listening TCP sockets found)"
fi
ORDER=()
while read -r _ i; do
  [ -n "$i" ] && ORDER+=("$i")
done < <(for i in "${!L_ADDR[@]}"; do printf '%s %s\n' "${L_PORT[$i]}" "$i"; done | sort -n -k1,1 -k2,2)

for i in ${ORDER[@]+"${ORDER[@]}"}; do
  addr=${L_ADDR[$i]}; port=${L_PORT[$i]}
  case "$addr" in *:*) shown="[$addr]:$port" ;; *) shown="$addr:$port" ;; esac
  IFS=, read -r -a parr <<<"${L_PIDS[$i]}"
  declare -A seen_u=() flags=()
  users=
  for pid in ${parr[@]+"${parr[@]}"}; do
    u=${P_USER[$pid]:-?}
    [ -n "${seen_u[$u]:-}" ] || { seen_u[$u]=1; users+=${users:+,}$u; }
  done
  if [ "${#parr[@]}" -gt 0 ]; then
    first=${parr[0]}
    more=
    [ "${#parr[@]}" -gt 1 ] && more=" (+$(( ${#parr[@]} - 1 )) more)"
    printf '%s\n' "$shown  ${P_COMM[$first]:-?}  pid $first$more  user(s): $users"
    printf '    exe: %s\n' "${P_EXE[$first]:-unreadable}"
    printf '    cwd: %s\n' "${P_CWD[$first]:-unreadable}"
    printf '    cmd: %s\n' "${P_CMD[$first]:-}"
  else
    uid_name "${L_UID[$i]}"
    printf '%s  process not visible (socket owner: %s)\n' "$shown" "$REPLY"
  fi
  if [ "$PROBE" != 1 ]; then
    echo "    http: probe disabled"
  elif [ -n "${L_HTTP[$i]}" ]; then
    while IFS=$'\t' read -r s sum; do
      printf '    %-6s %s\n' "$s:" "$sum"
    done <<<"${L_HTTP[$i]}"
  else
    echo "    http: no HTTP/HTTPS response"
  fi
  for pid in ${parr[@]+"${parr[@]}"}; do
    comm=${P_COMM[$pid]:-}; exe=${P_EXE[$pid]:-}; u=${P_USER[$pid]:-}
    [[ $comm =~ $SHELL_RE ]] && flags["[!] '$comm' is a shell/netcat-style program holding a listening socket: possible bind shell"]=1
    case "$exe" in
      *' (deleted)') flags["[!] the binary was deleted from disk while running (also happens after package upgrades; verify)"]=1 ;;
    esac
    in_tmp "$exe" && flags["[!] the binary runs from a temp directory: $exe"]=1
    for r in ${ROOTS[@]+"${ROOTS[@]}"}; do
      case "$exe" in "$r"/*) flags["[!] the binary runs from inside a web root: $exe"]=1 ;; esac
    done
    if [ -n "$u" ] && [ -n "${WEBU[$u]:-}" ] && ! [[ $comm =~ $WEBD_RE ]]; then
      flags["[?] owned by web user '$u' but '$comm' is not a known web daemon: confirm it is expected"]=1
    fi
    [[ $comm =~ $INTERP_RE ]] && flags["[?] interpreter-hosted listener ('$comm'): app/dev server or possible backdoor, confirm it is expected"]=1
    [ "$comm" = docker-proxy ] && flags["[i] forwarded to a container: scan that container's web root from inside it"]=1
  done
  if [ "${#flags[@]}" -gt 0 ]; then
    while IFS= read -r f; do
      printf '    %s\n' "$f"
      case "$f" in '[i]'*) ;; *) LISTEN_FLAGS=$((LISTEN_FLAGS + 1)) ;; esac
    done < <(printf '%s\n' "${!flags[@]}" | sort)
  fi
  unset seen_u flags
done
[ "$LISTEN_FLAGS" -gt 0 ] && SUMMARY+=("$(printf '%6d  %s' "$LISTEN_FLAGS" "A1. Listening-port flags ([!] and [?])")")

hdr "A2. Web services found (ports that answered HTTP or HTTPS)"
found=0
for i in ${ORDER[@]+"${ORDER[@]}"}; do
  [ -n "${L_HTTP[$i]}" ] || continue
  addr=${L_ADDR[$i]}
  case "$addr" in *:*) shown="[$addr]:${L_PORT[$i]}" ;; *) shown="$addr:${L_PORT[$i]}" ;; esac
  IFS=, read -r -a parr <<<"${L_PIDS[$i]}"
  comm=?
  [ "${#parr[@]}" -gt 0 ] && comm=${P_COMM[${parr[0]}]:-?}
  while IFS=$'\t' read -r s sum; do
    printf '%-26s %-5s %-16s %s\n' "$shown" "$s" "$comm" "$sum"
    found=1
  done <<<"${L_HTTP[$i]}"
done
if [ "$PROBE" != 1 ]; then
  echo "(probe disabled with PROBE=0)"
elif [ "$found" = 0 ]; then
  echo "(no port answered HTTP or HTTPS)"
fi

hdr "A3. Web daemons: running processes and installed versions"
for pid in ${PIDS[@]+"${PIDS[@]}"}; do
  [[ ${P_COMM[$pid]} =~ $WEBD_RE ]] && printf '%s\t%s\n' "${P_COMM[$pid]}" "${P_USER[$pid]}"
done | sort | uniq -c | awk '{ printf "running: %-16s user %-12s x%d\n", $2, $3, $1 }'
for c in nginx apache2 httpd lighttpd openresty php php-fpm; do
  command -v "$c" >/dev/null 2>&1 || continue
  printf 'installed: %-10s %s\n' "$c" "$(to 5 "$c" -v 2>&1 </dev/null | head -n 1)"
done
if command -v caddy >/dev/null 2>&1; then
  printf 'installed: %-10s %s\n' caddy "$(to 5 caddy version 2>&1 </dev/null | head -n 1)"
fi
printf 'web-server accounts used by the checks below: %s\n' \
  "$( [ "${#WEBU[@]}" -gt 0 ] && printf '%s\n' "${!WEBU[@]}" | sort | tr '\n' ' ' || echo '(none found)')"

hdr "A4. Web roots to scan"
if [ "${#ROOTS[@]}" -eq 0 ]; then
  echo "No web roots found. Pass them as arguments: $0 /path/to/webroot"
else
  for r in "${ROOTS[@]}"; do printf '%s   (%s)\n' "$r" "${ROOT_SRC[$r]}"; done
fi

# ============================================================================
# B. FILES
# ============================================================================
SELF_EXCL=()
SELF=$(readlink -f -- "$0" 2>/dev/null) || SELF=
[ -n "$SELF" ] && [ -f "$SELF" ] && SELF_EXCL=( ! -samefile "$SELF" )

# rfind MODE find-tests...
#   Runs find inside every web root with paths relative to the root, so the
#   directory-name tests never match on the root's own path.
#   MODE list = one human-readable line per file (a newline inside a file
#   name is shown as "?") ; MODE nul = NUL-separated paths
rfind() {
  local mode=$1 r e
  shift
  for r in "${ROOTS[@]}"; do
    e=${r//\\/\\\\}; e=${e//%/%%}
    if [ "$mode" = nul ]; then
      ( cd "$r" 2>/dev/null && find . -regextype posix-extended -type f \
          ${SELF_EXCL[@]+"${SELF_EXCL[@]}"} \( "$@" \) -printf "$e/%P\\0" 2>/dev/null )
    else
      ( cd "$r" 2>/dev/null && find . -regextype posix-extended -type f \
          ${SELF_EXCL[@]+"${SELF_EXCL[@]}"} \( "$@" \) \
          -printf "%TY-%Tm-%Td %TH:%TM  %CY-%Cm-%Cd %CH:%CM  %u:%g  %m  %s  $e/%P\\0" 2>/dev/null ) \
        | tr '\n' '?' | tr '\0' '\n'
    fi
  done
}
clean() { tr '\000-\011\013-\037\177' '?'; }

# Signatures (extended regex, case-insensitive, one per line, no blank lines).
# Spans use unbounded [^;]* ("same statement") on purpose: bounded {0,N} repeats
# make grep's combined automaton explode and the scan ~50x slower.
cat > "$PATS" <<'EOF'
(^|[^a-z0-9_])(eval|assert)[[:space:]]*\([[:space:]@]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|urldecode|hex2bin|convert_uudecode|pack)[[:space:]]*\(
(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)[[:space:]]*\(
(^|[^a-z0-9_>:$.])(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([^;]*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER[[:space:]]*\[[[:space:]]*['"]HTTP_)
(^|[^a-z0-9_])(include|require)(_once)?[[:space:]]*[[:space:](][^;]*\$_(GET|POST|REQUEST|COOKIE)
\$_(GET|POST|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\(
\$[a-z_][a-z0-9_]*[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)[[:space:]]*\[
\$\{[[:space:]]*['"]_(GET|POST|REQUEST|COOKIE)['"][[:space:]]*\}
preg_replace[[:space:]]*\([[:space:]]*['"][^'"]*[/#~@!%|][a-z]*e[a-z]*['"][[:space:]]*,
create_function[[:space:]]*\([^;]*\$_(GET|POST|REQUEST|COOKIE)
(eval|assert|include|require|file_put_contents|fwrite|fputs)[^;]*php://input
move_uploaded_file[[:space:]]*\([^;]*,[^;]*\$_(GET|POST|REQUEST|COOKIE)
(file_put_contents|fwrite|fputs)[[:space:]]*\([^;]*\$_(GET|POST|REQUEST|COOKIE)
=[[:space:]]*['"](assert|passthru|shell_exec|proc_open|create_function|base64_decode|gzinflate|str_rot13)['"][[:space:]]*;
(^|[^a-z0-9])(c99shell|c99madshell|r57shell|b374k|weevely|FilesMan|IndoXploit|p0wny|china[[:space:]_-]?chopper|antsword|behinder|phpspy|anonymousfox|priv8[[:space:]_-]?(shell|uploader)|wso[[:space:]_-]?shell|alfa[[:space:]_-]?(shell|team|tesla)|mini[[:space:]_-]?shell)
Runtime[[:space:]]*\.[[:space:]]*getRuntime[[:space:]]*\([[:space:]]*\)[[:space:]]*\.[[:space:]]*exec[[:space:]]*\(
(ProcessBuilder|defineClass|ScriptEngineManager|\.exec[[:space:]]*\()[^;]*request\.get(Parameter|Header|InputStream)
request\.get(Parameter|Header|InputStream)[^;]*(ProcessBuilder|defineClass|\.exec[[:space:]]*\()
class[[:space:]]+[a-z_][a-z0-9_]*[[:space:]]+extends[[:space:]]+ClassLoader
(^|[^a-z0-9_.])(eval|execute|executeglobal)[[:space:]]*\(?[[:space:]]*request[[:space:]]*[.(\[]
(WScript\.Shell|Shell\.Application|Process\.Start[[:space:]]*\()
/bin/(ba|da|z|k)?sh[[:space:]]+-i([[:space:]'"<>&|;)]|$)
/dev/tcp/[0-9a-z.:_-]+/[0-9]+
(^|[^a-z0-9_])(nc|ncat|netcat)(\.openbsd|\.traditional)?[[:space:]]+[^|;&]*-[a-z]*e[[:space:]]+/bin/
pty\.spawn[[:space:]]*\(
socket\.socket[[:space:]]*\(.*(os\.dup2|subprocess)
fsockopen[[:space:]]*\(.*(proc_open|shell_exec|/bin/(ba)?sh)
(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output|getoutput))[[:space:]]*\([^)]*(getvalue|getfirst|request\.(args|form|values|GET|POST|data|json)|QUERY_STRING|FieldStorage)
(^|[^a-z0-9_.>$])(system|exec)[[:space:]]*\(?[^;]*(\$(cgi|q|query)->param[[:space:]]*\(|\$ENV\{['"]?(QUERY_STRING|HTTP_))
<!--#exec[[:space:]]+cmd=
EOF

HANDLER_RE="^[^#;]*(AddType|AddHandler|SetHandler|ForceType|ExecCGI|x-httpd-php|allow_url_include[[:space:]=]+(on|1|true)|auto_(prepend|append)_file[[:space:]\"'=]+[^[:space:]\"'=])"

sig_scan() {
  rfind nul -size "-$((MAX_MB * 1024 + 1))k" \
    | xargs -0 -r grep -HnEia -m 3 -f "$PATS" -- 2>/dev/null | cut -c1-300 | clean
}
obfuscation() {
  rfind nul -iregex ".*\.($EXT)" \
    | xargs -0 -r awk 'FNR == 1 { s = 0 }
        !s && length($0) > 2000 { printf "%s: line %d is %d chars long\n", FILENAME, FNR, length($0); s = 1 }' 2>/dev/null
  rfind nul -iregex ".*\.($EXT)" \
    | xargs -0 -r grep -lE '[A-Za-z0-9+/]{500}' -- 2>/dev/null \
    | sed 's/$/: contains a base64-like blob of 500+ chars/'
  rfind nul -iregex ".*\.($EXT)" \
    | xargs -0 -r grep -liE '(\\x[0-9a-f]{2}){16}|(chr[[:space:]]*\([[:space:]]*[0-9]{1,3}[[:space:]]*\)[[:space:]]*\.[[:space:]]*){5}' -- 2>/dev/null \
    | sed 's/$/: long run of \\x hex escapes or chr() concatenation/'
}
disguised() {
  rfind list -iregex ".*\.(jpe?g|png|gif|ico|bmp|webp|svg|txt|pdf|docx?|xlsx?|zip|mp[34])\.($EXT)" \
             -o -iregex '.*\.(php[0-9]?|phtml|pht|phar|jspx?|aspx?)\.(jpe?g|png|gif|ico|bmp|webp|svg|txt|pdf)'
  rfind nul -iregex ".*\.($EXT)" \
    | xargs -0 -r grep -laE '^(GIF8[79]a|.PNG$|.JFIF)' -- 2>/dev/null \
    | sed 's/$/: script file starts with an image header/'
}
code_in_media() {
  rfind nul -iregex '.*\.(jpe?g|png|gif|ico|bmp|webp|svg|txt|pdf|css|log|dat)' \
    | xargs -0 -r grep -laiF -e '<?php' -- 2>/dev/null
}
handlers() {
  rfind nul -name .htaccess -o -name .user.ini -o -name php.ini -o -name web.config \
    | xargs -0 -r grep -HniE "$HANDLER_RE" -- 2>/dev/null | cut -c1-300 | clean
  local d dirs=()
  for d in /etc/php* /usr/local/etc/php* /usr/local/lib/php.ini /opt/lampp/etc/php.ini; do
    [ -e "$d" ] && dirs+=("$d")
  done
  [ "${#dirs[@]}" -gt 0 ] && grep -RHniE --include='*.ini' "$HANDLER_RE" "${dirs[@]}" 2>/dev/null | cut -c1-300 | clean
}
tmp_files() {
  local u dirs=() up=()
  for u in "${!WEBU[@]}"; do
    [ "${#up[@]}" -gt 0 ] && up+=( -o )
    up+=( -user "$u" )
  done
  for u in /tmp /var/tmp /dev/shm; do [ -d "$u" ] && dirs+=("$u"); done
  [ "${#up[@]}" -gt 0 ] && [ "${#dirs[@]}" -gt 0 ] || return 0
  find "${dirs[@]}" -regextype posix-extended -type f \( "${up[@]}" \) \
       \( -perm /111 -o -iregex ".*\.($EXT|so|elf|bin)" \) \
       -printf '%TY-%Tm-%Td %TH:%TM  %CY-%Cm-%Cd %CH:%CM  %u:%g  %m  %s  %p\0' 2>/dev/null \
    | tr '\n' '?' | tr '\0' '\n' | sort -r
}

if [ "${#ROOTS[@]}" -gt 0 ]; then
  echo
  echo "File listings below use the columns: mtime  ctime  owner:group  mode  bytes  path"

  check "B1. Webshell / dropper / reverse-shell code signatures (all files up to ${MAX_MB} MB; max 3 lines per file, cut at 300 chars)" \
    < <(sig_scan)
  check "B2. Obfuscation in script files (very long lines, encoded blobs, hex/chr() strings)" \
    < <(obfuscation | sort)
  check "B3. Script files inside upload/media/cache-style directories" \
    < <(rfind list -iregex ".*/(uploads?|files|images?|img|media|cache|te?mp|assets|static|avatars?|attachments?|userfiles|gallery|photos|pictures|docs?|documents|downloads?|backups?|logs?)/.*\.($EXT)" | sort -r)
  check "B4. Disguised script files (double extensions, image headers)" \
    < <(disguised)
  check "B5. PHP code inside image/text/data files" \
    < <(code_in_media)
  check "B6. Hidden script files (dot-files, or inside dot-directories)" \
    < <(rfind list -iregex "(.*/)?\.[^/]+/.*\.($EXT)" -o -iregex ".*/\.([^/]*\.)?($EXT)" | sort -r)
  check "B7. Handler / auto-prepend overrides (.htaccess, .user.ini, php.ini, web.config, system PHP ini)" \
    < <(handlers)
  check "B8. Script files, .htaccess and .war changed in the last ${RECENT_DAYS} day(s) (mtime or ctime)" \
    < <(rfind list \( -iregex ".*\.($EXT|war)" -o -name .htaccess -o -name .user.ini \) \
              \( -mtime "-$RECENT_DAYS" -o -ctime "-$RECENT_DAYS" \) | sort -r)
  check "B9. World-writable script files" \
    < <(rfind list -iregex ".*\.($EXT)" -perm -o+w | sort -r)
  check "B10. Script files over ${MAX_MB} MB (NOT content-scanned; unusual in themselves)" \
    < <(rfind list -iregex ".*\.($EXT)" -size "+$((MAX_MB * 1024))k")
  check "B11. File names containing control characters (e.g. a newline)" \
    < <(rfind list -regex '.*[[:cntrl:]].*')
else
  echo
  echo "File checks B1-B11 skipped: no web roots to scan."
fi
check "B12. Executables/scripts owned by web users in /tmp, /var/tmp, /dev/shm" \
  < <(tmp_files)

# ============================================================================
# C. PROCESSES, CONNECTIONS, PERSISTENCE
# ============================================================================
proc_anomalies() {
  local pid u comm cmd exe cwd why par
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    [ "$pid" = "$$" ] && continue
    u=${P_USER[$pid]}
    [ -n "${WEBU[$u]:-}" ] || continue
    comm=${P_COMM[$pid]}; cmd=${P_CMD[$pid]}; exe=${P_EXE[$pid]}; cwd=${P_CWD[$pid]}
    why=
    [[ $comm =~ $SHELL_RE ]] && why+="shell/network tool; "
    if [[ $comm =~ $INTERP_RE ]] && [[ " $cmd" =~ $INLINE_RE ]]; then why+="inline interpreter code (-c/-e/-r); "; fi
    case "$comm" in curl|wget|ftp|tftp|scp) why+="download tool; " ;; esac
    case "$exe" in *' (deleted)') why+="binary deleted from disk; " ;; esac
    in_tmp "$exe" && why+="binary in temp dir; "
    in_tmp "${cwd% (deleted)}" && why+="working dir in temp dir; "
    [ -n "$why" ] || continue
    par=${P_COMM[${P_PPID[$pid]}]:-?}
    printf 'user=%s pid=%s parent=%s(%s) [%s]  %s\n' "$u" "$pid" "$par" "${P_PPID[$pid]}" "${why%; }" "${cmd:0:200}"
  done
}
shell_conns() {
  local i pid
  local -a parr
  for i in "${!E_LOCAL[@]}"; do
    IFS=, read -r -a parr <<<"${E_PIDS[$i]}"
    for pid in ${parr[@]+"${parr[@]}"}; do
      if [[ ${P_COMM[$pid]:-} =~ $SHELL_RE ]]; then
        printf '%s -> %s  %s pid=%s user=%s  %s\n' "${E_LOCAL[$i]}" "${E_REMOTE[$i]}" \
          "${P_COMM[$pid]}" "$pid" "${P_USER[$pid]:-?}" "${P_CMD[$pid]:0:160}"
      fi
    done
  done
}
web_cron() {
  local u f
  for u in "${!WEBU[@]}"; do
    for f in "/var/spool/cron/crontabs/$u" "/var/spool/cron/$u"; do
      [ -r "$f" ] && grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | sed "s|^|$f: |" | cut -c1-300 | clean
    done
  done
}

check "C1. Suspicious processes running as a web user" < <(proc_anomalies)
check "C2. Established TCP connections held by a shell/netcat-style process (reverse-shell check)" < <(shell_conns)
check "C3. Cron jobs belonging to web users" < <(web_cron)

# ============================================================================
hdr "Summary"
if [ "${#SUMMARY[@]}" -eq 0 ]; then
  echo "Nothing flagged."
else
  echo "  hits  check"
  printf '%s\n' "${SUMMARY[@]}"
fi
echo "Hits are leads, not verdicts: compare each file with a known-good copy"
echo "(version control, package checksums, backups) before removing anything."
exit 0

#!/bin/sh
# Start the nginx built in this image with the coraza module and the OWASP CRS loaded,
# listening on port 80 (the configuration CI's go-ftw run uses, tests/ftw/nginx-test.conf).
#
#   .oss-scanner/serve.sh          the regular build (/usr/sbin/nginx)
#   .oss-scanner/serve.sh asan     the ASan/UBSan build (/src/nginx-asan-<ver>/objs/nginx)
#   .oss-scanner/serve.sh stop     stop whichever is running
#
# Then, for example:
#   curl -si 'http://127.0.0.1/?x=<script>alert(1)</script>'     # CRS blocks: 403
#   go-ftw run --cloud --config /src/tests/ftw-crs.yml -d /opt/coraza/coreruleset/tests/regression/tests/ --exclude '^920'
#   printf 'testoverride:\n  input:\n    dest_addr: "127.0.0.1"\n    port: 80\n' > /tmp/.ftw.yaml
#   go-ftw run --cloud --config /tmp/.ftw.yaml -d /src/tests/ftw/
set -eu
. /src/.github/versions.env
CONF=/etc/nginx/nginx.conf
PID=/tmp/nginx.pid   # set by tests/ftw/nginx-test.conf

# nginx writes the pid file from the master, after the process we started has returned.
wait_pid() {
    i=0
    while [ ! -s "$PID" ]; do
        i=$((i + 1))
        [ "$i" -le 50 ] || { echo "nginx did not write $PID" >&2; exit 1; }
        sleep 0.1
    done
}

case "${1:-}" in
  stop)
    [ -f "$PID" ] && kill "$(cat "$PID")" && echo "stopped"
    exit 0 ;;
esac

# The configuration's docroot; /tmp may be a fresh tmpfs.
mkdir -p /tmp/empty
[ -f /tmp/empty/index.html ] || echo OK > /tmp/empty/index.html
# A pid file left by a killed run would be read as ours.
if [ -f "$PID" ] && ! kill -0 "$(cat "$PID")" 2>/dev/null; then rm -f "$PID"; fi

case "${1:-}" in
  asan)
    ASAN_DIR="/src/nginx-asan-${NGINX_VERSION}"
    ASAN_SO="${ASAN_DIR}/objs/ngx_http_coraza_module.so"
    sed "s#/usr/lib/nginx/modules/ngx_http_coraza_module.so#${ASAN_SO}#" "$CONF" > /tmp/nginx-asan.conf
    grep -q "$ASAN_SO" /tmp/nginx-asan.conf \
        || { echo "load_module line not found in $CONF" >&2; exit 1; }
    # This tree has the default prefix (/usr/local/nginx), absent here: give it one for its
    # temp paths. LeakSanitizer is off: it only reports the start-up pool of the parent
    # process that exits when nginx daemonises.
    mkdir -p /tmp/nginx-asan/logs
    export ASAN_OPTIONS="${ASAN_OPTIONS:-verify_asan_link_order=0:detect_odr_violation=0}:detect_leaks=0"
    "${ASAN_DIR}/objs/nginx" -p /tmp/nginx-asan/ -c /tmp/nginx-asan.conf -e /dev/stderr
    wait_pid
    echo "ASan nginx started on port 80 (pid $(cat "$PID")); sanitizer reports go to stderr" ;;
  *)
    /usr/sbin/nginx -c "$CONF"
    wait_pid
    echo "nginx started on port 80 (pid $(cat "$PID"))" ;;
esac

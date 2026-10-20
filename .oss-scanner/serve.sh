#!/bin/sh
# Start the nginx built in this image with the coraza module and the OWASP CRS loaded,
# listening on 127.0.0.1:80 (the configuration CI's go-ftw run uses, tests/ftw/nginx-test.conf).
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
case "${1:-}" in
  stop)
    [ -f /tmp/nginx.pid ] && kill "$(cat /tmp/nginx.pid)" && echo "stopped"
    exit 0 ;;
  asan)
    ASAN_DIR="/src/nginx-asan-${NGINX_MAINLINE}"
    sed "s#/usr/lib/nginx/modules/ngx_http_coraza_module.so#${ASAN_DIR}/objs/ngx_http_coraza_module.so#" \
        "$CONF" > /tmp/nginx-asan.conf
    # This tree has the default prefix (/usr/local/nginx), absent here: give it one for its
    # temp paths. LeakSanitizer is off: it only reports the start-up pool of the parent
    # process that exits when nginx daemonises.
    mkdir -p /tmp/nginx-asan/logs
    export ASAN_OPTIONS="${ASAN_OPTIONS:-verify_asan_link_order=0:detect_odr_violation=0}:detect_leaks=0"
    "${ASAN_DIR}/objs/nginx" -p /tmp/nginx-asan/ -c /tmp/nginx-asan.conf -e /dev/stderr
    echo "ASan nginx started on 127.0.0.1:80 (pid $(cat /tmp/nginx.pid)); sanitizer reports go to stderr" ;;
  *)
    /usr/sbin/nginx -c "$CONF"
    echo "nginx started on 127.0.0.1:80 (pid $(cat /tmp/nginx.pid))" ;;
esac

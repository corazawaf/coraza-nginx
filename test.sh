cd /Users/jptosso/nginx-1.22.0
make clean
./configure \
    --with-compat \
    --add-module=/Users/jptosso/go/src/github.com/corazawaf/coraza-nginx \
    --prefix=/tmp/nginx \
    --conf-path=/tmp/nginx/nginx.conf \
    --http-log-path=/tmp/nginx/log/nginx/access.log \
    --error-log-path=/tmp/nginx/log/nginx/error.log \
    --lock-path=/tmp/nginx/nginx.lock \
    --pid-path=/tmp/nginx/nginx.pid \
    --modules-path=/tmp/nginx/modules \
    --http-client-body-temp-path=/tmp/nginx/tmp \
    --http-proxy-temp-path=/tmp/nginx/tmp/proxy \
    --http-scgi-temp-path=/tmp/nginx/tmp/scgi \
    --http-uwsgi-temp-path=/tmp/nginx/tmp/uwsgi \
    --with-debug \
    --with-http_stub_status_module \
    --with-http_auth_request_module \
    --with-http_v2_module \
    --with-http_slice_module \
    --with-threads \
    --with-http_addition_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_sub_module \
    --with-stream=dynamic
make
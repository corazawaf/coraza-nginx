FROM ubuntu:latest

RUN apt-get update \
    && apt install -y wget build-essential libpcre++-dev git-core libtool openssl libssl-dev zlib1g-dev\
    && wget http://nginx.org/download/nginx-1.22.0.tar.gz \
    && tar -xvzf nginx-1.22.0.tar.gz
WORKDIR /nginx-1.22.0

RUN wget https://go.dev/dl/go1.19.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz

ENV PATH="$PATH:/usr/local/go/bin"
ENV CPPFLAGS="-DPNG_ARM_NEON_OPT=0"
COPY . coraza

RUN git clone https://github.com/corazawaf/libcoraza && \
    cd libcoraza && \
    ./build.sh && \
    ./configure && \
    make && \
    make install

RUN  ./configure \
    --with-compat \
    --add-module=/nginx-1.22.0/coraza/ \
    --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' \
    --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC' \
    --prefix=/usr/share/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --http-log-path=/var/log/nginx/access.log \
    --error-log-path=/var/log/nginx/error.log \
    --lock-path=/var/lock/nginx.lock \
    --pid-path=/run/nginx.pid \
    --modules-path=/usr/lib/nginx/modules \
    --http-client-body-temp-path=/var/lib/nginx/body \
    --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
    --http-proxy-temp-path=/var/lib/nginx/proxy \
    --http-scgi-temp-path=/var/lib/nginx/scgi \
    --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
    --with-debug \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    #--with-http_realip_module \
    --with-http_auth_request_module \
    --with-http_v2_module \
    #--with-http_dav_module \
    --with-http_slice_module \
    --with-threads \
    --with-http_addition_module \
    #--with-http_geoip_module=dynamic \
    --with-http_gunzip_module \
    #--with-http_gzip_static_module \
    #--with-http_image_filter_module=dynamic \
    --with-http_sub_module \
    #--with-http_xslt_module=dynamic \
    --with-stream=dynamic
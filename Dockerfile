FROM --platform=$BUILDPLATFORM golang@sha256:c7e98cc0fd4dfb71ee7465fee6c9a5f079163307e4bf141b336bb9dae00159a5 as go-builder

# For latest build deps, see https://github.com/nginxinc/docker-nginx/blob/master/mainline/alpine/Dockerfile
RUN set -eux; \
  apt-get update -qq; \
  apt-get install -qq --no-install-recommends \
    autoconf \
    automake \
    libtool \
    gcc \
    bash \
    make

ARG LIBCORAZA_VERSION=v1.1.0

RUN set -eux; \
    wget https://github.com/corazawaf/libcoraza/tarball/${LIBCORAZA_VERSION} -O /tmp/libcoraza.tar.gz; \
    tar -xvf /tmp/libcoraza.tar.gz; \
    cd *-libcoraza-*; \
    ./build.sh; \
    ./configure; \
    make; \
    cp libcoraza.a /usr/local/lib/; \
    cp libcoraza.so /usr/local/lib/; \
    mkdir -p /usr/local/include/coraza; \
    cp coraza/coraza.h /usr/local/include/coraza/

FROM nginx:stable@sha256:810ad1346ec7fd3d0a246c178f2b82e73a43640c691774405adfd38a751ecce8 as ngx-coraza

COPY --from=go-builder /usr/local/include/coraza /usr/local/include/coraza
COPY --from=go-builder /usr/local/lib/libcoraza.a /usr/local/lib
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib

# For latest build deps, see https://github.com/nginxinc/docker-nginx/blob/master/mainline/alpine/Dockerfile
RUN set -eux; \
  apt-get update -qq; \
  apt-get install -qq --no-install-recommends \
  gcc \
  gnupg1 \
  ca-certificates  \
  libc-dev \
  make \
  openssl \
  curl \
  gnupg \
  wget \
  libpcre2-dev \
  zlib1g-dev

COPY . /usr/src/coraza-nginx

# Download sources
RUN set -eux; \
    curl "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o - | tar zxC /usr/src -f -;
    # Reuse same cli arguments as the nginx:alpine image used to build

RUN set -eux; \
    CONFARGS=$(nginx -V 2>&1 | sed -n -e 's/^.*arguments: //p');\
    cd /usr/src/nginx-$NGINX_VERSION; \
    ./configure --with-compat "$CONFARGS" --add-dynamic-module=/usr/src/coraza-nginx; \
    make modules; \
    mkdir -p /usr/lib/nginx/modules; \
    find objs/*.so -print; \
    cp objs/ngx_*.so /usr/lib/nginx/modules
    
FROM nginx:stable@sha256:810ad1346ec7fd3d0a246c178f2b82e73a43640c691774405adfd38a751ecce8

RUN sed -i -e "s|events {|load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\";\n\nevents {|" /etc/nginx/nginx.conf;

COPY ./coraza.conf /etc/nginx/conf.d/coraza.conf
COPY --from=ngx-coraza /usr/lib/nginx/modules/ /usr/lib/nginx/modules/
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib

RUN ldconfig -v

COPY ./t /tmp/t

RUN apt-get update -qq && \
    apt-get install -qq --no-install-recommends curl perl && \
    curl http://hg.nginx.org/nginx-tests/archive/tip.tar.gz -o tip.tar.gz && \
    tar xzf tip.tar.gz && \
    cd nginx-tests-* && \
    cp /tmp/t/* . && \
    export TEST_NGINX_BINARY=/usr/sbin/nginx && \
    export TEST_NGINX_GLOBALS="load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\"; user root;" && \
    prove -v coraza*.t 2>&1 || true


FROM --platform=$BUILDPLATFORM golang as go-builder

ARG libcoraza_version=master

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

RUN set -eux; \
    wget https://github.com/corazawaf/libcoraza/tarball/master -O /tmp/master; \
    tar -xvf /tmp/master; \
    cd corazawaf-libcoraza-*; \
    ./build.sh; \
    ./configure; \
    make; \
    make V=1 install

FROM nginx:stable as ngx-coraza

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
  libpcre3 libpcre3-dev \
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
    
FROM nginx:stable

RUN sed -i -e "s|events {|load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\";\n\nevents {|" /etc/nginx/nginx.conf;

COPY ./coraza.conf /etc/nginx/conf.d/coraza.conf
COPY --from=ngx-coraza /usr/lib/nginx/modules/ /usr/lib/nginx/modules/
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib

RUN ldconfig -v

COPY ./t /tmp/t

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -qq --no-install-recommends curl perl; \
    curl http://hg.nginx.org/nginx-tests/archive/tip.tar.gz -o tip.tar.gz; \
    tar xzf tip.tar.gz; \
    cd nginx-tests-*; \
    cp /tmp/t/* . ;\
    export TEST_NGINX_BINARY=/usr/sbin/nginx; \
    export TEST_NGINX_GLOBALS="load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\";"; \
    prove . -t coraza*.t


# Build environment for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this image with the repository checkout as the build context, then
# analyses it with no network access, so everything the build and the tests need is
# fetched here. Versions and sha256 pins come from .github/versions.env, the same single
# source of truth the CI workflows use; every archive is verified after download.
#
# Layout of the finished image (everything under /src, the checkout):
#   /src                         this repository (the connector: src/, t/, lint/, fuzz/, tools/)
#   /src/nginx-<ver>             nginx mainline (symlinked as /src/nginx), configured and built with the module
#                                (objs/nginx, objs/ngx_http_coraza_module.so); also installed as
#                                /usr/sbin/nginx + /usr/lib/nginx/modules/ngx_http_coraza_module.so
#   /src/nginx-asan-<ver>        nginx NGINX_VERSION built under ASan/UBSan as asan.yml does
#                                (objs/nginx, objs/ngx_http_coraza_module.so) -- use it to confirm
#                                memory-safety findings (the image's ASAN_OPTIONS is what CI uses)
#   /src/libcoraza-build         libcoraza (the cgo bridge to the Go engine), installed as
#                                /usr/local/lib/libcoraza.so + /usr/local/include/coraza/coraza.h;
#                                the module dlopen()s it at startup
#   /src/nginx-tests             nginx's Test::Nginx harness with t/*.t copied in:
#                                  cd /src/nginx-tests && prove --timer coraza*.t
#                                (env TEST_NGINX_BINARY/TEST_NGINX_GLOBALS/TEST_NGINX_SOURCE are set)
#   /src/lint                    static source contracts:  prove /src/lint/*.t
#   /src/fuzz                    libFuzzer targets fuzz_str_to_char and fuzz_pack_headers
#                                (built with clang/ASan):  bash fuzz/run.sh 60   or
#                                  FUZZ_BIN=./fuzz_pack_headers CORPUS_DIR=./corpus_pack_headers bash fuzz/run.sh 60
#   /src/tools/soak.sh           mixed benign/attack soak of a live nginx:
#                                  bash tools/soak.sh /src/nginx-asan-<ver>/objs/nginx 60 4
#   /opt/coraza                  OWASP CRS (pinned) + the config the CI go-ftw run uses;
#                                /etc/nginx/nginx.conf is tests/ftw/nginx-test.conf (CRS on port 80)
#   /src/.oss-scanner/serve.sh   starts that server ("serve.sh asan" starts the ASan build instead)
#                                for live probing; go-ftw (/usr/local/bin/go-ftw) replays
#                                tests/ftw/*.yaml and the CRS regression suite against it.
#
# Keep the Go image in step with the libcoraza go.mod (1.26) and CI's setup-go. trixie, not
# bookworm: gcc 12's and clang 14's ASan runtimes spin forever at start-up on kernels with
# 32-bit mmap randomisation (vm.mmap_rnd_bits=32), which hangs the ASan configure below.
FROM golang:1.26-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    GOTOOLCHAIN=local

# gcc builds nginx and the module (as CI does, incl. the ASan/UBSan tree); clang + compiler-rt
# build the libFuzzer targets; autotools build libcoraza; Perl + IO::Socket::SSL + CryptX run
# nginx-tests (CryptX is what Test::Nginx's HTTP/3 helper needs); gdb and valgrind for triage.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip xz-utils \
      build-essential gcc g++ clang libclang-rt-dev make pkg-config \
      autoconf automake libtool \
      libpcre2-dev zlib1g-dev libssl-dev openssl \
      perl libio-socket-ssl-perl libcryptx-perl \
      gdb valgrind procps netcat-openbsd mold \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# libcoraza at the pinned release: fetched and sha256-verified by the CI script, built with
# the Go toolchain of this image, installed under /usr/local (the module dlopen()s
# libcoraza.so and refuses anything older than the 1.8 floor).
RUN set -eu; . /src/.github/versions.env; \
    export GITHUB_WORKSPACE=/src; \
    bash .github/scripts/fetch-verify.sh \
      "https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.zip" \
      "$LIBCORAZA_SHA256" libcoraza.zip; \
    unzip -oq libcoraza.zip && rm libcoraza.zip; \
    mv libcoraza-*/ libcoraza-build; \
    cd libcoraza-build && ./build.sh && ./configure && make -j"$(nproc)" && make install && ldconfig; \
    test -f /usr/local/include/coraza/coraza.h

# nginx mainline (the version CI's full cell uses), configured as CI does: debug info and frame
# pointers, the module as a dynamic module, HTTP/2 + HTTP/3 (QUIC through OpenSSL's
# native QUIC API in trixie's OpenSSL 3.5), DAV/auth_request/sub/realip for the test fixtures.
# Installed to the CI paths so tests/ftw/nginx-test.conf and the prove env work unchanged.
RUN set -eu; . /src/.github/versions.env; \
    bash .github/scripts/fetch-verify.sh \
      "https://nginx.org/download/nginx-${NGINX_MAINLINE}.tar.gz" \
      "$NGINX_MAINLINE_SHA256" nginx-src.tar.gz; \
    tar -xzf nginx-src.tar.gz && rm nginx-src.tar.gz; \
    cd "nginx-${NGINX_MAINLINE}"; \
    ./configure \
      --with-compat \
      --add-dynamic-module=/src \
      --with-cc-opt="-g -O2 -fno-omit-frame-pointer -fstack-protector-strong -Wformat -Werror=format-security -Wno-unused-function -fPIC -D_FORTIFY_SOURCE=2" \
      --with-ld-opt="-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC" \
      --prefix=/etc/nginx \
      --sbin-path=/usr/sbin/nginx \
      --conf-path=/etc/nginx/nginx.conf \
      --http-log-path=/var/log/nginx/access.log \
      --error-log-path=/var/log/nginx/error.log \
      --lock-path=/var/lock/nginx.lock \
      --pid-path=/run/nginx.pid \
      --modules-path=/usr/lib/nginx/modules \
      --http-client-body-temp-path=/var/cache/nginx/client_temp \
      --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
      --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
      --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
      --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
      --with-debug --with-threads \
      --with-http_ssl_module --with-http_realip_module --with-http_auth_request_module \
      --with-http_v2_module --with-http_v3_module --with-http_sub_module --with-http_dav_module; \
    make -j"$(nproc)" && make install; \
    mkdir -p /var/cache/nginx/client_temp /var/log/nginx; \
    /usr/sbin/nginx -V

# nginx under ASan/UBSan, at the version and with the flags of CI's sanitizer and soak jobs
# (asan.yml, NGINX_VERSION): ASan errors are fatal, UBSan recovers; nonnull-attribute/null
# are excluded because nginx core trips them at init.
# Not installed: run /src/nginx-asan-<ver>/objs/nginx with its own module path.
RUN set -eu; . /src/.github/versions.env; \
    printf 'int main(void){return 0;}\n' > /tmp/asan-probe.c; \
    gcc -fsanitize=address,undefined /tmp/asan-probe.c -o /tmp/asan-probe; \
    timeout 30 /tmp/asan-probe || { echo "ASan runtime does not start on this kernel" >&2; exit 1; }; \
    rm -f /tmp/asan-probe /tmp/asan-probe.c; \
    bash .github/scripts/fetch-verify.sh \
      "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
      "$NGINX_VERSION_SHA256" nginx-asan.tar.gz; \
    mkdir "nginx-asan-${NGINX_VERSION}"; \
    tar -xzf nginx-asan.tar.gz -C "nginx-asan-${NGINX_VERSION}" --strip-components=1; \
    rm nginx-asan.tar.gz; \
    cd "nginx-asan-${NGINX_VERSION}"; \
    SAN_LD="-fsanitize=address,undefined"; \
    SAN_CC="$SAN_LD -fno-sanitize=nonnull-attribute,null -fno-sanitize-recover=address"; \
    ./configure \
      --with-compat --with-debug --with-threads \
      --with-http_ssl_module --with-http_v2_module --with-http_v3_module \
      --with-http_realip_module --with-http_auth_request_module \
      --with-http_sub_module --with-http_dav_module \
      --add-dynamic-module=/src \
      --with-cc-opt="-DNGX_DEBUG_PALLOC=1 -g3 -O0 -fno-omit-frame-pointer -funwind-tables $SAN_CC $(pkg-config --cflags libpcre2-8)" \
      --with-ld-opt="-fuse-ld=mold $SAN_LD $(pkg-config --libs libpcre2-8)"; \
    make -j"$(nproc)"; \
    ASAN_OPTIONS=verify_asan_link_order=0 ./objs/nginx -V

# Both libFuzzer targets (clang + ASan/UBSan), next to their seed corpora in /src/fuzz.
RUN bash fuzz/build.sh && ls -l fuzz/fuzz_str_to_char fuzz/fuzz_pack_headers

# OWASP CRS at the pinned LTS release + the configuration CI's go-ftw run uses, and go-ftw
# itself, so the CRS regression suite and tests/ftw/*.yaml can be replayed offline against
# the live server (see serve.sh). nginx -t proves the module loads with the full CRS.
RUN set -eu; . /src/.github/versions.env; \
    mkdir -p /opt/coraza/owasp-crs /opt/coraza/config /opt/coraza/config.d /opt/coraza/plugins \
             /opt/coraza/rules /opt/coraza/rules.d /opt/coraza/overrides /tmp/empty; \
    bash .github/scripts/fetch-verify.sh \
      "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
      "$CRS_SHA256" /tmp/crs.tar.gz; \
    tar xzf /tmp/crs.tar.gz -C /opt/coraza && rm /tmp/crs.tar.gz; \
    mv "/opt/coraza/coreruleset-${CRS_VERSION}" /opt/coraza/coreruleset; \
    cp -r /opt/coraza/coreruleset/rules /opt/coraza/coreruleset/plugins /opt/coraza/owasp-crs/; \
    cp /opt/coraza/coreruleset/crs-setup.conf.example /opt/coraza/config/crs-setup.conf; \
    printf '%s\n' 'SecRuleEngine On' 'SecRequestBodyAccess On' 'SecResponseBodyAccess Off' 'SecAuditEngine Off' \
      > /opt/coraza/config/coraza.conf; \
    printf '%s\n' \
      'Include /opt/coraza/config/coraza.conf' \
      'Include /opt/coraza/config.d/*.conf' \
      'Include /opt/coraza/config/crs-setup.conf' \
      'Include /opt/coraza/owasp-crs/plugins/*-config.conf' \
      'Include /opt/coraza/owasp-crs/plugins/*-before.conf' \
      'Include /opt/coraza/owasp-crs/rules/*.conf' \
      'Include /opt/coraza/owasp-crs/plugins/*-after.conf' \
      'Include /opt/coraza/plugins/*-config.conf' \
      'Include /opt/coraza/plugins/*-before.conf' \
      'Include /opt/coraza/plugins/*-after.conf' \
      'Include /opt/coraza/rules/*.conf' \
      'Include /opt/coraza/rules.d/*.conf' \
      'Include /opt/coraza/overrides/*.conf' \
      > /opt/coraza/config/coraza-rules.conf; \
    cp tests/ftw/nginx-test.conf /etc/nginx/nginx.conf; \
    echo OK > /tmp/empty/index.html; \
    /usr/sbin/nginx -t; \
    go install "github.com/coreruleset/go-ftw/v2@${GO_FTW_VERSION}" \
    && cp "$(go env GOPATH)/bin/go-ftw" /usr/local/bin/go-ftw && go-ftw --help >/dev/null

# nginx-tests at the pinned commit, with the connector's t/*.t copied in (the CI layout: the
# harness sits next to src/, which some tests reach through ../src).
RUN set -eu; . /src/.github/versions.env; \
    bash .github/scripts/fetch-verify.sh \
      "https://github.com/nginx/nginx-tests/archive/${NGINX_TESTS_REF}.tar.gz" \
      "$NGINX_TESTS_SHA256" nginx-tests.tar.gz; \
    tar xzf nginx-tests.tar.gz && rm nginx-tests.tar.gz; \
    mv nginx-tests-*/ nginx-tests; \
    cp t/* nginx-tests/; \
    ln -sfn "nginx-${NGINX_MAINLINE}" /src/nginx

# Test environment for Test::Nginx, as CI sets it (TEST_NGINX_SOURCE pins the compile
# fixtures to the tree built above; /src/nginx follows NGINX_MAINLINE when bump.yml moves it).
# CI runs the suite unprivileged; here everything runs as root, and nginx would then start its
# workers as nobody, who cannot read the root-owned test directory: `user root;` keeps the
# workers on the same account as the harness.
ENV TEST_NGINX_BINARY=/usr/sbin/nginx \
    TEST_NGINX_GLOBALS='user root; load_module "/usr/lib/nginx/modules/ngx_http_coraza_module.so";' \
    TEST_NGINX_SOURCE=/src/nginx \
    ASAN_OPTIONS=verify_asan_link_order=0:detect_odr_violation=0

# The static source contracts are cheap and must pass on a clean checkout (a failure here is
# a CI failure anyway). The integration suite is not run here: oss-scanner-image.yml runs it
# inside the built image, offline.
RUN prove lint/*.t

# No Go toolchain work is needed at run time, but keep `go` usable offline for anyone who
# rebuilds libcoraza: serve the module cache as the proxy, as the engine's image does.
ENV GOPROXY=file:///go/pkg/mod/cache/download \
    GOSUMDB=off

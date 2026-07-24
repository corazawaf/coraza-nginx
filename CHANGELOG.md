# Changelog

## [0.11.5](https://github.com/corazawaf/coraza-nginx/compare/v0.11.4...v0.11.5) (2026-07-24)


### Bug Fixes

* align non-delayed body intervention teardown with finalize path ([1b0a60f](https://github.com/corazawaf/coraza-nginx/commit/1b0a60f5af3f91d2e1e8f070bb5dff4cf41c98b8))
* cap delayed response-body buffering to bound worker memory ([03691ca](https://github.com/corazawaf/coraza-nginx/commit/03691ca9d8e91ca0d41a37345c073160275c4e44))
* cap delayed response-body buffering to bound worker memory ([da34c4c](https://github.com/corazawaf/coraza-nginx/commit/da34c4c5b2d648df5e5b68c2208f89dbb712017d))
* clear entity headers on synthesized redirects ([c8ed380](https://github.com/corazawaf/coraza-nginx/commit/c8ed3805853077172ddb5fdec450371fe8d2d8f8))
* clear entity headers on synthesized redirects ([0c2163b](https://github.com/corazawaf/coraza-nginx/commit/0c2163b6f3268310b030c0c1bcea14031ab04d5d))
* dedup body chunk length calc via shared helper ([955fa99](https://github.com/corazawaf/coraza-nginx/commit/955fa99e0215c7f1861a09f6bec0a252e9f0c0d3))
* do not synthesize Connection/Keep-Alive for the WAF on HTTP/2 ([5dbcdb7](https://github.com/corazawaf/coraza-nginx/commit/5dbcdb7a05b05a39705e7ad5b69218515f4f1c21))
* do not synthesize Connection/Keep-Alive for the WAF on HTTP/2 ([74ac2aa](https://github.com/corazawaf/coraza-nginx/commit/74ac2aace3bc6e123df595906cb2202b3558ffe8))
* don't delay HEAD response headers ([062fd57](https://github.com/corazawaf/coraza-nginx/commit/062fd575f29372e64a609a84cafefd8af9c3bbc4))
* don't delay HEAD response headers ([f7f65a3](https://github.com/corazawaf/coraza-nginx/commit/f7f65a39e0eea25b5c19f693e957c8d24a2da933))
* don't delay response headers for SSE streams ([#81](https://github.com/corazawaf/coraza-nginx/issues/81)) ([dc49612](https://github.com/corazawaf/coraza-nginx/commit/dc496124bd69eaf7f55cbd88eb854d7a27aced21))
* don't delay response headers for SSE streams ([#81](https://github.com/corazawaf/coraza-nginx/issues/81)) ([099f587](https://github.com/corazawaf/coraza-nginx/commit/099f5879df3c107a42b0d6d4a134980e4174b603))
* drop unused Coraza dl symbols ([c1c0481](https://github.com/corazawaf/coraza-nginx/commit/c1c0481d32ae0a44058ad11bba676fcde12359fb))
* drop unused Coraza dl symbols ([07eae2d](https://github.com/corazawaf/coraza-nginx/commit/07eae2d2d2c60d8a7a60f5b047545ad491affabc))
* **fuzz:** empty input yields a valid pointer, not NULL ([8d4dda8](https://github.com/corazawaf/coraza-nginx/commit/8d4dda881b10ae150978f23f1adeb9a760fd2664))
* guard h2/h3 forbidden headers by http_version, not r-&gt;stream ([cc38a6b](https://github.com/corazawaf/coraza-nginx/commit/cc38a6b7965aa3d7300b6973317a1091af59445b))
* guard size_t to int narrowing at the Coraza cgo boundary ([ff47fd4](https://github.com/corazawaf/coraza-nginx/commit/ff47fd4ebc9f3b54889ff3d2b585b4eee8f26c8d))
* guard size_t to int narrowing at the Coraza cgo boundary ([34987d4](https://github.com/corazawaf/coraza-nginx/commit/34987d497edc1c663e7bc79b7743e395ab0c8e58))
* keep libcoraza loaded for worker lifetime ([056e7b3](https://github.com/corazawaf/coraza-nginx/commit/056e7b362df8789056b9cb4db5d8b5ce34277aa2))
* keep libcoraza loaded for worker lifetime ([f5bd4c7](https://github.com/corazawaf/coraza-nginx/commit/f5bd4c7fd1ad7ee6bc2a2e7c51183814b899278d))
* omit NUL from synthetic server header ([c27575d](https://github.com/corazawaf/coraza-nginx/commit/c27575d46b9883c81e4c27e5d8a1a90f907bf7ac))
* omit NUL from synthetic server header ([6edbace](https://github.com/corazawaf/coraza-nginx/commit/6edbace5a10d239ccbf255dcc2b77e263c43b2e8))
* propagate delayed header filter status ([acf18c0](https://github.com/corazawaf/coraza-nginx/commit/acf18c0992e6dbca3459d573e9192690d20ec9d4))
* propagate delayed header filter status ([5c4be30](https://github.com/corazawaf/coraza-nginx/commit/5c4be3072793271429e7798866c48a952d532bdb))
* propagate response header insert failures ([3a14a41](https://github.com/corazawaf/coraza-nginx/commit/3a14a4113eb4c049a661d9a23ffffedbef0cdd61))
* propagate response header insert failures ([11916db](https://github.com/corazawaf/coraza-nginx/commit/11916db458b51c038f6a5ff67c1b9cd6f015920b))
* reject oversized response-body chunks before read, set intervention flag ([d151590](https://github.com/corazawaf/coraza-nginx/commit/d151590a24facd625a8a9fbc46acff0e10c0fa2b))
* remove linker path from include flags ([f864842](https://github.com/corazawaf/coraza-nginx/commit/f86484267ac4cafcee1f22840c2e7e7435e5c1ff))
* remove linker path from include flags ([89a7a5f](https://github.com/corazawaf/coraza-nginx/commit/89a7a5f964a7a2dcba3a7a2fb83abd06f3935d49))
* remove stale sanity check build traps ([d29279f](https://github.com/corazawaf/coraza-nginx/commit/d29279f1d2fba60f98ea0d98d015f44b2cc5102b))
* remove stale sanity check build traps ([589785b](https://github.com/corazawaf/coraza-nginx/commit/589785b90a17b4beeff5a658f68d6bf7109be568))
* require libcoraza 1.4 ABI ([2492a2a](https://github.com/corazawaf/coraza-nginx/commit/2492a2afbd3c85e0f4e273475f6f1582a5f0d427))
* require libcoraza 1.4 ABI ([ff2181b](https://github.com/corazawaf/coraza-nginx/commit/ff2181ba342d0104eb49774cc718947ef5c55bf2))
* require valid file pointer before replaying file buffer ([9fc0a19](https://github.com/corazawaf/coraza-nginx/commit/9fc0a1949bbec7a4779471736750db782cb6e7f9))
* return empty C string for empty ngx_str ([f8a76b0](https://github.com/corazawaf/coraza-nginx/commit/f8a76b0bba69f92e18ac4b0f38fafd750df36c2c))
* return empty C string for empty ngx_str ([7abb251](https://github.com/corazawaf/coraza-nginx/commit/7abb251aaa3c3bc9438cea8760275bc1250c5273))
* use ngx_http_clear_accept_ranges to clear Accept-Ranges ([4ef52a9](https://github.com/corazawaf/coraza-nginx/commit/4ef52a9ffa2d274b35693917d2d4f0b9d0463898))


### Performance Improvements

* add coraza_delay_response_headers directive ([2afa451](https://github.com/corazawaf/coraza-nginx/commit/2afa451a38356020bf4e73129464efda3f8809e9))
* avoid copying uninspected file response buffers ([735d715](https://github.com/corazawaf/coraza-nginx/commit/735d715d41ffdee4545b86bb967a49e18744b8d2))
* avoid copying uninspected file response buffers ([7c2bb44](https://github.com/corazawaf/coraza-nginx/commit/7c2bb44a495baac02aa9456d670c1392033fb054))
* make response body header delay configurable ([a42e606](https://github.com/corazawaf/coraza-nginx/commit/a42e6063186610ca660cf0ce3410dfe6c54d54b7))

## [0.11.4](https://github.com/corazawaf/coraza-nginx/compare/v0.11.3...v0.11.4) (2026-06-28)


### Bug Fixes

* skip deleted (hash == 0) headers when collecting them for coraza ([bca1f6d](https://github.com/corazawaf/coraza-nginx/commit/bca1f6de77dddbf73349a52e31bb6c50913bf256))

## [0.11.3](https://github.com/corazawaf/coraza-nginx/compare/v0.11.2...v0.11.3) (2026-06-26)


### Bug Fixes

* don't delay 101 Switching Protocols, breaks websocket upgrades ([3c5ce85](https://github.com/corazawaf/coraza-nginx/commit/3c5ce85dce9823a61d4f50b9ce187e4fc7f18677))
* pass through 101 Switching Protocols (WebSocket upgrades) ([2c61d19](https://github.com/corazawaf/coraza-nginx/commit/2c61d19483d20cb054efeef5ad2ea0465fbb609f))

## [0.11.2](https://github.com/corazawaf/coraza-nginx/compare/v0.11.1...v0.11.2) (2026-06-15)


### Bug Fixes

* **header_filter:** pass Content-Length: 0 to the WAF for inspection ([50e6030](https://github.com/corazawaf/coraza-nginx/commit/50e6030133057c3c91e12e45fa29021dfcab2970))
* **header_filter:** pass Content-Length: 0 to the WAF for inspection ([bcda3f9](https://github.com/corazawaf/coraza-nginx/commit/bcda3f9d0bb64c598f74a04a3349919fc0b8e4eb))
* **module:** do not allocate an unused cleanup data buffer per request ([3fb3f53](https://github.com/corazawaf/coraza-nginx/commit/3fb3f5352ca441abaf247069314c19f7b60145c4))

## [0.11.1](https://github.com/corazawaf/coraza-nginx/compare/v0.11.0...v0.11.1) (2026-06-02)


### Bug Fixes

* forward empty/multi-buffer responses (return 301/404) ([16cdc41](https://github.com/corazawaf/coraza-nginx/commit/16cdc41555a8da948df55bec92903a67be038deb))
* forward empty/multi-buffer responses correctly ([6e424f1](https://github.com/corazawaf/coraza-nginx/commit/6e424f18e392881ad9af56249331cee93269a9a1))

## [0.11.0](https://github.com/corazawaf/coraza-nginx/compare/v0.10.1...v0.11.0) (2026-04-16)


### Features

* add Debian packaging ([fd75748](https://github.com/corazawaf/coraza-nginx/commit/fd7574861ff81a295224dfcedb697eeb3f7ad405))
* add Debian packaging ([e014c2c](https://github.com/corazawaf/coraza-nginx/commit/e014c2c8543b8bf7b338bca50db242c0e28fc449))
* add go-ftw e2e tests ([f343fcd](https://github.com/corazawaf/coraza-nginx/commit/f343fcd1c04358f00157e683f8e3d87b0a5e698c))
* add go-ftw e2e tests ([6381b71](https://github.com/corazawaf/coraza-nginx/commit/6381b7145d570cb2f5dc4700db6cb07007ab5456)), closes [#33](https://github.com/corazawaf/coraza-nginx/issues/33)
* handle unix domain sockets in connection info ([8b101be](https://github.com/corazawaf/coraza-nginx/commit/8b101be69cd9abf1b57cd3b158ae3d3d0bcacbfa))
* handle unix domain sockets in connection info ([a6b9175](https://github.com/corazawaf/coraza-nginx/commit/a6b9175893975fc1ac0950c6ea5e115390ad341d))


### Bug Fixes

* address review feedback on go-ftw CI step ([9a7525e](https://github.com/corazawaf/coraza-nginx/commit/9a7525e7aa2f4cdc722569e267082e86bdf7bfd7))
* always run phase 4 rules even when body inspection is disabled ([d3fe533](https://github.com/corazawaf/coraza-nginx/commit/d3fe533285f5b34861ca1f16a2c2d5daf9bae5fd))
* debug mode compilation errors (CORAZA_DDEBUG=1) ([20a0924](https://github.com/corazawaf/coraza-nginx/commit/20a0924142bfbeedb6aa249d7908c04ac1dcb9db))
* match pidfile path with nginx-test.conf (/tmp/nginx.pid) ([3643cfe](https://github.com/corazawaf/coraza-nginx/commit/3643cfea134e6696f762ed31525a71c0ebf7ad63))
* require coraza_is_response_body_processable (libcoraza &gt;= 1.4.0) ([d8c121f](https://github.com/corazawaf/coraza-nginx/commit/d8c121f4f2daf88a2ca3e54b8e335861a7d1bcd3))
* skip response body inspection when SecResponseBodyAccess is Off ([c118201](https://github.com/corazawaf/coraza-nginx/commit/c1182015e422f22ab0dbb4b49aa353e91e287ae3))
* stop routing response bodies through Go FFI when body inspection is disabled ([9d5c083](https://github.com/corazawaf/coraza-nginx/commit/9d5c08385b2e9b876ae71edd1d402cbf422f5047))
* use command injection payload for GET RCE test, add 405 fallback to all locations ([c2dab85](https://github.com/corazawaf/coraza-nginx/commit/c2dab8557ed95200bb74dc1c261841fb25bb061a))

## [0.10.1](https://github.com/corazawaf/coraza-nginx/compare/v0.10.0...v0.10.1) (2026-03-16)


### Bug Fixes

* upgrade Go version and modify test download method ([ce3a1f7](https://github.com/corazawaf/coraza-nginx/commit/ce3a1f718001e42911242c93e2210322949b645c))

## [0.10.0](https://github.com/corazawaf/coraza-nginx/compare/v0.9.0...v0.10.0) (2026-03-01)


### Features

* add redirect support and bump libcoraza to v1.1.0 ([1642c13](https://github.com/corazawaf/coraza-nginx/commit/1642c13796d1b7bcdb95a49ff41341d44c849ea3))
* add redirect support and bump libcoraza to v1.1.0 ([8779899](https://github.com/corazawaf/coraza-nginx/commit/8779899afadea413a2c72b7c6a68ebf4807cd23b))

## 0.9.0 (2026-02-28)


### Features

* **ci:** change names and add automated build ([5bd81f3](https://github.com/corazawaf/coraza-nginx/commit/5bd81f3c20da3d5640c6bd50865583721193cb04))
* **ci:** change names and add automated build ([d02394c](https://github.com/corazawaf/coraza-nginx/commit/d02394c556e985ba486b990807494827dfb7892d))
* coraza-nginx with working tests ([774b496](https://github.com/corazawaf/coraza-nginx/commit/774b496d0bdbf149c5c045dc915d1f1acdeb01c8))
* full coraza-nginx rework — config inheritance, dlopen wrapper, bug fixes ([c0f3b6c](https://github.com/corazawaf/coraza-nginx/commit/c0f3b6c5d5cfca913e19f2277da8746266e38aed))
* transaction ID tracking and access denied logging ([fcc5551](https://github.com/corazawaf/coraza-nginx/commit/fcc5551306f08b7b14f31cff9563bcf8e32eb992))


### Bug Fixes

* adapt tests for Coraza compatibility ([d24a47c](https://github.com/corazawaf/coraza-nginx/commit/d24a47caf52a575b40625a520abc405e614759e4))
* address review feedback ([eec1d9c](https://github.com/corazawaf/coraza-nginx/commit/eec1d9cc90ce9d5ba4db5660cfc0ebb4f9c1957b))
* check body limit intervention before processing rules ([95479e4](https://github.com/corazawaf/coraza-nginx/commit/95479e40980d999117303f43857eb2fdba2514f0))
* config inheritance for locations without rules ([0c4806c](https://github.com/corazawaf/coraza-nginx/commit/0c4806c433d5163def626350dca07e18358bcc62))
* config syntax ([7e5b812](https://github.com/corazawaf/coraza-nginx/commit/7e5b81249592db74fe1e14edb51346cc185d53d8))
* delay response headers until phase 4 body inspection completes ([6f60f15](https://github.com/corazawaf/coraza-nginx/commit/6f60f15d10df288d5a2b3c8e2046f553a346c2ce))
* delay response headers until phase 4 body inspection completes ([95b9c5b](https://github.com/corazawaf/coraza-nginx/commit/95b9c5ba1daac6aa0fa36eed003a9de5d6dbaae3))
* dlopen libcoraza after fork to avoid Go runtime deadlock ([e3cd8c6](https://github.com/corazawaf/coraza-nginx/commit/e3cd8c6a98197c0df28cde49db32aa515c48f9ab))
* Dockerfile prove runs only coraza tests ([2f53dc4](https://github.com/corazawaf/coraza-nginx/commit/2f53dc4feb818290a689f62545c27cccc87e144b))
* Dockerfile test runner ([b77a9da](https://github.com/corazawaf/coraza-nginx/commit/b77a9da1f9fb8bd7de9f1102a59d067c8964ab84))
* enable passing tests and fix audit log assertions ([a609d97](https://github.com/corazawaf/coraza-nginx/commit/a609d9726fd723dd4a634c17eda76cb0c4c85723))
* intervention memory leaks ([8ae8f72](https://github.com/corazawaf/coraza-nginx/commit/8ae8f72bde54ad9a217f724c29240da390aa176f))
* ngx_str_to_char pass pointer by reference ([093eec4](https://github.com/corazawaf/coraza-nginx/commit/093eec4d919a20732b39be706179f80456924638))
* second pass changing names and main module ([a746b53](https://github.com/corazawaf/coraza-nginx/commit/a746b538a52d0b5ac13f2b5605e8ae2e5e7b6b1a))
* second pass changing names and main module ([d381f1a](https://github.com/corazawaf/coraza-nginx/commit/d381f1a2b10840c52ca78b1e3dd4848f9d22a731))
* set intervention_triggered flag consistently ([e38a4a7](https://github.com/corazawaf/coraza-nginx/commit/e38a4a77efcb116b486b0ec492282d32736a2f44))
* tests ([4fd9b30](https://github.com/corazawaf/coraza-nginx/commit/4fd9b304130015ff5c38c367f94aa25fe43fa05e))
* update dockerfile ([b0c6a27](https://github.com/corazawaf/coraza-nginx/commit/b0c6a2731c3d18b96aa930467b01ad5324ed7f8e))
* update header comment ([4e8621e](https://github.com/corazawaf/coraza-nginx/commit/4e8621eaf0cf2529ad03ca6a82d2ffa542816247))
* use ppomes/libcoraza fork with working rules_merge ([86063cc](https://github.com/corazawaf/coraza-nginx/commit/86063ccd4c16113e62c4acd7ad0e75cd8761f6c9))


### Miscellaneous Chores

* release 0.9.0 ([bc82be7](https://github.com/corazawaf/coraza-nginx/commit/bc82be7454cdd8c30cfa6856d5dda2a5c3026c12))

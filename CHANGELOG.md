# Changelog

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

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.14'>v0.0.14</a>
### 2024-06-17

### Chores
+ dependencies updated, [95d94b92](https://github.com/mrjackwills/staticpi_backend/commit/95d94b9299574fca5c43f5852b11677029f26d14),, [f0cedb14](https://github.com/mrjackwills/staticpi_backend/commit/f0cedb14a3eaaad39050b359c4b5591da51e0aa6),
+ Docker alpine version bump, [52f41024](https://github.com/mrjackwills/staticpi_backend/commit/52f41024fb5359595f3455337143a776247fe056),
+ linting, [4481bdf4](https://github.com/mrjackwills/staticpi_backend/commit/4481bdf46b9dbf2e0996686cf066218bac84cb77),
+ run.sh v0.3.0, [37d20bdf](https://github.com/mrjackwills/staticpi_backend/commit/37d20bdf841b9b5860f925e84c6b9251a4a68b9c),
+ dependencies updated, [3b19f347](https://github.com/mrjackwills/staticpi_backend/commit/3b19f347bca60d48a152119c7d8dbc9a7a8e0337),

### Features
+ exit on tracing error, [861c835a](https://github.com/mrjackwills/staticpi_backend/commit/861c835a90e40a6a9abcd7d80fb3387a52dc68d6),

### Fixes
+ connect_async tests, [9bc2a3e8](https://github.com/mrjackwills/staticpi_backend/commit/9bc2a3e8b44b026d6bfeebf9044ac4cbba3bb360),
+ docker log mount location, [60c241ed](https://github.com/mrjackwills/staticpi_backend/commit/60c241edcd614eec6fb541552e2e25dd8fac6ff9),
+ init_db.sql error, [f44e12e7](https://github.com/mrjackwills/staticpi_backend/commit/f44e12e7f509085b8bf9259c426b4bf2cb59105b),

### Refactors
+ dead code removed, [2184c089](https://github.com/mrjackwills/staticpi_backend/commit/2184c089b05d1b8de4e0125672d6e78b07900616),
+ replace OR with IN operator, [45c3b7db](https://github.com/mrjackwills/staticpi_backend/commit/45c3b7dbb41492ef945740743ece2b50891498bb),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.13'>v0.0.13</a>
### 2024-05-07

### Chores
+ dependencies updated, [d5b3cfab](https://github.com/mrjackwills/staticpi_backend/commit/d5b3cfabed95357f3bec23468a3abdc622b5df80),, [026d3e33](https://github.com/mrjackwills/staticpi_backend/commit/026d3e3330d348364a3320c1ee0acba66caa74f5),, [00918885](https://github.com/mrjackwills/staticpi_backend/commit/009188855c57da335c80279fb0946190060234f0),

### Features
+ show name & version at application start, [90c046b4](https://github.com/mrjackwills/staticpi_backend/commit/90c046b4e45f6553f0d8525da3a0a34def7077bc),

### Fixes
+ use .d directories, [5f0cc02aa49c3d136837f265463596ae29d3f2f]
+ delete_ip() missing joins, [766220cc7ef57c30505115999dbccc3042867db]

### Refactors
+ use &str instead of String, [f39364f3](https://github.com/mrjackwills/staticpi_backend/commit/f39364f3e15c9b69d959f85fc30b22029b992f31),

### Tests
+ redis dependency import, [29fb209d](https://github.com/mrjackwills/staticpi_backend/commit/29fb209d82379d9e491d707895778883be104681),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.12'>v0.0.12</a>
### 2024-04-01

### Chores
+ create_release v0.5.4, [d01c4aa7](https://github.com/mrjackwills/staticpi_backend/commit/d01c4aa77aab7f18e82e5ab19a281b16879e18a2),
+ dependencies updated, [1cf6935f](https://github.com/mrjackwills/staticpi_backend/commit/1cf6935ff56e6b599061735724e00832d12f8490),

### Docs
+ typo, [e9fa744c](https://github.com/mrjackwills/staticpi_backend/commit/e9fa744ce7e8dfe37f59fe48fc76fe9d7a92eb3e),

### Features
+ use mimalloc, [0ce04c50](https://github.com/mrjackwills/staticpi_backend/commit/0ce04c504e72f4cb4f5a10b7ef999baa30ea6895),

### Fixes
+ docker-compose api memory limit reduction, [3bd58f3a](https://github.com/mrjackwills/staticpi_backend/commit/3bd58f3a554f3f2e66dc0fe4f9a17512166478a5),

### Refactors
+ redundant as ref clone, [485c8756](https://github.com/mrjackwills/staticpi_backend/commit/485c8756b2c26c316e69a5fbe14be861dbbca5fd),
+ remove docker-compose version, [cb7bfe02](https://github.com/mrjackwills/staticpi_backend/commit/cb7bfe02a5f6f91fb53704c2915a58b9cfb4506f),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.11'>v0.0.11</a>
### 2024-02-11

### Chores
+ create_release.sh v0.5.3, [aa566d2c](https://github.com/mrjackwills/staticpi_backend/commit/aa566d2cc00574537dd6f2454f8426c625cbcfbe),
+ .devcontainer updated, [9fc5b448](https://github.com/mrjackwills/staticpi_backend/commit/9fc5b4484b0ee7c4337d90b9c982d9a89e4cfa9c),
+ dependencies updated, [3cd915c4](https://github.com/mrjackwills/staticpi_backend/commit/3cd915c47885c1460dd5072ce0f4007e7f97601a),, [974412ad](https://github.com/mrjackwills/staticpi_backend/commit/974412ad38719eaeb3f46fcc9432526130f22de7),

### Features
+ switch redis client to Fred, [e55a0918](https://github.com/mrjackwills/staticpi_backend/commit/e55a0918a0f63034a0f15e0bfba97d08ce1337a0),

### Fixes
+ authentication & token, [9d62454b](https://github.com/mrjackwills/staticpi_backend/commit/9d62454beba8dd97e3ad0c3c02fffb9f722c4ae1),
+ change Arc<Mutex<redis>> to ConnectionManager (now redundant) [e184f726](https://github.com/mrjackwills/staticpi_backend/commit/e184f7260b66a5fa149daeeadbf6c2ea6afdce0c),
+ create_release typo, [47b4e85f](https://github.com/mrjackwills/staticpi_backend/commit/47b4e85fc119216ae8ad4e96f688dc21ec7a3195),
+ increase api memory limit, [f39bf8cb](https://github.com/mrjackwills/staticpi_backend/commit/f39bf8cb75ac157a32bd0da75d97368928c5ce66),

### Refactors
+ authentication, [0d85b096](https://github.com/mrjackwills/staticpi_backend/commit/0d85b0963f193990c81203eb787a7b63f733668a),
+ authenticate backup codes, tests added, [b626222e](https://github.com/mrjackwills/staticpi_backend/commit/b626222e24fe396ffca4e2b53c21b611768325fa),
+ Docker setup reduced, [50a07855](https://github.com/mrjackwills/staticpi_backend/commit/50a078555de7fa8c14943f6d23451256d20ac818),
+ sql queries formatted, [1c6403f7](https://github.com/mrjackwills/staticpi_backend/commit/1c6403f72bf7f10c963105c7ed3d0f02cdda8ebb),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.10'>v0.0.10</a>
### 2024-01-29

### CHores
+ GitHub workflow updated, [6dac6085](https://github.com/mrjackwills/staticpi_backend/commit/6dac608515aed97b79188082909251900acb8b27),
+ create_release v0.5.1, [81cfc478](https://github.com/mrjackwills/staticpi_backend/commit/81cfc47826b7048a85609d452ba64b1c0f855974),
+ .sql files formatted, [1d908e5e](https://github.com/mrjackwills/staticpi_backend/commit/1d908e5eddef4285c12dec1004109d1c35bf0c62),
+ .devcontainer updated, [b0426eb9](https://github.com/mrjackwills/staticpi_backend/commit/b0426eb9eb30004dbda5607e69d80cb3aa578857),
+ dependencies updated, [43833dea](https://github.com/mrjackwills/staticpi_backend/commit/43833dea35232c4cdbd54a2b8df32965efdc0412),

### Fixes
+ argon debug/release cfg, [f01ed9bb](https://github.com/mrjackwills/staticpi_backend/commit/f01ed9bbebd6450671e6d6bfb5086d30b4213553),

### Refactors
+ dead code removed, [be888528](https://github.com/mrjackwills/staticpi_backend/commit/be88852891b67a3856fff0756d0b194958f7609c),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.9'>v0.0.9</a>
### 2024-01-06

### Chores
+ Docker TZ updated, [861a5a07](https://github.com/mrjackwills/staticpi_backend/commit/861a5a072717877cca799e9b04a3a1d82a45c1fc),
+ dependencies updated, [12edddae](https://github.com/mrjackwills/staticpi_backend/commit/12edddaec1aac46a740e08432f4e194867b5a655),, [2ca492f0](https://github.com/mrjackwills/staticpi_backend/commit/2ca492f0e96a5321acca77d519a8ad7a0b870693),

### Fixes
+ session_set expire temp fix, [718393ba](https://github.com/mrjackwills/staticpi_backend/commit/718393bae630d043ff7ea9bca92b0f7f816d49bd),
+ .gitattributes, [053c892a](https://github.com/mrjackwills/staticpi_backend/commit/053c892aeef8c59e8302e1149a1799a83ea25985),

### Refactors
+ tabs switched for spaces, [01f1745d](https://github.com/mrjackwills/staticpi_backend/commit/01f1745d369514511a09b74ca0f2f86775b5594c),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.8'>v0.0.8</a>
### 2023-12-30

### Chores
+ Rust 1.75.0 linting, [c8ce91aa](https://github.com/mrjackwills/staticpi_backend/commit/c8ce91aa153bc87b6eae128d7e3f48b36a22472f),
+ dependencies updated, redis method updated, [4000dab9](https://github.com/mrjackwills/staticpi_backend/commit/4000dab991893a52c8f591834a5f817e9f7e36f3),, [da528da6](https://github.com/mrjackwills/staticpi_backend/commit/da528da68a1cb0498cee515c9b32901e635dd767),
+ bump alpine to 3.19, [d491323a](https://github.com/mrjackwills/staticpi_backend/commit/d491323a0e298568241edb8a25e488266116be63),

### Features
+ graceful shutdown re-introduced, [ae753b4f](https://github.com/mrjackwills/staticpi_backend/commit/ae753b4f64f2afad394cf4756495171b1834adaa),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.7'>v0.0.7</a>
### 2023-11-28

### Chores
+ bump PostgreSQL to v16, [9ec8330b](https://github.com/mrjackwills/staticpi_backend/commit/9ec8330b2d47f6250bffd6f896d7c230b26da798),
+ lints moved from main.rs to Cargo.toml, [be39164d](https://github.com/mrjackwills/staticpi_backend/commit/be39164da90d58ed103462b06829e46f00642eb4),
+ .devcontainer updated, [d3dc2225](https://github.com/mrjackwills/staticpi_backend/commit/d3dc222596f50e999f20502eff551ca45fdc1460),, [6094305a](https://github.com/mrjackwills/staticpi_backend/commit/6094305a4c78badb2cdfc916e085d90d6952701d),
+ dependencies updated, [08d693a2](https://github.com/mrjackwills/staticpi_backend/commit/08d693a26141ad28f3527b85136a2cffb190e2ba),, [6f87e1d4](https://github.com/mrjackwills/staticpi_backend/commit/6f87e1d4c88222c901607ff1432371557c22819f),, [39ba2d18](https://github.com/mrjackwills/staticpi_backend/commit/39ba2d18a4ea72d5efe28352f556bf2d9c212779),, [d4e2a1e4](https://github.com/mrjackwills/staticpi_backend/commit/d4e2a1e4440c876139768c6a09bf723e0a20d841),, [88ca9711](https://github.com/mrjackwills/staticpi_backend/commit/88ca9711b5b7bc439daf48cfababefa7a5dd4de6),, [1c4c6a9b](https://github.com/mrjackwills/staticpi_backend/commit/1c4c6a9b7eb273d3a568729a5fad831cf5ebaa22),
+ Rust 1.74.0 linting, [7d32e3ff](https://github.com/mrjackwills/staticpi_backend/commit/7d32e3ff3e90b588f38cb790f84b336d6e0419bd),
+ Rust 1.73.0 linting, [5a518c32](https://github.com/mrjackwills/staticpi_backend/commit/5a518c32171848af0618770329ea45d6fd5d6715),
+ update to axum 0.7, [a23754c8](https://github.com/mrjackwills/staticpi_backend/commit/a23754c81ca45eb748332056c1db21d8a775a17e),

### Features
+ Application state now an arc, [79f3cee6](https://github.com/mrjackwills/staticpi_backend/commit/79f3cee6027ca7b96031537d466bbd6aefa5a8cc),

### Refactors
+ use '&str' instead of '&String', [3c987925](https://github.com/mrjackwills/staticpi_backend/commit/3c9879251354d6ea4bec4ed79526f257334cc521),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.6'>v0.0.6</a>
### 2023-08-25

### Chores
+ Rust 1.72.0 linting, [7d5a57df](https://github.com/mrjackwills/staticpi_backend/commit/7d5a57df1a0934530f15d32096edcf43822b408e),
+ dependencies updated, [ecf010fc](https://github.com/mrjackwills/staticpi_backend/commit/ecf010fc978d53356bb3d32cf2ad5be865f646a7),

### Features
+ tungstenite max_buffer, [9129df98](https://github.com/mrjackwills/staticpi_backend/commit/9129df9867e6e86ddfa8bc327d43c9a292188c1e),

### Fixes
+ release build profile LTO thin, [ca358daf](https://github.com/mrjackwills/staticpi_backend/commit/ca358daf4c7887390c38ca155e8d8907e19dc278),

### Reverts
+ Transactions double de-reference, [a2dab6a5](https://github.com/mrjackwills/staticpi_backend/commit/a2dab6a50aad15367eeae8d6b951f921183e270d),
+ remove spare protocol env, [a1af9e22](https://github.com/mrjackwills/staticpi_backend/commit/a1af9e22b1159d9871c0eccf777a5ff12867f6f3),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.5'>v0.0.5</a>
### 2023-07-28

### Chores
+ create_release 0.3.0, [64621b14](https://github.com/mrjackwills/staticpi_backend/commit/64621b1469143515c2a4d93a1dadefe9c613ecb2),
+ dependencies updated, [ab9cc8aa](https://github.com/mrjackwills/staticpi_backend/commit/ab9cc8aa28d3b2b52c9d02d33bd8f0dd7ac6252f),

### Fixes
+ disable logging based on env level, [e7fd7c67](https://github.com/mrjackwills/staticpi_backend/commit/e7fd7c670953921517de5b2064688cdbb9d0c304),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.4'>v0.0.4</a>
### 2023-06-07

### Reverts
+ banned_domain macro removed, [5f235231](https://github.com/mrjackwills/staticpi_backend/commit/5f23523167526de26db09e53b108aff6b0ad15e7),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.3'>v0.0.3</a>
### 2023-06-07

### Chores
+ Drop linting, [50bce1a4](https://github.com/mrjackwills/staticpi_backend/commit/50bce1a441e0aa540ad56889ac66c993a0d25f90),
+ dependencies updated, [9dd7c2a1](https://github.com/mrjackwills/staticpi_backend/commit/9dd7c2a1ad60637ef7e24d0ffc07c40f2b30cd09),, [4209ff7d](https://github.com/mrjackwills/staticpi_backend/commit/4209ff7dc1a552aed74b8fc7725c3a07ec65fca3),
+ Dockerfile bumps, use Ubuntu, [8d5d7bb3](https://github.com/mrjackwills/staticpi_backend/commit/8d5d7bb3a2fe81c99268df827c2ada4d16370a53),

### Features
+ use `totp-rs` for two factor authentication, [52cb876c](https://github.com/mrjackwills/staticpi_backend/commit/52cb876c83389de4d7c367f4e6ccea21597c54f8),
+ `sleep!` & `define_routes!` macros, [7dc41721](https://github.com/mrjackwills/staticpi_backend/commit/7dc417217795ed66855a211b24062ee79f72c40f),, [54597748](https://github.com/mrjackwills/staticpi_backend/commit/54597748a0b21c47b172bd9bfae4b9c2f7a46a1e),

### Fixes
+ api Dockerfile fix, [c78fbb60](https://github.com/mrjackwills/staticpi_backend/commit/c78fbb6038b74c563491934677ff786f1ae8f474),
+ run.sh, [cf9fd012](https://github.com/mrjackwills/staticpi_backend/commit/cf9fd0124e370982dba50dcf6108bfbd8bffe97c),

### Refactors
+ use macro to generate new type SQL ids, [0fdf247b](https://github.com/mrjackwills/staticpi_backend/commit/0fdf247bc37c3c8561903de8c7b09df9295a21a7),
+ dead code removed, [2fa15d95](https://github.com/mrjackwills/staticpi_backend/commit/2fa15d953088847db2e2cef36d24503dd4529720),

### Tests
+ totp fix, [cda5e65e](https://github.com/mrjackwills/staticpi_backend/commit/cda5e65e4cf23062da8123ec6f6c321d4661b6ee),
+ ratelimit fix, [dd049ee2](https://github.com/mrjackwills/staticpi_backend/commit/dd049ee2700d945992ac5d5cb606f24b08319742),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.2'>v0.0.2</a>
### 2023-03-10

### Chores
+ dependencies updated, [fddecdcb](https://github.com/mrjackwills/staticpi_backend/commit/fddecdcb47a703ae696a186cadc967d82740020c),, [d6ad0eb6](https://github.com/mrjackwills/staticpi_backend/commit/d6ad0eb6b22d7a577b429fd92fbc358370c210dc),
+ Rust 1.68.0 linting, [d3ab2cef](https://github.com/mrjackwills/staticpi_backend/commit/d3ab2ceff7f62b91f4fc3811d2c300c807bdde4c),
+ devcontainer sparse protocol index, [8a974849](https://github.com/mrjackwills/staticpi_backend/commit/8a974849d6b49dba4fd6c39544a74c9bb19b6b66),

### Features
+ SysInfo make async, [cb0eb394](https://github.com/mrjackwills/staticpi_backend/commit/cb0eb394c205e894af31c1f7b23c1d0c431fca00),, [823e362c](https://github.com/mrjackwills/staticpi_backend/commit/823e362cd5df03a8c1f35da59b46c1367ee5ca0f),

### Refactors
+ `unwrap`, to `ok()` or `_default()`, [afb73acb](https://github.com/mrjackwills/staticpi_backend/commit/afb73acb1e4fd4e6087b4d2c4a9dbab5e34db27a),

# <a href='https://github.com/mrjackwills/staticpi_backend/releases/tag/v0.0.1'>v0.0.1</a>
### 2023-03-06

### Chores
+ dependencies updated, [d7a5d5e7](https://github.com/mrjackwills/staticpi_backend/commit/d7a5d5e73b781636f8d75f80ac50957e8eb3ae84),, [e3490c8d](https://github.com/mrjackwills/staticpi_backend/commit/e3490c8d6cdc1818594581400cac6da3e29758ac),
+ devcontainer updated, [e907057f](https://github.com/mrjackwills/staticpi_backend/commit/e907057f1321839f8df1ecc2d57a9f2d9c20fefc),

### Docs
+ readme updated, [709477af](https://github.com/mrjackwills/staticpi_backend/commit/709477af645d2851598d1b49b6803eda8fa906e2),

### Features
+ argon2 param builder into lazy static, [eeba93ea](https://github.com/mrjackwills/staticpi_backend/commit/eeba93eac397ab75d71fa26c4de3d2322502accc),

### Fixes
+ incoming json downcast error, [7699db04](https://github.com/mrjackwills/staticpi_backend/commit/7699db04cb122e785bf95c191a3187e52edfd97c),
+ devcontainer updated, [31acce16](https://github.com/mrjackwills/staticpi_backend/commit/31acce167d0efe49857f261302b5eb63da4a89e1),

### Refactors
+ postgreSQL use `USING(x)` where appropriate, [1018a280](https://github.com/mrjackwills/staticpi_backend/commit/1018a280bca4af88ab31713cb8f99c8dedca463c),

### Tests
+ use UNSAFE_PASSWORD const, [3a061a07](https://github.com/mrjackwills/staticpi_backend/commit/3a061a07a7ccdf980fa53c9296a519d78f407192),

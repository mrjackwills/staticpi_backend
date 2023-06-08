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

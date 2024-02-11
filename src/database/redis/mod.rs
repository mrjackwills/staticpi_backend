mod models;

use crate::{api_error::ApiError, parse_env::AppEnv};
use fred::{clients::RedisPool, interfaces::ClientLike, types::ReconnectPolicy};

pub use models::*;
use std::{fmt, net::IpAddr};
use ulid::Ulid;

use self::rate_limit::RateLimit;

use super::new_types::{DeviceId, UserId};

pub const HASH_FIELD: &str = "data";

#[derive(Debug, Clone)]
pub enum RedisKey<'a> {
    AccessToken(&'a Ulid),
    CacheIp(IpAddr),
    CacheMessage(DeviceId),
    CacheMonthlyBandwidth(UserId),
    CacheUseragent(&'a str),
    RateLimit(&'a RateLimit),
    Session(&'a Ulid),
    SessionSet(UserId),
    TwoFASetup(UserId),
    VerifyEmail(&'a str),
    VerifySecret(&'a Ulid),
}

impl<'a> fmt::Display for RedisKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let disp = match self {
            Self::AccessToken(ulid) => format!("access_token::{ulid}"),
            Self::CacheIp(ip) => format!("cache::ip::{ip}"),
            Self::CacheMessage(device_id) => {
                format!("cache::message::{}", device_id.get())
            }
            Self::CacheMonthlyBandwidth(registered_user_id) => {
                format!("cache::monthly_bandwidth::{}", registered_user_id.get())
            }
            Self::CacheUseragent(useragent) => format!("cache::useragent::{useragent}"),
            Self::RateLimit(limiter) => limiter.to_string(),
            Self::Session(ulid) => format!("session::{ulid}"),
            Self::SessionSet(id) => format!("session_set::user::{}", id.get()),
            Self::TwoFASetup(id) => format!("two_fa_setup::{}", id.get()),
            Self::VerifyEmail(email) => format!("verify::email::{email}"),
            Self::VerifySecret(secret) => format!("verify::secret::{secret}"),
        };
        write!(f, "{disp}")
    }
}

/// Macro to convert a stringified struct back into the struct
#[macro_export]
macro_rules! redis_hash_to_struct {
    ($struct_name:ident) => {
        impl fred::types::FromRedis for $struct_name {
            fn from_value(
                value: fred::prelude::RedisValue,
            ) -> Result<Self, fred::prelude::RedisError> {
                value.as_str().map_or(
                    Err(fred::error::RedisError::new(
                        fred::error::RedisErrorKind::Parse,
                        format!("FromRedis: {}", stringify!(struct_name)),
                    )),
                    |i| {
                        serde_json::from_str::<Self>(&i).map_err(|_| {
                            fred::error::RedisError::new(
                                fred::error::RedisErrorKind::Parse,
                                "serde",
                            )
                        })
                    },
                )
            }
        }
    };
}

// Generate a hashmap with a fixed key, used for redis hset
#[macro_export]
macro_rules! hmap {
    ($x:expr) => {{
        std::collections::HashMap::from([(HASH_FIELD, $x)])
    }};
}

pub struct DbRedis;

impl DbRedis {
    /// Get an async redis connection
    pub async fn get_pool(app_env: &AppEnv) -> Result<RedisPool, ApiError> {
        let redis_url = format!(
            "redis://:{password}@{host}:{port}/{db}",
            password = app_env.redis_password,
            host = app_env.redis_host,
            port = app_env.redis_port,
            db = app_env.redis_database
        );

        let config = fred::types::RedisConfig::from_url(&redis_url)?;
        let pool = fred::types::Builder::from_config(config)
            .with_performance_config(|config| {
                config.auto_pipeline = true;
            })
            // use exponential backoff, starting at 100 ms and doubling on each failed attempt up to 30 sec
            .set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2))
            .build_pool(32)?;
        pool.init().await?;
        Ok(pool)
    }
}

/// cargo watch -q -c -w src/ -x 'test db_redis_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {

    use crate::parse_env;

    use super::*;

    #[tokio::test]
    async fn db_redis_mod_get_connection_and_ping() {
        let app_env = parse_env::AppEnv::get_env();
        let result = DbRedis::get_pool(&app_env).await;
        assert!(result.is_ok());
        let result = result.unwrap();

        let result = result.ping::<String>().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "PONG");
    }
}

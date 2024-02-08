mod models;

use crate::{api_error::ApiError, parse_env::AppEnv};
pub use models::*;
use redis::{
    aio::ConnectionManager, from_redis_value, ConnectionAddr, ConnectionInfo, RedisConnectionInfo,
    Value,
};
use serde::de::DeserializeOwned;
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

/// Convert from a Redis string into the struct they are based on
pub fn string_to_struct<T>(v: &Value) -> Result<T, redis::RedisError>
where
    T: DeserializeOwned,
{
    let json_str: String = from_redis_value(v)?;
    let result: Result<T, serde_json::Error> = serde_json::from_str(&json_str);
    result.map_or(
        Err((redis::ErrorKind::TypeError, "Parse to JSON Failed").into()),
        Ok,
    )
}

pub struct DbRedis;

impl DbRedis {
    /// Open up a redis connection, to be saved in an Arc<Mutex> in application state
    /// Get an async redis connection
    pub async fn get_connection(app_env: &AppEnv) -> Result<ConnectionManager, ApiError> {
        let connection_info = ConnectionInfo {
            redis: RedisConnectionInfo {
                db: i64::from(app_env.redis_database),
                password: Some(app_env.redis_password.clone()),
                username: None,
            },
            addr: ConnectionAddr::Tcp(app_env.redis_host.clone(), app_env.redis_port),
        };

        Ok(redis::aio::ConnectionManager::new(redis::Client::open(connection_info)?).await?)
    }
}

/// cargo watch -q -c -w src/ -x 'test db_redis_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {

    use redis::{cmd, RedisError};

    use crate::parse_env;

    use super::*;

    #[tokio::test]
    async fn db_redis_mod_get_connection_and_ping() {
        let app_env = parse_env::AppEnv::get_env();
        let result = DbRedis::get_connection(&app_env).await;
        assert!(result.is_ok());

        let result: Result<String, RedisError> =
            cmd("PING").query_async(&mut result.unwrap()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "PONG");
    }
}

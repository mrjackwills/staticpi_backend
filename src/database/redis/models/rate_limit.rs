use std::{fmt, net::IpAddr};

use redis::{aio::Connection, AsyncCommands};
use tokio::sync::MutexGuard;

use crate::{
    api_error::ApiError,
    database::{
        device::{ModelDevice, ModelWsDevice},
        new_types::{ApiKey, DeviceId, UserId},
        redis::RedisKey,
        user::ModelUser,
        user_level::UserLevel,
    },
    servers::AMRedis,
    user_io::{deserializer::IncomingDeserializer, outgoing_json::oj::AdminLimit},
};

const ONE_MINUTE_AS_SEC: usize = 60;

#[derive(Debug, Clone)]
pub enum LimitContact {
    Ip(IpAddr),
    Email(String),
}

#[derive(Debug, Clone)]
pub enum LimitWs {
    // Ws limiter for free user, uses user_id
    Free(UserId),
    // WS limiter for anything other than Free user, uses device_id
    Pro(DeviceId),
}

#[derive(Debug, Clone)]
pub enum RateLimit {
    // Token server
    ApiKey(ApiKey),
    // General api rate limit - for none authenticated users
    Ws(LimitWs),
    // General Ip limiter
    Ip(IpAddr),
    // Authenticated user api
    User(UserId),
    // unique rate limit, so that can only register with an email address once per day?
    Register(String),
    // Limit the download data option to only be used once per day
    DownloadData(UserId),
    // Contact form limits based on both IP and email address
    Contact(LimitContact),
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let disp = match self {
            Self::DownloadData(user_id) => format!("download_data::{}", user_id.get()),
            Self::ApiKey(api_key) => format!("api_key::{}", api_key.get()),
            Self::User(user_id) => format!("user::{}", user_id.get()),
            Self::Ip(ip) => format!("ip::{ip}"),
            Self::Register(email) => format!("register::{email}"),
            Self::Ws(limit_ws) => match limit_ws {
                LimitWs::Free(user_id) => format!("ws_free::{}", user_id.get()),
                LimitWs::Pro(device_id) => format!("ws_pro::{}", device_id.get()),
            },
            Self::Contact(contact) => match contact {
                LimitContact::Email(email) => format!("contact_email::{email}"),
                LimitContact::Ip(ip) => format!("contact_ip::{ip}"),
            },
        };
        write!(f, "ratelimit::{disp}")
    }
}

/// Return AdminLimit object for a given rate_limit
async fn get_admin_limit(rate_limit: RateLimit, redis: &AMRedis) -> Result<AdminLimit, ApiError> {
    let mut redis = redis.lock().await;
    let blocked = rate_limit.exceeded(&mut redis).await?;
    let ttl = rate_limit.ttl(&mut redis).await?;
    let points = rate_limit.get_count(&mut redis).await?.unwrap_or_default();
    drop(redis);
    Ok(AdminLimit {
        key: rate_limit.to_string(),
        points,
        max: rate_limit.get_limit(),
        ttl,
        blocked,
    })
}

/// Used to convert a full rate limit, e.g. `ratelimit::ws_pro::123` into a RateLimit
/// Used to delete a rate limit by an Admin user
impl TryFrom<&String> for RateLimit {
    type Error = ApiError;

    fn try_from(key: &String) -> Result<Self, ApiError> {
        let splitter = key.splitn(3, "::").skip(1).collect::<Vec<_>>();
        if let (Some(limit_type), Some(limit_key)) = (splitter.first(), splitter.get(1)) {
            Ok(match *limit_type {
                "api_key" => {
                    if IncomingDeserializer::is_hex(limit_key, 128) {
                        Self::from(&ApiKey::from(*limit_key))
                    } else {
                        return Err(ApiError::Internal(String::from("api_key error")));
                    }
                }
                "ws_free" => {
                    if let Ok(id) = limit_key.parse::<i64>() {
                        Self::Ws(LimitWs::Free(UserId::from(id)))
                    } else {
                        return Err(ApiError::Internal(String::from("ws_free error")));
                    }
                }
                "ws_pro" => {
                    if let Ok(id) = limit_key.parse::<i64>() {
                        Self::Ws(LimitWs::Pro(DeviceId::from(id)))
                    } else {
                        return Err(ApiError::Internal(String::from("ws_pro error")));
                    }
                }
                "ip" => {
                    if let Ok(ip) = limit_key.parse::<IpAddr>() {
                        Self::Ip(ip)
                    } else {
                        return Err(ApiError::Internal(String::from("ip error")));
                    }
                }
                "user" => {
                    if let Ok(i) = limit_key.parse::<i64>() {
                        Self::User(UserId::from(i))
                    } else {
                        return Err(ApiError::Internal(String::from("user_id")));
                    }
                }
                "download_data" => {
                    if let Ok(i) = limit_key.parse::<i64>() {
                        Self::DownloadData(UserId::from(i))
                    } else {
                        return Err(ApiError::Internal(String::from("download_data")));
                    }
                }
                "register" => {
                    if let Some(email) = IncomingDeserializer::valid_email(limit_key) {
                        Self::Register(email)
                    } else {
                        return Err(ApiError::Internal(String::from("email address")));
                    }
                }
                "contact_email" => {
                    if let Some(email) = IncomingDeserializer::valid_email(limit_key) {
                        Self::Contact(LimitContact::Email(email))
                    } else {
                        return Err(ApiError::Internal(String::from("email address")));
                    }
                }
                "contact_ip" => {
                    if let Ok(ip) = limit_key.parse::<IpAddr>() {
                        Self::Contact(LimitContact::Ip(ip))
                    } else {
                        return Err(ApiError::Internal(String::from("ip error")));
                    }
                }
                _ => return Err(ApiError::Internal(String::from("unknown key"))),
            })
        } else {
            Err(ApiError::InvalidValue("invalid rate limit key".to_owned()))
        }
    }
}

impl From<&ModelWsDevice> for RateLimit {
    fn from(device: &ModelWsDevice) -> Self {
        match device.user_level {
            UserLevel::Free => Self::Ws(LimitWs::Free(device.registered_user_id)),
            _ => Self::Ws(LimitWs::Pro(device.device_id)),
        }
    }
}

impl From<&ApiKey> for RateLimit {
    fn from(api_key: &ApiKey) -> Self {
        Self::ApiKey(api_key.clone())
    }
}

impl From<(&ModelDevice, &ModelUser)> for RateLimit {
    fn from((device, user): (&ModelDevice, &ModelUser)) -> Self {
        match user.user_level {
            UserLevel::Free => Self::Ws(LimitWs::Free(user.registered_user_id)),
            _ => Self::Ws(LimitWs::Pro(device.device_id)),
        }
    }
}

struct BlockTimes {
    big: usize,
    small: usize,
}

/// Generate big and small block time, in seconds
/// So far all limiters use same block times
impl BlockTimes {
    const fn new(rate_limit: &RateLimit) -> Self {
        match rate_limit {
            RateLimit::Register(_) => Self {
                big: ONE_MINUTE_AS_SEC * 60 * 24 * 7,
                small: ONE_MINUTE_AS_SEC * 60 * 24,
            },
            RateLimit::DownloadData(_) => Self {
                big: ONE_MINUTE_AS_SEC * 60 * 24,
                small: ONE_MINUTE_AS_SEC * 60 * 24,
            },
            RateLimit::Contact(_) => Self {
                big: ONE_MINUTE_AS_SEC * 60 * 6,
                small: ONE_MINUTE_AS_SEC,
            },
            _ => Self {
                big: ONE_MINUTE_AS_SEC * 5,
                small: ONE_MINUTE_AS_SEC,
            },
        }
    }
}

impl RateLimit {
    /// rate limits per limiter
    const fn get_limit(&self) -> u64 {
        match self {
            Self::ApiKey(_) => 60,
            Self::Ip(_) => 45,
            Self::User(_) => 150,
            Self::Ws(limit_ws) => match limit_ws {
                LimitWs::Free(_) => 15,
                LimitWs::Pro(_) => 300,
            },
            Self::Contact(_) => 2,
            Self::DownloadData(_) | Self::Register(_) => 1,
        }
    }

    // Get all current rate limits - is either based on user_email or ip address
    // User as input, so that only admin user can access it?
    pub async fn get_all(redis: &AMRedis, user: &ModelUser) -> Result<Vec<AdminLimit>, ApiError> {
        match user.user_level {
            UserLevel::Admin => {
                let mut output = vec![];
                let all_keys: Vec<String> = redis.lock().await.keys("ratelimit::*").await?;
                for key in all_keys {
                    let rate_limit = Self::try_from(&key)?;
                    output.push(get_admin_limit(rate_limit, redis).await?);
                }
                Ok(output)
            }
            _ => Err(ApiError::Authorization),
        }
    }

    fn key(&self) -> String {
        RedisKey::RateLimit(self).to_string()
    }

    /// Get the ttl for a given limiter, converts from the redis isize to usize
    pub async fn ttl(&self, redis: &mut MutexGuard<'_, Connection>) -> Result<usize, ApiError> {
        Ok(usize::try_from(redis.ttl::<String, isize>(self.key()).await?).unwrap_or_default())
    }

    /// If currently rate limited, return ttl, else 0
    pub async fn limited_ttl(&self, redis: &AMRedis) -> Result<usize, ApiError> {
        let mut redis = redis.lock().await;
        if let Some(count) = self.get_count(&mut redis).await? {
            if count >= self.get_limit() {
                return self.ttl(&mut redis).await;
            }
        }
        Ok(0)
    }

    /// Return true if rate limit is exceeded by factor of 4
    pub async fn exceeded(&self, redis: &mut MutexGuard<'_, Connection>) -> Result<bool, ApiError> {
        if let Some(i) = self.get_count(redis).await? {
            if i >= self.get_limit() * 4 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn get_count(
        &self,
        redis: &mut MutexGuard<'_, Connection>,
    ) -> Result<Option<u64>, ApiError> {
        Ok(redis.get::<&str, Option<u64>>(&self.key()).await?)
    }
    /// Check if request has been rate limited, always increases the current value of the given rate limit
    pub async fn check(&self, redis: &AMRedis) -> Result<(), ApiError> {
        let key = self.key();
        let limit = self.get_limit();
        let blocks = BlockTimes::new(self);
        let mut redis = redis.lock().await;

        if let Some(count) = self.get_count(&mut redis).await? {
            redis.incr(&key, 1).await?;
            if count >= limit * 2 {
                redis.expire(&key, blocks.big).await?;
            }
            if count > limit {
                return Err(ApiError::RateLimited(self.ttl(&mut redis).await?));
            }
            if count == limit {
                redis.expire(&key, blocks.small).await?;
                return Err(ApiError::RateLimited(blocks.small));
            }
        } else {
            redis.incr(&key, 1).await?;
            redis.expire(&key, blocks.small).await?;
        }
        drop(redis);
        Ok(())
    }
}

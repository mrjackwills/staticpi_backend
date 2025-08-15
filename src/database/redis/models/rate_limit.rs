use std::{fmt, net::IpAddr};

use fred::{clients::Pool, interfaces::KeysInterface, types::scan::Scanner};
use futures::TryStreamExt;

use crate::{
    C, S,
    api_error::ApiError,
    database::{
        device::{ModelDevice, ModelWsDevice},
        new_types::{ApiKey, DeviceId, UserId},
        redis::RedisKey,
        user::ModelUser,
        user_level::UserLevel,
    },
    user_io::{deserializer::IncomingDeserializer, outgoing_json::oj::AdminLimit},
};

const ONE_MINUTE_AS_SEC: i64 = 60;

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
async fn get_admin_limit(rate_limit: RateLimit, redis: &Pool) -> Result<AdminLimit, ApiError> {
    let blocked = rate_limit.exceeded(redis).await?;
    let ttl = rate_limit.ttl(redis).await?;
    let points = rate_limit.get_count(redis).await?.unwrap_or_default();
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
impl TryFrom<&str> for RateLimit {
    type Error = ApiError;

    fn try_from(key: &str) -> Result<Self, ApiError> {
        let (limit_type, limit_key) = key
            .strip_prefix("ratelimit::")
            .ok_or(ApiError::Internal(S!("can't split key")))?
            .split_once("::")
            .ok_or(ApiError::Internal(S!("can't split key")))?;

        match limit_type {
            "api_key" => IncomingDeserializer::is_hex(limit_key, 128)
                .then(|| Self::from(&ApiKey::from(limit_key)))
                .ok_or(ApiError::Internal(S!("api key error"))),
            "contact_email" => IncomingDeserializer::valid_email(limit_key)
                .map(|email| Self::Contact(LimitContact::Email(email)))
                .ok_or(ApiError::Internal(S!("email_address"))),
            "contact_ip" => limit_key
                .parse::<IpAddr>()
                .map(|ip| Self::Contact(LimitContact::Ip(ip)))
                .map_err(|_| ApiError::Internal(S!("ip error"))),
            "download_data" => limit_key
                .parse::<i64>()
                .map(|i| Self::DownloadData(UserId::from(i)))
                .map_err(|_| ApiError::Internal(S!("download_data"))),
            "ip" => limit_key
                .parse::<IpAddr>()
                .map(Self::Ip)
                .map_err(|_| ApiError::Internal(S!("ip error"))),
            "register" => IncomingDeserializer::valid_email(limit_key)
                .map(Self::Register)
                .ok_or(ApiError::Internal(S!("email_address"))),
            "user" => limit_key
                .parse::<i64>()
                .map(|i| Self::User(UserId::from(i)))
                .map_err(|_| ApiError::Internal(S!("user id"))),
            "ws_free" => limit_key
                .parse::<i64>()
                .map(|i| Self::Ws(LimitWs::Free(UserId::from(i))))
                .map_err(|_| ApiError::Internal(S!("ws_free error"))),
            "ws_pro" => limit_key
                .parse::<i64>()
                .map(|i| Self::Ws(LimitWs::Pro(DeviceId::from(i))))
                .map_err(|_| ApiError::Internal(S!("ws_pro error"))),
            _ => Err(ApiError::Internal(S!("unknown key"))),
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
        Self::ApiKey(C!(api_key))
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
    big: i64,
    small: i64,
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
    pub async fn get_all(redis: &Pool, user: &ModelUser) -> Result<Vec<AdminLimit>, ApiError> {
        match user.user_level {
            UserLevel::Admin => {
                let mut output = vec![];
                let mut scanner = redis.next().scan("ratelimit::*", Some(100), None);
                while let Some(mut page) = scanner.try_next().await? {
                    if let Some(page) = page.take_results() {
                        for key in page {
                            output.push(
                                get_admin_limit(
                                    Self::try_from(key.as_str().unwrap_or_default())?,
                                    redis,
                                )
                                .await?,
                            );
                        }
                    }
                    page.next();
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
    pub async fn ttl(&self, redis: &Pool) -> Result<i64, ApiError> {
        Ok(redis.ttl::<i64, String>(self.key()).await?)
    }

    /// If currently rate limited, return ttl, else 0
    pub async fn limited_ttl(&self, redis: &Pool) -> Result<i64, ApiError> {
        if let Some(count) = self.get_count(redis).await?
            && count >= self.get_limit()
        {
            return self.ttl(redis).await;
        }
        Ok(0)
    }

    /// Return true if rate limit is exceeded by factor of 4
    pub async fn exceeded(&self, redis: &Pool) -> Result<bool, ApiError> {
        if let Some(i) = self.get_count(redis).await?
            && i >= self.get_limit() * 4
        {
            return Ok(true);
        }
        Ok(false)
    }

    async fn get_count(&self, redis: &Pool) -> Result<Option<u64>, ApiError> {
        Ok(redis.get::<Option<u64>, String>(self.key()).await?)
    }
    /// Check if request has been rate limited, always increases the current value of the given rate limit
    pub async fn check(&self, redis: &Pool) -> Result<(), ApiError> {
        let key = self.key();
        let limit = self.get_limit();
        let blocks = BlockTimes::new(self);

        if let Some(count) = self.get_count(redis).await? {
            redis.incr::<(), _>(&key).await?;
            if count >= limit * 2 {
                redis.expire::<(), _>(&key, blocks.big, None).await?;
            }
            if count > limit {
                return Err(ApiError::RateLimited(self.ttl(redis).await?));
            }
            if count == limit {
                redis.expire::<(), _>(&key, blocks.small, None).await?;
                return Err(ApiError::RateLimited(blocks.small));
            }
        } else {
            redis.incr::<(), _>(&key).await?;
            redis.expire::<(), _>(&key, blocks.small, None).await?;
        }
        Ok(())
    }
}

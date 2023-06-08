use redis::{AsyncCommands, FromRedisValue, RedisResult, Value};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    api_error::ApiError,
    connections::ConnectionType,
    database::{
        ip_user_agent::ModelUserAgentIp,
        new_types::{DeviceId, IpId},
        redis::{string_to_struct, RedisKey, HASH_FIELD},
    },
    servers::AMRedis,
};

impl FromRedisValue for AccessToken {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessToken {
    pub device_id: DeviceId,
    pub ip_id: IpId,
    pub device_type: ConnectionType,
}

impl AccessToken {
    /// twenty seconds
    pub const TTL_AS_SEC: u8 = 20;

    pub const fn new(
        device_id: DeviceId,
        useragent_ip: &ModelUserAgentIp,
        device_type: ConnectionType,
    ) -> Self {
        Self {
            device_id,
            ip_id: useragent_ip.ip_id,
            device_type,
        }
    }

    /// Generate redis key
    fn key(ulid: Ulid) -> String {
        RedisKey::AccessToken(&ulid).to_string()
    }

    /// Insert an access token, with a ttl of 20 seconds,
    pub async fn insert(&self, redis: &AMRedis, ulid: Ulid) -> Result<(), ApiError> {
        let key = Self::key(ulid);
        let data = serde_json::to_string(&self)?;
        let mut redis = redis.lock().await;
        redis.hset(&key, HASH_FIELD, &data).await?;
        Ok(redis.expire(key, Self::TTL_AS_SEC.into()).await?)
    }

    /// Remove access token
    pub async fn delete(&self, redis: &AMRedis, ulid: Ulid) -> Result<(), ApiError> {
        redis.lock().await.del(Self::key(ulid)).await?;
        Ok(())
    }

    /// Retrieve the access token, assuming ttl is still valid, and that the ip_id & device type matches
    pub async fn get(
        redis: &AMRedis,
        ulid: Ulid,
        device_type: ConnectionType,
        useragent_ip: &ModelUserAgentIp,
    ) -> Result<Option<Self>, ApiError> {
        (redis
            .lock()
            .await
            .hget::<'_, String, &str, Option<Self>>(Self::key(ulid), HASH_FIELD)
            .await?)
            .map_or(Ok(None), |data| {
                if data.ip_id == useragent_ip.ip_id && data.device_type == device_type {
                    Ok(Some(data))
                } else {
                    Ok(None)
                }
            })
    }
}

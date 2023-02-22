use redis::{AsyncCommands, FromRedisValue, RedisResult, Value};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

use crate::{
    api_error::ApiError,
    database::{
        device::ModelDeviceId,
        new_types::DeviceId,
        redis::{string_to_struct, RedisKey, HASH_FIELD},
    },
    servers::AMRedis,
    user_io::ws_message::wm,
};

impl FromRedisValue for MessageCache {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageCache(pub serde_json::Value);

impl MessageCache {
    /// Generate the redis key
    fn key(device_id: DeviceId) -> String {
        RedisKey::CacheMessage(device_id).to_string()
    }

    pub fn new(message: &wm::PiBody) -> Self {
        Self(message.data.clone())
    }

    /// Insert message into redis cache
    /// Is spawned onto own thread
    pub fn insert(&self, redis: &AMRedis, device_id: DeviceId) {
        let spawn_self = self.clone();
        let spawn_redis = Arc::clone(redis);
        tokio::spawn(async move {
            if let Ok(data) = serde_json::to_string(&spawn_self) {
                if let Err(e) = spawn_redis
                    .lock()
                    .await
                    .hset::<String, &str, String, ()>(Self::key(device_id), HASH_FIELD, data)
                    .await
                {
                    error!("{e:?}");
                };
            }
        });
    }

    /// Remove single device message cache
    pub async fn delete(redis: &AMRedis, device_id: DeviceId) -> Result<(), ApiError> {
        redis.lock().await.del(Self::key(device_id)).await?;
        Ok(())
    }

    /// Remove multiple device's message cache
    pub async fn delete_all(redis: &AMRedis, device_ids: &[ModelDeviceId]) -> Result<(), ApiError> {
        for device in device_ids {
            redis.lock().await.del(Self::key(device.device_id)).await?;
        }
        Ok(())
    }

    /// Retrieve message cache, and convert to a piBody
    pub async fn get(redis: &AMRedis, device_id: DeviceId) -> Result<Option<wm::PiBody>, ApiError> {
        redis
            .lock()
            .await
            .hget::<'_, String, &str, Option<Self>>(Self::key(device_id), HASH_FIELD)
            .await?
            .map_or(Ok(None), |data| {
                Ok(Some(wm::PiBody {
                    cache: Some(true),
                    data: data.0,
                    unique: None,
                }))
            })
    }
}

use std::collections::HashMap;

use fred::{
    clients::Pool,
    interfaces::{HashesInterface, KeysInterface},
};
use serde::{Deserialize, Serialize};

use crate::{
    C,
    api_error::ApiError,
    database::{
        device::ModelDeviceId,
        new_types::DeviceId,
        redis::{HASH_FIELD, RedisKey},
    },
    hmap, redis_hash_to_struct,
    user_io::ws_message::wm,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageCache(pub serde_json::Value);

redis_hash_to_struct!(MessageCache);

impl MessageCache {
    /// Generate the redis key
    fn key(device_id: DeviceId) -> String {
        RedisKey::CacheMessage(device_id).to_string()
    }

    pub fn new(message: &wm::PiBody) -> Self {
        Self(C!(message.data))
    }

    /// Insert message into redis cache
    /// Is spawned onto own thread
    pub fn insert(&self, redis: &Pool, device_id: DeviceId) {
        let spawn_self = C!(self);
        let spawn_redis = C!(redis);
        tokio::spawn(async move {
            if let Ok(data) = serde_json::to_string(&spawn_self)
                && let Err(e) = spawn_redis
                    .hset::<(), String, HashMap<&str, String>>(Self::key(device_id), hmap!(data))
                    .await
            {
                tracing::error!("{e:?}");
            }
        });
    }

    /// Remove single device message cache
    pub async fn delete(redis: &Pool, device_id: DeviceId) -> Result<(), ApiError> {
        Ok(redis.del(Self::key(device_id)).await?)
    }

    /// Remove multiple device's message cache
    pub async fn delete_all(redis: &Pool, device_ids: &[ModelDeviceId]) -> Result<(), ApiError> {
        for device in device_ids {
            redis.del::<(), _>(Self::key(device.device_id)).await?;
        }
        Ok(())
    }

    /// Retrieve message cache, and convert to a piBody
    pub async fn get(redis: &Pool, device_id: DeviceId) -> Result<Option<wm::PiBody>, ApiError> {
        redis
            .hget::<Option<Self>, String, &str>(Self::key(device_id), HASH_FIELD)
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

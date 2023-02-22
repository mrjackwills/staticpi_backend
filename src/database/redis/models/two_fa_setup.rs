use redis::{AsyncCommands, FromRedisValue, RedisResult, Value};
use serde::{Deserialize, Serialize};

use crate::{
    api_error::ApiError,
    database::{
        new_types::UserId,
        redis::{string_to_struct, RedisKey, HASH_FIELD},
        user::ModelUser,
    },
    servers::AMRedis,
};

impl FromRedisValue for RedisTwoFASetup {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisTwoFASetup(pub String);

impl RedisTwoFASetup {
    pub fn new(secret: &str) -> Self {
        Self(secret.to_owned())
    }

    /// Generate the caches redis key
    fn key(registered_user_id: UserId) -> String {
        RedisKey::TwoFASetup(registered_user_id).to_string()
    }

    // Insert new twofa secret & set ttl od 2 minutes
    pub async fn insert(&self, redis: &AMRedis, user: &ModelUser) -> Result<&Self, ApiError> {
        let key = Self::key(user.registered_user_id);
        let session = serde_json::to_string(&self)?;
        redis.lock().await.hset(&key, HASH_FIELD, session).await?;
        redis.lock().await.expire(&key, 120).await?;
        Ok(self)
    }

    /// Delete twofa secret
    pub async fn delete(redis: &AMRedis, user: &ModelUser) -> Result<(), ApiError> {
        Ok(redis
            .lock()
            .await
            .del::<String, ()>(Self::key(user.registered_user_id))
            .await?)
    }

    /// get twofa setup secret
    pub async fn get(redis: &AMRedis, user: &ModelUser) -> Result<Option<Self>, ApiError> {
        Ok(redis
            .lock()
            .await
            .hget::<String, &str, Option<Self>>(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }

    /// Check twofa setup secret is in cache or not
    pub async fn exists(redis: &AMRedis, user: &ModelUser) -> Result<bool, ApiError> {
        Ok(redis
            .lock()
            .await
            .hexists::<String, &str, bool>(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }
}

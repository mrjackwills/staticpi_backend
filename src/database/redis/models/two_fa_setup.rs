use redis::{aio::ConnectionManager, AsyncCommands, FromRedisValue, RedisResult, Value};
use serde::{Deserialize, Serialize};

use crate::{
    api_error::ApiError,
    database::{
        new_types::UserId,
        redis::{string_to_struct, RedisKey, HASH_FIELD},
        user::ModelUser,
    },
};

impl FromRedisValue for RedisTwoFASetup {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisTwoFASetup(String);

impl RedisTwoFASetup {
    pub fn value(&self) -> &str {
        self.0.as_str()
    }

    pub fn new(secret: &str) -> Self {
        Self(secret.to_owned())
    }

    /// Generate the caches redis key
    fn key(registered_user_id: UserId) -> String {
        RedisKey::TwoFASetup(registered_user_id).to_string()
    }

    // Insert new twofa secret & set ttl od 2 minutes
    pub async fn insert(
        &self,
        redis: &mut ConnectionManager,
        user: &ModelUser,
    ) -> Result<&Self, ApiError> {
        let key = Self::key(user.registered_user_id);
        let session = serde_json::to_string(&self)?;
        {
            redis.hset(&key, HASH_FIELD, session).await?;
            redis.expire(&key, 120).await?;
        }
        Ok(self)
    }

    /// Delete twofa secret
    pub async fn delete(redis: &mut ConnectionManager, user: &ModelUser) -> Result<(), ApiError> {
        Ok(redis
            .del::<String, ()>(Self::key(user.registered_user_id))
            .await?)
    }

    /// get twofa setup secret
    pub async fn get(
        redis: &mut ConnectionManager,
        user: &ModelUser,
    ) -> Result<Option<Self>, ApiError> {
        Ok(redis
            .hget::<String, &str, Option<Self>>(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }

    /// Check twofa setup secret is in cache or not
    pub async fn exists(redis: &mut ConnectionManager, user: &ModelUser) -> Result<bool, ApiError> {
        Ok(redis
            .hexists::<String, &str, bool>(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }
}

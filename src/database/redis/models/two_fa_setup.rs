use fred::{
    clients::RedisPool,
    interfaces::{HashesInterface, KeysInterface},
};
use serde::{Deserialize, Serialize};

use crate::{
    api_error::ApiError,
    database::{
        gen_hashmap,
        new_types::UserId,
        redis::{RedisKey, HASH_FIELD},
        user::ModelUser,
    },
    redis_hash_to_struct,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisTwoFASetup(String);

redis_hash_to_struct!(RedisTwoFASetup);

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
    pub async fn insert(&self, redis: &RedisPool, user: &ModelUser) -> Result<&Self, ApiError> {
        let key = Self::key(user.registered_user_id);
        let session = serde_json::to_string(&self)?;
        redis.hset(&key, gen_hashmap(session)).await?;
        redis.expire(&key, 120).await?;
        Ok(self)
    }

    /// Delete twofa secret
    pub async fn delete(redis: &RedisPool, user: &ModelUser) -> Result<(), ApiError> {
        Ok(redis.del(Self::key(user.registered_user_id)).await?)
    }

    /// get twofa setup secret
    pub async fn get(redis: &RedisPool, user: &ModelUser) -> Result<Option<Self>, ApiError> {
        Ok(redis
            .hget(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }

    /// Check twofa setup secret is in cache or not
    pub async fn exists(redis: &RedisPool, user: &ModelUser) -> Result<bool, ApiError> {
        Ok(redis
            .hexists::<bool, String, &str>(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }
}

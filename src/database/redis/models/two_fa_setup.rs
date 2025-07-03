use fred::{
    clients::Pool,
    interfaces::{HashesInterface, KeysInterface},
};
use serde::{Deserialize, Serialize};

use crate::{
    S,
    api_error::ApiError,
    database::{
        new_types::UserId,
        redis::{HASH_FIELD, RedisKey},
        user::ModelUser,
    },
    hmap, redis_hash_to_struct,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisTwoFASetup(String);

redis_hash_to_struct!(RedisTwoFASetup);

impl RedisTwoFASetup {
    pub const fn value(&self) -> &str {
        self.0.as_str()
    }

    pub fn new(secret: &str) -> Self {
        Self(S!(secret))
    }

    /// Generate the caches redis key
    fn key(registered_user_id: UserId) -> String {
        RedisKey::TwoFASetup(registered_user_id).to_string()
    }

    // Insert new twofa secret & set ttl of 2 minutes
    pub async fn insert(&self, redis: &Pool, user: &ModelUser) -> Result<&Self, ApiError> {
        let key = Self::key(user.registered_user_id);
        let session = serde_json::to_string(&self)?;
        redis.hset::<(), _, _>(&key, hmap!(session)).await?;
        redis.expire::<(), _>(&key, 120, None).await?;
        Ok(self)
    }

    /// Delete twofa secret
    pub async fn delete(redis: &Pool, user: &ModelUser) -> Result<(), ApiError> {
        Ok(redis.del(Self::key(user.registered_user_id)).await?)
    }

    /// get twofa setup secret
    pub async fn get(redis: &Pool, user: &ModelUser) -> Result<Option<Self>, ApiError> {
        Ok(redis
            .hget(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }

    /// Check twofa setup secret is in cache or not
    pub async fn exists(redis: &Pool, user: &ModelUser) -> Result<bool, ApiError> {
        Ok(redis
            .hexists::<bool, String, &str>(Self::key(user.registered_user_id), HASH_FIELD)
            .await?)
    }
}

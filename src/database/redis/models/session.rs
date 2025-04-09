use fred::{
    clients::Pool,
    interfaces::{HashesInterface, KeysInterface, SetsInterface},
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use ulid::Ulid;

use crate::{
    S,
    api_error::ApiError,
    database::{
        admin::AdminSession,
        new_types::UserId,
        redis::{HASH_FIELD, RedisKey},
        user::ModelUser,
    },
    hmap, redis_hash_to_struct,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisSession {
    pub registered_user_id: UserId,
    pub email: String,
    pub timestamp: Timestamp,
}

redis_hash_to_struct!(RedisSession);

impl RedisSession {
    pub fn new(registered_user_id: UserId, email: &str) -> Self {
        Self {
            registered_user_id,
            email: S!(email),
            timestamp: Timestamp::now(),
        }
    }

    /// Generate redis key
    fn key_session(ulid: &Ulid) -> String {
        RedisKey::Session(ulid).to_string()
    }

    /// Generate redis key
    fn key_session_set(registered_user_id: UserId) -> String {
        RedisKey::SessionSet(registered_user_id).to_string()
    }

    pub async fn admin_get_all(
        redis: &Pool,
        registered_user_id: UserId,
    ) -> Result<Vec<AdminSession>, ApiError> {
        let key_session_set = Self::key_session_set(registered_user_id);
        let session_keys: Vec<String> = redis.smembers(&key_session_set).await?;
        let mut output = vec![];
        for key in session_keys {
            if let Some(session) = redis
                .hget::<Option<Self>, &str, &str>(key.as_str(), HASH_FIELD)
                .await?
            {
                let ttl = redis.ttl(&key).await?;
                output.push(AdminSession {
                    key,
                    ttl,
                    timestamp: session.timestamp.as_second(),
                });
            }
        }

        Ok(output)
    }

    /// Insert new session & set ttl
    pub async fn insert(&self, redis: &Pool, ttl: i64, ulid: Ulid) -> Result<(), ApiError> {
        let key_session = Self::key_session(&ulid);
        let session = serde_json::to_string(&self)?;
        let key_session_set = Self::key_session_set(self.registered_user_id);

        redis.hset::<(), _, _>(&key_session, hmap!(session)).await?;
        redis
            .sadd::<(), _, _>(&key_session_set, &key_session)
            .await?;
        // This won't work as expected, should set TTL to the max at all times
        // redis.expire(&key_session_set, ttl).await?;
        Ok(redis.expire(&key_session, ttl, None).await?)
    }

    /// Delete session
    pub async fn delete(redis: &Pool, ulid: &Ulid) -> Result<(), ApiError> {
        let key_session = Self::key_session(ulid);
        if let Some(session) = redis
            .hget::<Option<Self>, &str, &str>(&key_session, HASH_FIELD)
            .await?
        {
            let key_session_set = Self::key_session_set(session.registered_user_id);
            redis
                .srem::<(), _, _>(&key_session_set, &key_session)
                .await?;

            // Need to test this!
            if redis
                .smembers::<Vec<String>, &str>(&key_session_set)
                .await?
                .is_empty()
            {
                redis.del::<(), _>(&key_session_set).await?;
            }
        }
        Ok(redis.del(&key_session).await?)
    }

    /// Delete all sessions for a single user - used when setting a user active status to false, or password reset!
    pub async fn delete_all(redis: &Pool, registered_user_id: UserId) -> Result<(), ApiError> {
        let key_session_set = Self::key_session_set(registered_user_id);

        let session_set: Vec<String> = redis.smembers(&key_session_set).await?;
        for key in session_set {
            redis.del::<(), _>(key).await?;
        }
        Ok(redis.del(&key_session_set).await?)
    }

    /// Delete all sessions for a single user, except for current sessions, used when changing password
    pub async fn delete_all_except_current(
        redis: &Pool,
        registered_user_id: UserId,
        current_session: Ulid,
    ) -> Result<(), ApiError> {
        let session_set_key = Self::key_session_set(registered_user_id);
        let all_keys = redis
            .smembers::<Vec<String>, &str>(&session_set_key)
            .await?;
        for key in all_keys {
            if current_session.to_string() == key.split_once("::").unwrap_or_default().1 {
                continue;
            }
            redis.del::<(), _>(&key).await?;
            redis.srem::<(), _, _>(&session_set_key, key).await?;
        }
        Ok(())
    }

    /// Convert a session into a `ModelUser` object
    pub async fn get(
        redis: &Pool,
        postgres: &PgPool,
        ulid: &Ulid,
    ) -> Result<Option<ModelUser>, ApiError> {
        let key_session = Self::key_session(ulid);
        match redis
            .hget::<Option<Self>, &str, &str>(&key_session, HASH_FIELD)
            .await?
        {
            Some(session) => {
                let user = ModelUser::get(postgres, &session.email).await?;
                // If, for some reason, user isn't in postgres, delete session
                if user.is_none() {
                    Self::delete(redis, ulid).await?;
                }
                Ok(user)
            }
            _ => Ok(None),
        }
    }
    /// Check session exists in redis
    pub async fn exists(redis: &Pool, ulid: &Ulid) -> Result<Option<Self>, ApiError> {
        Ok(redis.hget(Self::key_session(ulid), HASH_FIELD).await?)
    }
}

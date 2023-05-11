use redis::{AsyncCommands, FromRedisValue, RedisResult, Value};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use ulid::Ulid;

use crate::{
    api_error::ApiError,
    database::{
        admin::AdminSession,
        new_types::UserId,
        redis::{string_to_struct, RedisKey, HASH_FIELD},
        user::ModelUser,
    },
    servers::AMRedis,
};

impl FromRedisValue for RedisSession {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisSession {
    pub registered_user_id: UserId,
    pub email: String,
    pub timestamp: i64,
}

impl RedisSession {
    pub fn new(registered_user_id: UserId, email: &str) -> Self {
        Self {
            registered_user_id,
            email: email.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
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
        redis: &AMRedis,
        registered_user_id: UserId,
    ) -> Result<Vec<AdminSession>, ApiError> {
        let key_session_set = Self::key_session_set(registered_user_id);
        let session_keys: Vec<String> = redis.lock().await.smembers(&key_session_set).await?;
        let mut output = vec![];
        for key in session_keys {
            let op_session = redis
                .lock()
                .await
                .hget::<&String, &str, Option<Self>>(&key, HASH_FIELD)
                .await?;

            if let Some(session) = op_session {
                let ttl: u64 = redis.lock().await.ttl(&key).await?;
                output.push(AdminSession {
                    key,
                    ttl,
                    timestamp: session.timestamp,
                });
            }
        }

        Ok(output)
    }

    /// Insert new session & set ttl
    pub async fn insert(&self, redis: &AMRedis, ttl: Duration, ulid: Ulid) -> Result<(), ApiError> {
        let key_session = Self::key_session(&ulid);
        let session = serde_json::to_string(&self)?;
        let key_session_set = Self::key_session_set(self.registered_user_id);

        let ttl = usize::try_from(ttl.whole_seconds()).unwrap_or(60);

        let mut redis = redis.lock().await;
        redis.hset(&key_session, HASH_FIELD, session).await?;
        redis.sadd(&key_session_set, &key_session).await?;
        redis.expire(&key_session_set, ttl).await?;
        Ok(redis.expire(&key_session, ttl).await?)
    }

    // On any setting change, need to make sure to update session
    // pub async fn update(&self, redis: &AMRedis, ulid: Ulid) -> Result<(), ApiError> {
    //     let key = RedisKey::Session(&ulid);
    //     let session = serde_json::to_string(&self)?;
    //     redis.lock().await.set(key.to_string(), session).await?;
    //     Ok(())
    // }

    /// Delete session
    pub async fn delete(redis: &AMRedis, ulid: &Ulid) -> Result<(), ApiError> {
        let key_session = Self::key_session(ulid);
        let mut redis = redis.lock().await;

        if let Some(session) = redis
            .hget::<&str, &str, Option<Self>>(&key_session, HASH_FIELD)
            .await?
        {
            let key_session_set = Self::key_session_set(session.registered_user_id);
            redis.srem(&key_session_set, &key_session).await?;

            // Need to test this!
            if redis
                .smembers::<&str, Vec<String>>(&key_session_set)
                .await?
                .is_empty()
            {
                redis.del(&key_session_set).await?;
            }
        }
        Ok(redis.del(&key_session).await?)
    }

    /// Delete all sessions for a single user - used when setting a user active status to false, or password reset!
    pub async fn delete_all(redis: &AMRedis, registered_user_id: UserId) -> Result<(), ApiError> {
        let key_session_set = Self::key_session_set(registered_user_id);

        let mut redis = redis.lock().await;

        let session_set: Vec<String> = redis.smembers(&key_session_set).await?;
        for key in session_set {
            redis.del(key).await?;
        }
        Ok(redis.del(&key_session_set).await?)
    }

    /// Convert a session into a `ModelUser` object
    pub async fn get(
        redis: &AMRedis,
        postgres: &PgPool,
        ulid: &Ulid,
    ) -> Result<Option<ModelUser>, ApiError> {
        let key_session = Self::key_session(ulid);

        let op_session: Option<Self> = redis.lock().await.hget(&key_session, HASH_FIELD).await?;
        if let Some(session) = op_session {
            // If, for some reason, user isn't in postgres, delete session before returning None
            let user = ModelUser::get(postgres, &session.email).await?;
            if user.is_none() {
                Self::delete(redis, ulid).await?;
            }
            Ok(user)
        } else {
            Ok(None)
        }
    }
    /// Check session exists in redis
    pub async fn exists(redis: &AMRedis, ulid: &Ulid) -> Result<Option<Self>, ApiError> {
        Ok(redis
            .lock()
            .await
            .hget(Self::key_session(ulid), HASH_FIELD)
            .await?)
    }
}

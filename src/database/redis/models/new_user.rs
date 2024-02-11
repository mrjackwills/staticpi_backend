use fred::{
    clients::RedisPool,
    interfaces::{HashesInterface, KeysInterface},
};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    api_error::ApiError, argon::ArgonHash, database::{
        email_address::ModelEmailAddress,
        ip_user_agent::ModelUserAgentIp,
        new_types::{EmailAddressId, IpId, UserAgentId},
        redis::{RedisKey, HASH_FIELD},
    }, hmap, redis_hash_to_struct
};


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisNewUser {
    pub email: String,
    pub email_address_id: EmailAddressId,
    pub full_name: String,
    pub password_hash: String,
    pub ip_id: IpId,
    pub user_agent_id: UserAgentId,
}

redis_hash_to_struct!(RedisNewUser);

impl RedisNewUser {
    /// one hour
    pub const TTL_AS_SEC: u16 = 60 * 60;

    pub fn new(
        email: &ModelEmailAddress,
        name: &str,
        password_hash: &ArgonHash,
        req: &ModelUserAgentIp,
    ) -> Self {
        Self {
            email: email.email.clone(),
            email_address_id: email.email_address_id,
            full_name: name.to_owned(),
            password_hash: password_hash.to_string(),
            ip_id: req.ip_id,
            user_agent_id: req.user_agent_id,
        }
    }

    /// Generate redis key for the secret
    fn key_secret(ulid: &Ulid) -> String {
        RedisKey::VerifySecret(ulid).to_string()
    }

    /// Generate redis key for the email
    fn key_email(email: &str) -> String {
        RedisKey::VerifyEmail(email).to_string()
    }

    /// On register, insert a new user into redis cache, to be inserted into postgres once verify email responded to
    pub async fn insert(&self, redis: &RedisPool, ulid: &Ulid) -> Result<(), ApiError> {
        let key_secret = Self::key_secret(ulid);
        let key_email = Self::key_email(&self.email);

        let new_user_as_string = serde_json::to_string(&self)?;

        redis
            .hset(&key_email, hmap!(ulid.to_string()))
            .await?;
        redis.expire(key_email, Self::TTL_AS_SEC.into()).await?;
        redis
            .hset(&key_secret, hmap!(new_user_as_string))
            .await?;
        Ok(redis.expire(key_secret, Self::TTL_AS_SEC.into()).await?)
    }

    /// Remove both verify keys from redis
    pub async fn delete(&self, redis: &RedisPool, ulid: &Ulid) -> Result<(), ApiError> {
        redis.del(Self::key_secret(ulid)).await?;
        Ok(redis.del(Self::key_email(&self.email)).await?)
    }

    /// Just check if a email is in redis cache, so that if a user has register but not yet verified, cannot sign up again
    /// Static method, as want to use before one creates a `NewUser` struct
    /// THIS ONE NEEDS TO BE mut redis rather than redis: &mut
    pub async fn exists(redis: &RedisPool, email: &str) -> Result<bool, ApiError> {
        Ok(redis.hexists(Self::key_email(email), HASH_FIELD).await?)
    }

    /// Verify a new account, secret emailed to user, user visits url with secret as a param
    pub async fn get(redis: &RedisPool, ulid: &Ulid) -> Result<Option<Self>, ApiError> {
        Ok(redis.hget(Self::key_secret(ulid), HASH_FIELD).await?)
    }
}

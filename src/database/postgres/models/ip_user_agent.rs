use redis::AsyncCommands;
use std::net::{IpAddr, SocketAddr};

use axum::{
    async_trait,
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::request::Parts,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Transaction, Postgres};

use crate::{
    api_error::ApiError,
    database::{redis::RedisKey, HASH_FIELD},
    servers::{get_ip, get_user_agent_header, AMRedis, ApplicationState},
};

use super::new_types::{IpId, UserAgentId};

#[derive(Debug, Clone)]
pub struct ReqUserAgentIp {
    pub user_agent: String,
    pub ip: IpAddr,
}

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Ip {
    ip_id: IpId,
}

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Useragent {
    user_agent_id: UserAgentId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelUserAgentIp {
    pub user_agent_id: UserAgentId,
    pub user_agent: String,
    pub ip_id: IpId,
    pub ip: IpAddr,
}

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DeleteIp {
    pub ip: IpAddr,
}
#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DeleteUserAgent {
    pub user_agent: String,
}

impl ModelUserAgentIp {
    /// Search for ip_addresses that are not longer referenced anywhere, delete, and also remove from redis cache
    pub async fn delete_ip(
        transaction: &mut Transaction<'_, Postgres>,
        redis: &AMRedis,
    ) -> Result<(), ApiError> {
        let query = r"
DELETE
FROM ip_address
WHERE ip_id
IN (
	SELECT ip_address.ip_id
	FROM ip_address
	LEFT JOIN api_key USING(ip_id)
	LEFT JOIN connection USING(ip_id)
	LEFT JOIN device USING(ip_id)
	LEFT JOIN login_history USING(ip_id)
	LEFT JOIN password_reset USING(ip_id)
	LEFT JOIN registered_user USING(ip_id)
	LEFT JOIN two_fa_backup USING(ip_id)
	LEFT JOIN two_fa_secret USING(ip_id)
	WHERE api_key.ip_id IS NULL
	AND connection.ip_id IS NULL
	AND device.ip_id IS NULL
	AND login_history.ip_id IS NULL
	AND password_reset.ip_id IS NULL
	AND registered_user.ip_id IS NULL
	AND two_fa_backup.ip_id IS NULL
	AND two_fa_secret.ip_id IS NULL
)
RETURNING ip_address.ip;";
        let ips = sqlx::query_as::<_, DeleteIp>(query)
            .fetch_all(&mut **transaction)
            .await?;

        for i in ips {
            redis
                .lock()
                .await
                .del(RedisKey::CacheIp(i.ip).to_string())
                .await?;
        }
        Ok(())
    }

    /// Search for user_agent's that are not longer referenced anywhere, delete, and also remove from redis cache
    pub async fn delete_useragent(
        transaction: &mut Transaction<'_, Postgres>,
        redis: &AMRedis,
    ) -> Result<(), ApiError> {
        let query = "
DELETE FROM user_agent
WHERE user_agent_id
IN (
	SELECT user_agent.user_agent_id
	FROM user_agent
	LEFT JOIN api_key USING(user_agent_id)
	LEFT JOIN device USING(user_agent_id)
	LEFT JOIN login_history USING(user_agent_id)
	LEFT JOIN password_reset USING(user_agent_id)
	LEFT JOIN registered_user USING(user_agent_id)
	LEFT JOIN two_fa_backup USING(user_agent_id)
	LEFT JOIN two_fa_secret USING(user_agent_id)
	WHERE api_key.ip_id IS NULL
	AND device.user_agent_id IS NULL
	AND login_history.user_agent_id IS NULL
	AND password_reset.user_agent_id IS NULL
	AND registered_user.user_agent_id IS NULL
	AND two_fa_backup.user_agent_id IS NULL
	AND two_fa_secret.user_agent_id IS NULL
)
RETURNING user_agent.user_agent_string AS user_agent";
        let user_agents = sqlx::query_as::<_, DeleteUserAgent>(query)
            .fetch_all(&mut **transaction)
            .await?;
        for i in user_agents {
            redis
                .lock()
                .await
                .del(RedisKey::CacheUseragent(&i.user_agent).to_string())
                .await?;
        }
        Ok(())
    }

    async fn insert_cache(&self, redis: &AMRedis) -> Result<(), ApiError> {
        let ip_key = RedisKey::CacheIp(self.ip).to_string();
        let user_agent_key = RedisKey::CacheUseragent(&self.user_agent).to_string();

        redis
            .lock()
            .await
            .hset(ip_key, HASH_FIELD, self.ip_id.get())
            .await?;
        Ok(redis
            .lock()
            .await
            .hset(user_agent_key, HASH_FIELD, self.user_agent_id.get())
            .await?)
    }

    async fn get_cache(
        redis: &AMRedis,
        ip: IpAddr,
        user_agent: &str,
    ) -> Result<Option<Self>, ApiError> {
        let ip_key = RedisKey::CacheIp(ip).to_string();
        let user_agent_key = RedisKey::CacheUseragent(user_agent).to_string();

        let mut redis = redis.lock().await;
        if let (Some(ip_id), Some(user_agent_id)) = (
            redis.hget(ip_key, HASH_FIELD).await?,
            redis.hget(user_agent_key, HASH_FIELD).await?,
        ) {
            Ok(Some(Self {
                ip,
                user_agent: user_agent.to_owned(),
                ip_id,
                user_agent_id,
            }))
        } else {
            Ok(None)
        }
    }

    /// Have to cast as inet in the query, until sqlx gets updated
    /// get `ip_id`
    async fn get_ip_id(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Option<Ip>, sqlx::Error> {
        let query = "SELECT ip_id from ip_address WHERE ip = $1::inet";
        sqlx::query_as::<_, Ip>(query)
            .bind(req.ip.to_string())
            .fetch_optional(&mut **transaction)
            .await
    }

    /// Have to cast as inet in the query, until sqlx gets updated
    /// Insert ip into postgres
    async fn insert_ip(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Ip, sqlx::Error> {
        let query = "INSERT INTO ip_address(ip) VALUES ($1::inet) RETURNING ip_id";
        sqlx::query_as::<_, Ip>(query)
            .bind(req.ip.to_string())
            .fetch_one(&mut **transaction)
            .await
    }

    /// get `user_agent_id`
    async fn get_user_agent(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Option<Useragent>, sqlx::Error> {
        let query = "SELECT user_agent_id from user_agent WHERE user_agent_string = $1";
        sqlx::query_as::<_, Useragent>(query)
            .bind(req.user_agent.clone())
            .fetch_optional(&mut **transaction)
            .await
    }

    /// Insert useragent into postgres
    async fn insert_user_agent(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Useragent, sqlx::Error> {
        let query = "INSERT INTO user_agent(user_agent_string) VALUES ($1) RETURNING user_agent_id";
        sqlx::query_as::<_, Useragent>(query)
            .bind(req.user_agent.clone())
            .fetch_one(&mut **transaction)
            .await
    }

    /// get `ip_id` and `user_agent_id`
    pub async fn get(
        postgres: &PgPool,
        redis: &AMRedis,
        req: &ReqUserAgentIp,
    ) -> Result<Self, ApiError> {
        if let Some(cache) = Self::get_cache(redis, req.ip, &req.user_agent).await? {
            return Ok(cache);
        }

        let mut transaction = postgres.begin().await?;
        let ip_id = if let Some(ip) = Self::get_ip_id(&mut transaction, req).await? {
            ip
        } else {
            Self::insert_ip(&mut transaction, req).await?
        };
        let user_agent_id =
            if let Some(user_agent) = Self::get_user_agent(&mut transaction, req).await? {
                user_agent
            } else {
                Self::insert_user_agent(&mut transaction, req).await?
            };
        transaction.commit().await?;

        let output = Self {
            user_agent: req.user_agent.clone(),
            ip: req.ip,
            user_agent_id: user_agent_id.user_agent_id,
            ip_id: ip_id.ip_id,
        };

        output.insert_cache(redis).await?;

        Ok(output)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ModelUserAgentIp
where
    ApplicationState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = ApplicationState::from_ref(state);

        let addr = ConnectInfo::<SocketAddr>::from_request_parts(parts, &state).await?;
        let useragent_ip = ReqUserAgentIp {
            user_agent: get_user_agent_header(&parts.headers),
            ip: get_ip(&parts.headers, addr),
        };
        Ok(Self::get(&state.postgres, &state.redis, &useragent_ip).await?)
    }
}

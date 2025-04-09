use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::request::Parts,
};
use fred::{
    clients::Pool,
    interfaces::{HashesInterface, KeysInterface},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction, types::ipnetwork::IpNetwork};

use crate::{
    C, S,
    api_error::ApiError,
    database::{HASH_FIELD, redis::RedisKey},
    hmap,
    servers::{ApplicationState, get_ip, get_user_agent_header},
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
        redis: &Pool,
    ) -> Result<(), ApiError> {
        let query = r"
DELETE FROM
    ip_address
WHERE
    ip_id IN (
        SELECT
            ip_address.ip_id
        FROM
            ip_address
            LEFT JOIN api_key USING(ip_id)
            LEFT JOIN connection USING(ip_id)
            LEFT JOIN device USING(ip_id)
            LEFT JOIN email_log USING(ip_id)
            LEFT JOIN invite_code USING(ip_id)
            LEFT JOIN login_history USING(ip_id)
            LEFT JOIN password_reset USING(ip_id)
            LEFT JOIN registered_user USING(ip_id)
            LEFT JOIN two_fa_backup USING(ip_id)
            LEFT JOIN two_fa_secret USING(ip_id)
        WHERE
            api_key.ip_id IS NULL
            AND connection.ip_id IS NULL
            AND device.ip_id IS NULL
            AND email_log.ip_id IS NULL
            AND invite_code.ip_id IS NULL
            AND login_history.ip_id IS NULL
            AND password_reset.ip_id IS NULL
            AND registered_user.ip_id IS NULL
            AND two_fa_backup.ip_id IS NULL
            AND two_fa_secret.ip_id IS NULL
    ) RETURNING ip_address.ip";
        let ips = sqlx::query_as::<_, DeleteIp>(query)
            .fetch_all(&mut **transaction)
            .await?;

        for i in ips {
            redis
                .del::<(), _>(RedisKey::CacheIp(i.ip).to_string())
                .await?;
        }
        Ok(())
    }

    /// Search for user_agent's that are not longer referenced anywhere, delete, and also remove from redis cache
    pub async fn delete_useragent(
        transaction: &mut Transaction<'_, Postgres>,
        redis: &Pool,
    ) -> Result<(), ApiError> {
        let query = "
DELETE FROM
    user_agent
WHERE
    user_agent_id IN (
        SELECT
            user_agent.user_agent_id
        FROM
            user_agent
            LEFT JOIN api_key USING(user_agent_id)
            LEFT JOIN connection USING(user_agent_id)
            LEFT JOIN device USING(user_agent_id)
            LEFT JOIN email_log USING(user_agent_id)
            LEFT JOIN invite_code USING(user_agent_id)
            LEFT JOIN login_history USING(user_agent_id)
            LEFT JOIN password_reset USING(user_agent_id)
            LEFT JOIN registered_user USING(user_agent_id)
            LEFT JOIN two_fa_backup USING(user_agent_id)
            LEFT JOIN two_fa_secret USING(user_agent_id)
        WHERE
            api_key.ip_id IS NULL
            AND connection.user_agent_id IS NULL
            AND device.user_agent_id IS NULL
            AND email_log.user_agent_id IS NULL
            AND invite_code.user_agent_id IS NULL
            AND login_history.user_agent_id IS NULL
            AND password_reset.user_agent_id IS NULL
            AND registered_user.user_agent_id IS NULL
            AND two_fa_backup.user_agent_id IS NULL
            AND two_fa_secret.user_agent_id IS NULL
    ) RETURNING user_agent.user_agent_string AS user_agent";
        let user_agents = sqlx::query_as::<_, DeleteUserAgent>(query)
            .fetch_all(&mut **transaction)
            .await?;
        for i in user_agents {
            redis
                .del::<(), _>(RedisKey::CacheUseragent(&i.user_agent).to_string())
                .await?;
        }
        Ok(())
    }

    async fn insert_cache(&self, redis: &Pool) -> Result<(), ApiError> {
        let ip_key = RedisKey::CacheIp(self.ip).to_string();
        let user_agent_key = RedisKey::CacheUseragent(&self.user_agent).to_string();

        redis
            .hset::<(), _, _>(ip_key, hmap!(self.ip_id.get()))
            .await?;
        Ok(redis
            .hset(user_agent_key, hmap!(self.user_agent_id.get()))
            .await?)
    }

    async fn get_cache(
        redis: &Pool,
        ip: IpAddr,
        user_agent: &str,
    ) -> Result<Option<Self>, ApiError> {
        let ip_key = RedisKey::CacheIp(ip).to_string();
        let user_agent_key = RedisKey::CacheUseragent(user_agent).to_string();

        match (
            redis.hget(ip_key, HASH_FIELD).await?,
            redis.hget(user_agent_key, HASH_FIELD).await?,
        ) {
            (Some(ip_id), Some(user_agent_id)) => Ok(Some(Self {
                ip,
                user_agent: S!(user_agent),
                ip_id,
                user_agent_id,
            })),
            _ => Ok(None),
        }
    }

    /// Have to cast as inet in the query, until sqlx gets updated
    /// get `ip_id`
    async fn get_ip_id(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Option<Ip>, sqlx::Error> {
        sqlx::query_as!(
            Ip,
            "
SELECT
    ip_id
FROM
    ip_address
WHERE
    ip = $1",
            IpNetwork::from(req.ip)
        )
        .fetch_optional(&mut **transaction)
        .await
    }

    /// Have to cast as inet in the query, until sqlx gets updated
    /// Insert ip into postgres
    async fn insert_ip(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Ip, sqlx::Error> {
        sqlx::query_as!(
            Ip,
            "INSERT INTO
    ip_address(ip)
VALUES
    ($1)
RETURNING
    ip_id",
            IpNetwork::from(req.ip)
        )
        .fetch_one(&mut **transaction)
        .await
    }

    /// get `user_agent_id`
    async fn get_user_agent(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Option<Useragent>, sqlx::Error> {
        sqlx::query_as!(
            Useragent,
            "SELECT
    user_agent_id
FROM
    user_agent
WHERE
    user_agent_string = $1",
            req.user_agent
        )
        .fetch_optional(&mut **transaction)
        .await
    }

    /// Insert useragent into postgres
    async fn insert_user_agent(
        transaction: &mut Transaction<'_, Postgres>,
        req: &ReqUserAgentIp,
    ) -> Result<Useragent, sqlx::Error> {
        sqlx::query_as!(
            Useragent,
            "
INSERT INTO
    user_agent(user_agent_string)
VALUES
    ($1)
RETURNING
    user_agent_id",
            &req.user_agent
        )
        .fetch_one(&mut **transaction)
        .await
    }

    /// get `ip_id` and `user_agent_id`
    pub async fn get(
        postgres: &PgPool,
        redis: &Pool,
        req: &ReqUserAgentIp,
    ) -> Result<Self, ApiError> {
        if let Some(cache) = Self::get_cache(redis, req.ip, &req.user_agent).await? {
            return Ok(cache);
        }

        let mut transaction = postgres.begin().await?;
        let ip_id = match Self::get_ip_id(&mut transaction, req).await? {
            Some(ip) => ip,
            _ => Self::insert_ip(&mut transaction, req).await?,
        };
        let user_agent_id = match Self::get_user_agent(&mut transaction, req).await? {
            Some(user_agent) => user_agent,
            _ => Self::insert_user_agent(&mut transaction, req).await?,
        };
        transaction.commit().await?;

        let output = Self {
            user_agent: C!(req.user_agent),
            ip: req.ip,
            user_agent_id: user_agent_id.user_agent_id,
            ip_id: ip_id.ip_id,
        };
        output.insert_cache(redis).await?;
        Ok(output)
    }
}

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
        Self::get(&state.postgres, &state.redis, &useragent_ip).await
    }
}

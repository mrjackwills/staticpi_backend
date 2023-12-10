use redis::{AsyncCommands, FromRedisValue, RedisResult, Value};
use serde::{Deserialize, Serialize};

use sqlx::PgPool;

use crate::{
    api_error::ApiError,
    database::{string_to_struct, RedisKey, HASH_FIELD},
    servers::AMRedis,
};

use super::new_types::{DeviceId, UserId};

#[derive(sqlx::FromRow, Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ModelMonthlyBandwidth {
    pub size_in_bytes: i64,
    registered_user_id: UserId,
}

impl FromRedisValue for ModelMonthlyBandwidth {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

impl ModelMonthlyBandwidth {
    async fn get_cache(
        redis: &AMRedis,
        registered_user_id: UserId,
    ) -> Result<Option<Self>, ApiError> {
        Ok(redis
            .lock()
            .await
            .hget(
                RedisKey::CacheMonthlyBandwidth(registered_user_id).to_string(),
                HASH_FIELD,
            )
            .await?)
    }

    async fn insert_cache(&self, redis: &AMRedis) -> Result<(), ApiError> {
        let key = RedisKey::CacheMonthlyBandwidth(self.registered_user_id).to_string();
        redis
            .lock()
            .await
            .hset(&key, HASH_FIELD, serde_json::to_string(&self)?)
            .await?;
        Ok(redis.lock().await.expire(&key, 30).await?)
    }

    /// Force update monthly bandwidth redis cache, derive user_id from device_id
    pub async fn force_update_cache(
        postgres: &PgPool,
        redis: &AMRedis,
        device_id: DeviceId,
    ) -> Result<(), ApiError> {
        let query = r"

SELECT
    COALESCE(SUM(hb.size_in_bytes), 0)::BIGINT AS size_in_bytes, ru.registered_user_id
FROM
    hourly_bandwidth hb
LEFT JOIN device de USING(device_id)
LEFT JOIN
    registered_user ru
ON 
    ru.registered_user_id = de.registered_user_id
WHERE
    extract(year from hb.timestamp) = extract (year from CURRENT_DATE)
AND
    extract(month from hb.timestamp) = extract (month from CURRENT_DATE)
AND
    hb.is_counted = TRUE
AND
    ru.registered_user_id = (
        SELECT
            ru.registered_user_id
        FROM
            device de
			LEFT JOIN registered_user ru USING(registered_user_id)
        WHERE
            device_id = $1
    )
GROUP BY
    ru.registered_user_id;";
        if let Some(bandwidth) = sqlx::query_as::<_, Self>(query)
            .bind(device_id.get())
            .fetch_optional(postgres)
            .await?
        {
            bandwidth.insert_cache(redis).await?;
        }
        Ok(())
    }

    /// Get a users monthly bandwidth, check redis cache before hitting postgres
    pub async fn get(
        postgres: &PgPool,
        redis: &AMRedis,
        registered_user_id: UserId,
    ) -> Result<Option<Self>, ApiError> {
        if let Some(cache) = Self::get_cache(redis, registered_user_id).await? {
            return Ok(Some(cache));
        }
        let query = r"
SELECT
    hb.size_in_bytes::BIGINT AS size_in_bytes, $1 AS registered_user_id
FROM
    hourly_bandwidth hb
LEFT JOIN device de USING(device_id)
LEFT JOIN
    registered_user ru
ON
    ru.registered_user_id = de.registered_user_id
WHERE
    extract(year from hb.timestamp) = extract (year from CURRENT_DATE)
AND
    extract(month from hb.timestamp) = extract (month from CURRENT_DATE)
AND
    hb.is_counted = TRUE
AND
    ru.registered_user_id = $1";

        if let Some(bandwidth) = sqlx::query_as::<_, Self>(query)
            .bind(registered_user_id.get())
            .fetch_optional(postgres)
            .await?
        {
            bandwidth.insert_cache(redis).await?;
            Ok(Some(bandwidth))
        } else {
            Ok(None)
        }
    }
}

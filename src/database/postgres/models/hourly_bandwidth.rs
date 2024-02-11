use super::{monthly_bandwidth::ModelMonthlyBandwidth, new_types::DeviceId};
use crate::connections::ConnectionType;

use fred::clients::RedisPool;
use sqlx::PgPool;
use tracing::error;

pub struct ModelHourlyBandwidth;

impl ModelHourlyBandwidth {
    /// Insert bandwidth count, done on it's own thread,
    /// Will only execute if msg_size > 0,
    /// Also update monthly bandwidth cache
    pub fn insert(
        device_id: DeviceId,
        device_type: ConnectionType,
        // Maybe - change to enum
        is_counted: bool,
        msg_size: usize,
        postgres: &PgPool,
        redis: &RedisPool,
    ) {
        if msg_size > 0 {
            let spawn_postgres = postgres.clone();
            let redis = redis.clone();
            if let Ok(size_in_bytes) = i64::try_from(msg_size) {
                tokio::spawn(async move {
                    let query = r"
INSERT INTO
	hourly_bandwidth (device_id, size_in_bytes, is_pi, is_counted)
VALUES
	($1, $2, $3, $4) ON CONFLICT (
		extract(
			year
			FROM
			 (timestamp AT TIME ZONE 'UTC')
		),
		extract(
			month
			FROM
				 (timestamp AT TIME ZONE 'UTC')
		),
		extract(
			day
			FROM
			(timestamp AT TIME ZONE 'UTC')
		),
		extract(
			hour
			FROM
				(timestamp AT TIME ZONE 'UTC')
		),
		device_id,
		is_pi,
		is_counted
	) DO
	UPDATE
SET
	size_in_bytes = hourly_bandwidth.size_in_bytes + $2";
                    if let Some(e) = sqlx::query(query)
                        .bind(device_id.get())
                        .bind(size_in_bytes)
                        .bind(device_type.is_pi())
                        .bind(is_counted)
                        .execute(&spawn_postgres)
                        .await
                        .err()
                    {
                        error!("{e:?}");
                        error!("unable to insert bandwidth");
                    }
                    if let Some(e) = ModelMonthlyBandwidth::force_update_cache(
                        &spawn_postgres,
                        &redis,
                        device_id,
                    )
                    .await
                    .err()
                    {
                        error!("{e:?}");
                        error!("unable to force update cache");
                    };
                });
            }
        }
    }
}

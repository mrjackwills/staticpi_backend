use super::{monthly_bandwidth::ModelMonthlyBandwidth, new_types::DeviceId};
use crate::{C, connections::ConnectionType};

use fred::clients::Pool;
use sqlx::PgPool;

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
        redis: &Pool,
    ) {
        if msg_size > 0 {
            let spawn_postgres = C!(postgres);
            let redis = C!(redis);
            if let Ok(size_in_bytes) = i64::try_from(msg_size) {
                tokio::spawn(async move {
                    // INSERT INTO hourly_bandwidth (device_id, size_in_bytes, is_pi, is_counted)
                    // VALUES ($1, $2, $3, $4)
                    // ON CONFLICT (year, month, day, hour, device_id, is_pi, is_counted)
                    // DO UPDATE
                    // SET size_in_bytes = hourly_bandwidth.size_in_bytes + EXCLUDED.size_in_bytes;

                    // -- Add generated columns for the time parts
                    // ALTER TABLE hourly_bandwidth
                    //   ADD COLUMN year  int GENERATED ALWAYS AS (extract(year  FROM timestamp AT TIME ZONE 'UTC')) STORED,
                    //   ADD COLUMN month int GENERATED ALWAYS AS (extract(month FROM timestamp AT TIME ZONE 'UTC')) STORED,
                    //   ADD COLUMN day   int GENERATED ALWAYS AS (extract(day   FROM timestamp AT TIME ZONE 'UTC')) STORED,
                    //   ADD COLUMN hour  int GENERATED ALWAYS AS (extract(hour  FROM timestamp AT TIME ZONE 'UTC')) STORED;

                    // -- Create unique index
                    // CREATE UNIQUE INDEX hourly_bandwidth_uk
                    //   ON hourly_bandwidth (year, month, day, hour, device_id, is_pi, is_counted);
                    if let Err(e) = sqlx::query!(
                        // WHY?
                        // TODO this is wrong
                        "INSERT INTO
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
                        size_in_bytes = hourly_bandwidth.size_in_bytes + $2",
                        device_id.get(),
                        size_in_bytes,
                        device_type.is_pi(),
                        is_counted
                    )
                    .execute(&spawn_postgres)
                    .await
                    {
                        tracing::error!("{e:?}");
                        tracing::error!("unable to insert bandwidth");
                    }
                    if let Some(e) = ModelMonthlyBandwidth::force_update_cache(
                        &spawn_postgres,
                        &redis,
                        device_id,
                    )
                    .await
                    .err()
                    {
                        tracing::error!("{e:?}");
                        tracing::error!("unable to force update cache");
                    }
                });
            }
        }
    }
}

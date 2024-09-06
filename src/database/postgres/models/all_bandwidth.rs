use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api_error::ApiError;

#[derive(sqlx::FromRow, Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ModelAllBandwidth {
    hour_in: i64,
    hour_out: i64,
    day_in: i64,
    day_out: i64,
    month_in: i64,
    month_out: i64,
    total_in: i64,
    total_out: i64,
}

impl ModelAllBandwidth {
    #[expect(clippy::too_many_lines)]
    pub async fn get(postgres: &PgPool) -> Result<Self, ApiError> {
        let query = r"
SELECT
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			timestamp >= NOW() - INTERVAL '1 hour'
			AND timestamp <= NOW()
			AND is_counted = FALSE
	) as hour_in,
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			timestamp >= NOW() - INTERVAL '1 hour'
			AND timestamp <= NOW()
			AND is_counted = TRUE
	) as hour_out,
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			timestamp >= NOW() - INTERVAL '24 hours'
			AND timestamp <= NOW()
			AND is_counted = FALSE
	) as day_in,
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			timestamp >= NOW() - INTERVAL '24 hours'
			AND timestamp <= NOW()
			AND is_counted = TRUE
	) as day_out,
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			extract(
				year
				from
					timestamp
			) = extract (
				year
				FROM
					CURRENT_DATE
			)
			AND extract(
				month
				FROM
					timestamp
			) = extract (
				month
				FROM
					CURRENT_DATE
			)
			AND is_counted = FALSE
	) as month_in,
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			extract(
				year
				from
					timestamp
			) = extract (
				year
				FROM
					CURRENT_DATE
			)
			AND extract(
				month
				FROM
					timestamp
			) = extract (
				month
				FROM
					CURRENT_DATE
			)
			AND is_counted = TRUE
	) as month_out,
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			is_counted = FALSE
	) as total_in,
	(
		SELECT
			COALESCE(SUM(size_in_bytes), 0)::BIGINT
		FROM
			hourly_bandwidth
		WHERE
			is_counted = TRUE
	) as total_out";
        Ok(sqlx::query_as::<_, Self>(query).fetch_one(postgres).await?)
    }
}

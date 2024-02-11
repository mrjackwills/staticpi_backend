use fred::clients::RedisPool;
use serde::Serialize;
use sqlx::PgPool;

use crate::{
    api_error::ApiError, connections::AdminConnectionInfo, database::session::RedisSession,
};

use super::{device::ModelDevice, new_types::UserId, user_level::UserLevel};

#[derive(Debug, Serialize)]
pub struct AdminDevice {
    pub connections: Vec<AdminConnectionInfo>,
    pub device: ModelDevice,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AdminUserAndSession {
    user: AdminModelUser,
    sessions: Vec<AdminSession>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AdminSession {
    pub key: String,
    pub ttl: u64,
    pub timestamp: i64,
}
#[derive(Debug, Clone, sqlx::FromRow, Serialize, PartialEq, Eq)]
pub struct AdminModelUser {
    pub registered_user_id: UserId,

    pub full_name: String,
    pub email: String,
    pub active: bool,
    pub login_attempt_number: i32,
    pub two_fa_enabled: bool,
    pub two_fa_backup_count: i64,
    pub user_level: UserLevel,

    pub timestamp: String,
    pub device_count: i64,
    pub password_reset: bool,

    pub pi_bytes_day_in: i64,
    pub pi_bytes_day_out: i64,
    pub pi_bytes_month_in: i64,
    pub pi_bytes_month_out: i64,
    pub pi_bytes_total_in: i64,
    pub pi_bytes_total_out: i64,

    pub client_bytes_day_in: i64,
    pub client_bytes_day_out: i64,
    pub client_bytes_month_in: i64,
    pub client_bytes_month_out: i64,
    pub client_bytes_total_in: i64,
    pub client_bytes_total_out: i64,
}

impl AdminModelUser {
    /// Get vec of all registered users
    /// This is a brutal query, need to simplify
    #[allow(clippy::too_many_lines)]
    pub async fn get_all(
        postgres: &PgPool,
        redis: &RedisPool,
    ) -> Result<Vec<AdminUserAndSession>, ApiError> {
        let query = r"
SELECT
	ru.active,
	ru.full_name,
	ru.timestamp::TEXT,
	ru.registered_user_id,
	ea.email,
	COALESCE(la.login_attempt_number, 0) AS login_attempt_number,
	CASE
		WHEN tfs.two_fa_secret IS NULL THEN FALSE
		ELSE TRUE
	END as two_fa_enabled,
	CASE
		WHEN (
			SELECT
				pr.password_reset_id
			FROM
				password_reset pr
			WHERE
				pr.registered_user_id = ru.registered_user_id
				AND pr.timestamp >= NOW () - INTERVAL '1 hour'
				AND pr.consumed IS NOT TRUE
		) IS NULL THEN FALSE
		ELSE TRUE
		END AS password_reset,
	(
		SELECT
			COALESCE(COUNT(*), 0)
		FROM
			two_fa_backup tfb
		WHERE
			tfb.registered_user_id = ru.registered_user_id
	) AS two_fa_backup_count,
	(
		SELECT
			COALESCE(COUNT(*), 0)
			FROM
				device de
			WHERE
				de.registered_user_id = ru.registered_user_id
				AND de.active = true
	) AS device_count,
	ul.user_level_name AS user_level,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = TRUE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = FALSE
	) AS pi_bytes_day_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = TRUE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = TRUE
	) AS pi_bytes_day_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = TRUE
			AND extract(
				month
				FROM
					hb.timestamp
			) = extract (
				month
				FROM
					CURRENT_DATE
			)
			AND extract(
				year
				FROM
					hb.timestamp
			) = extract (
				year
				FROM
					CURRENT_DATE
			)
			AND hb.is_counted = FALSE
	) AS pi_bytes_month_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = TRUE
			AND extract(
				month
				FROM
					hb.timestamp
			) = extract (
				month
				FROM
					CURRENT_DATE
			)
			AND extract(
				year
				FROM
					hb.timestamp
			) = extract (
				year
				FROM
					CURRENT_DATE
			)
			AND hb.is_counted = TRUE
	) AS pi_bytes_month_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = TRUE
			AND hb.is_counted = FALSE
	) AS pi_bytes_total_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = TRUE
			AND hb.is_counted = TRUE
	) AS pi_bytes_total_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = FALSE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = FALSE
	) AS client_bytes_day_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = FALSE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = TRUE
	) AS client_bytes_day_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = FALSE
			AND extract(
				month
				FROM
					hb.timestamp
			) = extract (
				month
				FROM
					CURRENT_DATE
			)
			AND extract(
				year
				FROM
					hb.timestamp
			) = extract (
				year
				FROM
					CURRENT_DATE
			)
			AND hb.is_counted = FALSE
	) AS client_bytes_month_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = FALSE
			AND extract(
				month
				FROM
					hb.timestamp
			) = extract (
				month
				FROM
					CURRENT_DATE
			)
			AND extract(
				year
				FROM
					hb.timestamp
			) = extract (
				year
				FROM
					CURRENT_DATE
			)
			AND hb.is_counted = TRUE
	) AS client_bytes_month_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = FALSE
			AND hb.is_counted = FALSE
	) AS client_bytes_total_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0::BIGINT
				ELSE SUM(size_in_bytes)::BIGINT
			END
		FROM
			hourly_bandwidth hb
			LEFT JOIN device de USING(device_id)
		WHERE
			de.registered_user_id = ru.registered_user_id
			AND hb.is_pi = FALSE
			AND hb.is_counted = TRUE
	) AS client_bytes_total_out
FROM
	registered_user ru
	LEFT JOIN two_fa_secret tfs USING(registered_user_id)
	LEFT JOIN login_attempt la USING(registered_user_id)
	LEFT JOIN user_level ul USING(user_level_id)
	LEFT JOIN email_address ea USING(email_address_id)
";
        let users = sqlx::query_as::<_, Self>(query).fetch_all(postgres).await?;

        let mut output = vec![];
        for user in users {
            let sessions = RedisSession::admin_get_all(redis, user.registered_user_id).await?;
            output.push(AdminUserAndSession { user, sessions });
        }
        Ok(output)
    }
}

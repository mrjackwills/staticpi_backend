use serde::Deserialize;
use sqlx::PgPool;
use ulid::Ulid;

use crate::api_error::ApiError;

use super::{ip_user_agent::ModelUserAgentIp, new_types::UserId};

#[derive(sqlx::FromRow, Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ModelLogin {
    // pub login_attempt_id: i64,
    pub login_attempt_number: i32,
}

impl ModelLogin {
    #[cfg(test)]
    pub async fn get(
        postgres: &PgPool,
        registered_user_id: UserId,
    ) -> Result<Option<Self>, ApiError> {
        let query = "SELECT * FROM login_attempt WHERE registered_user_id = $1";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(registered_user_id.get())
            .fetch_optional(postgres)
            .await?)
    }

    async fn reset(postgres: &PgPool, registered_user_id: UserId) -> Result<(), ApiError> {
        let query =
            "UPDATE login_attempt SET login_attempt_number = 0 WHERE registered_user_id = $1";
        sqlx::query(query)
            .bind(registered_user_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    pub async fn admin_delete_attempt(postgres: &PgPool, email: String) -> Result<(), ApiError> {
        let query = r"
UPDATE
	login_attempt
SET
	login_attempt_number = 0
WHERE
	registered_user_id = (
	SELECT
		registered_user_id
	FROM
		registered_user
	LEFT JOIN email_address USING(email_address_id)
	WHERE
		email_address.email = $1)";
        sqlx::query(query).bind(email).execute(postgres).await?;
        Ok(())
    }

    async fn increase(postgres: &PgPool, registered_user_id: UserId) -> Result<(), ApiError> {
        let query = r"
INSERT INTO
    login_attempt (login_attempt_number, registered_user_id)
VALUES
    (1, $1)
ON CONFLICT
    (registered_user_id)
DO UPDATE
    SET
        login_attempt_number = login_attempt.login_attempt_number + 1";
        sqlx::query(query)
            .bind(registered_user_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    pub async fn insert(
        postgres: &PgPool,
        registered_user_id: UserId,
        useragent_ip: ModelUserAgentIp,
        success: bool,
        session_ulid: Option<Ulid>,
    ) -> Result<(), ApiError> {
        let query = r"
INSERT INTO
    login_history(ip_id, success, session_name, user_agent_id, registered_user_id)
VALUES
    ($1, $2, $3, $4, $5)
RETURNING login_history_id";

        sqlx::query(query)
            .bind(useragent_ip.ip_id.get())
            .bind(success)
            .bind(session_ulid.map(|ulid| ulid.to_string()))
            .bind(useragent_ip.user_agent_id.get())
            .bind(registered_user_id.get())
            .execute(postgres)
            .await?;

        if success {
            Self::reset(postgres, registered_user_id).await?;
        } else {
            Self::increase(postgres, registered_user_id).await?;
        }
        Ok(())
    }
}

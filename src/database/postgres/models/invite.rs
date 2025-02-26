use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::{ip_user_agent::ModelUserAgentIp, new_types::InviteId, user::ModelUser};
use crate::api_error::ApiError;

#[derive(sqlx::FromRow, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ModelInvite {
    pub invite_code_id: InviteId,
    pub invite: String,
    pub count: i16,
}

impl ModelInvite {
    /// Insert a new invite
    pub async fn insert(
        postgres: &PgPool,
        req: ModelUserAgentIp,
        count: i16,
        user: &ModelUser,
        invite: &str,
    ) -> Result<(), sqlx::Error> {
        // TODO if user.user_level !== admin, error?
        let query = "
INSERT INTO
	invite_code (
		registered_user_id,
		invite,
		count,
		ip_id,
		user_agent_id
	)
VALUES
	($1, $2, $3, $4, $5)";
        sqlx::query(query)
            .bind(user.registered_user_id.get())
            .bind(invite)
            .bind(count)
            .bind(req.ip_id.get())
            .bind(req.user_agent_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    /// Should check that the executor is an admin user?
    pub async fn get_all(postgres: &PgPool) -> Result<Vec<Self>, ApiError> {
        let query = "
SELECT
	invite, count, invite_code_id
FROM
	invite_code";
        Ok(sqlx::query_as::<_, Self>(query).fetch_all(postgres).await?)
    }

    /// Should check that the executor is an admin user?
    pub async fn delete(postgres: &PgPool, invite: String) -> Result<(), ApiError> {
        let query = "
DELETE FROM
	invite_code
WHERE
	invite = $1";
        sqlx::query(query).bind(invite).execute(postgres).await?;
        Ok(())
    }

    /// Check if a given invite is valid, if so, will reduce count of said invite
    /// make rename it consume?
    pub async fn valid(postgres: &PgPool, invite: &str) -> Result<bool, ApiError> {
        let mut transaction = postgres.begin().await?;
        let query = "
SELECT
	invite_code_id,
	invite,
	count
FROM
	invite_code
WHERE
	invite = $1
	AND count > 0";

        match sqlx::query_as::<_, Self>(query)
            .bind(invite)
            .fetch_optional(&mut *transaction)
            .await?
        {
            Some(invite) => {
                let query = "
UPDATE
	invite_code
SET
	count = count - 1
WHERE
	invite_code_id = $1";
                sqlx::query(query)
                    .bind(invite.invite_code_id.get())
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

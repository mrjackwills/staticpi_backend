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
        sqlx::query!(
            "
INSERT INTO
    invite_code (
        registered_user_id,
        invite,
        count,
        ip_id,
        user_agent_id
    )
VALUES
    ($1, $2, $3, $4, $5)",
            user.registered_user_id.get(),
            invite,
            count,
            req.ip_id.get(),
            req.user_agent_id.get()
        )
        .execute(postgres)
        .await?;
        Ok(())
    }

    /// Should check that the executor is an admin user?
    pub async fn get_all(postgres: &PgPool) -> Result<Vec<Self>, ApiError> {
        Ok(sqlx::query_as!(
            Self,
            "
SELECT
    invite, count, invite_code_id
FROM
    invite_code"
        )
        .fetch_all(postgres)
        .await?)
    }

    /// Should check that the executor is an admin user?
    pub async fn delete(postgres: &PgPool, invite: String) -> Result<(), ApiError> {
        sqlx::query!(
            "DELETE FROM
    invite_code
WHERE
    invite = $1",
            invite
        )
        .execute(postgres)
        .await?;
        Ok(())
    }

    /// Check if a given invite is valid, if so, will reduce count of said invite
    /// make rename it consume?
    pub async fn valid(postgres: &PgPool, invite: &str) -> Result<bool, ApiError> {
        let mut transaction = postgres.begin().await?;
        if let Some(invite) = sqlx::query_as!(
            Self,
            "
SELECT
    invite_code_id,
    invite,
    count
FROM
    invite_code
WHERE
    invite = $1
    AND count > 0",
            invite
        )
        .fetch_optional(&mut *transaction)
        .await?
        {
            sqlx::query!(
                "
UPDATE
    invite_code
SET
    count = count - 1
WHERE
    invite_code_id = $1",
                invite.invite_code_id.get()
            )
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

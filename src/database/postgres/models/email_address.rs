use crate::api_error::ApiError;
use serde::Deserialize;
use sqlx::PgExecutor;

use super::new_types::EmailAddressId;

#[derive(sqlx::FromRow, Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ModelEmailAddress {
    pub email_address_id: EmailAddressId,
    pub email: String,
}

impl ModelEmailAddress {
    pub async fn insert(postgres: impl PgExecutor<'_>, email: &str) -> Result<Self, ApiError> {
        Ok(sqlx::query_as!(
            Self,
            "
INSERT INTO
	email_address(email)
VALUES
	($1)
RETURNING
	email_address_id, email",
            email
        )
        .fetch_one(postgres)
        .await?)
    }

    pub async fn get(postgres: impl PgExecutor<'_>, email: &str) -> Result<Option<Self>, ApiError> {
        Ok(sqlx::query_as!(
            Self,
            "
SELECT
    email_address_id, email
FROM
    email_address
WHERE
    email = $1;",
            email
        )
        .fetch_optional(postgres)
        .await?)
    }
}

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
        let query =
            "INSERT INTO email_address(email) VALUES ($1) RETURNING email_address_id, email;";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(email)
            .fetch_one(postgres)
            .await?)
    }

    pub async fn get(postgres: impl PgExecutor<'_>, email: &str) -> Result<Option<Self>, ApiError> {
        let query = "SELECT * FROM email_address WHERE email = $1;";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(email)
            .fetch_optional(postgres)
            .await?)
    }
}

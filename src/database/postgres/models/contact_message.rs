use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sqlx::{PgExecutor, PgPool};

use super::{
    ip_user_agent::ModelUserAgentIp,
    new_types::{ContactMessageId, EmailAddressId, UserId},
};
use crate::api_error::ApiError;

#[derive(sqlx::FromRow, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ModelContactMessage {
    pub contact_message_id: ContactMessageId,
    pub registered_user_id: Option<UserId>,
    pub timestamp: String,
    pub email: String,
    pub user_agent: String,
    pub message: String,
    pub ip: IpAddr,
}

impl ModelContactMessage {
    /// Insert a new contact message
    pub async fn insert(
        postgres: impl PgExecutor<'_>,
        req: ModelUserAgentIp,
        registered_user_id: Option<UserId>,
        message: String,
        email_address_id: EmailAddressId,
    ) -> Result<(), sqlx::Error> {
        let query = "
INSERT INTO
	contact_message (
		ip_id,
		user_agent_id,
		email_address_id,
		message,
		registered_user_id
	)
VALUES
	($1, $2, $3, $4, $5)";
        sqlx::query(query)
            .bind(req.ip_id.get())
            .bind(req.user_agent_id.get())
            .bind(email_address_id.get())
            .bind(message)
            .bind(registered_user_id.map(UserId::get))
            .execute(postgres)
            .await?;
        Ok(())
    }

    /// Should check that the executor is an admin user?
    pub async fn get_all(postgres: &PgPool) -> Result<Vec<Self>, ApiError> {
        let query = "
SELECT
	cm.contact_message_id,
	cm.message,
	cm.timestamp::TEXT,
	ea.email,
	ip.ip,
	ua.user_agent_string AS user_agent,
	ru.registered_user_id
FROM
	contact_message cm
	LEFT JOIN email_address ea USING(email_address_id)
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
	LEFT JOIN registered_user ru USING(registered_user_id)
ORDER BY
	cm.timestamp ASC,
	ru.registered_user_id ASC";
        Ok(sqlx::query_as::<_, Self>(query).fetch_all(postgres).await?)
    }

    // Should check that the executor is an admin user?
    pub async fn delete(
        postgres: &PgPool,
        contact_message_id: ContactMessageId,
    ) -> Result<(), ApiError> {
        let query = r"
DELETE FROM
	contact_message
WHERE
	contact_message_id = $1";
        sqlx::query(query)
            .bind(contact_message_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }
}

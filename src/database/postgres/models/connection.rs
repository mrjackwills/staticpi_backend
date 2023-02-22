use serde::Serialize;
use sqlx::PgPool;
use std::net::IpAddr;

use crate::{api_error::ApiError, connections::ConnectionType};

use super::{
    device::ModelWsDevice, ip_user_agent::ModelUserAgentIp, new_types::ConnectionId,
    user::ModelUser,
};

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct ModelConnection {
    pub timestamp_online: String,
    pub timestamp_offline: Option<String>,
    pub ip: IpAddr,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct ModelConnectionId {
    pub connection_id: ConnectionId,
}

impl ModelConnection {
    /// Set all connection timestamps to NOW(), for when server is shutdown, make sure db is in sync with the actual connections
    pub async fn update_all_offline(postgres: &PgPool) -> Result<(), ApiError> {
        let query =
            r#"UPDATE connection SET timestamp_offline = NOW() WHERE timestamp_offline IS NULL"#;
        sqlx::query(query).execute(postgres).await?;
        Ok(())
    }

    /// Set a connection to offline
    pub async fn update_offline(
        postgres: &PgPool,
        connection_id: ConnectionId,
    ) -> Result<(), ApiError> {
        let query = r#"UPDATE connection SET timestamp_offline = NOW() WHERE connection_id = $1"#;
        sqlx::query(query)
            .bind(connection_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    /// Get the ip_address, and connection timestamp, of all connections of a given user + device
    /// is_pi bool toggle if device connections of client connections
    pub async fn get_client_online(
        postgres: &PgPool,
        user: &ModelUser,
        name_of_device: &str,
    ) -> Result<Vec<Self>, ApiError> {
        let query = r#"
SELECT
    ipa.ip,
    co.timestamp_online::TEXT, co.timestamp_offline::TEXT
FROM
    connection co
LEFT JOIN
    device de
ON
    co.device_id = de.device_id
LEFT JOIN
    device_name dn
ON
    de.device_name_id = dn.device_name_id
LEFT JOIN
    ip_address ipa
ON
    co.ip_id = ipa.ip_id
WHERE
    de.registered_user_id = $1
AND	
    co.is_pi = FALSE
AND
    co.timestamp_offline IS NULL
AND
    dn.name_of_device = $2
ORDER BY
    co.timestamp_online"#;
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(user.registered_user_id.get())
            .bind(name_of_device)
            .fetch_all(postgres)
            .await?)
    }

    /// Insert a new connection
    pub async fn insert(
        postgres: &PgPool,
        device: &ModelWsDevice,
        user_agent_ip: &ModelUserAgentIp,
        device_type: ConnectionType,
    ) -> Result<ConnectionId, ApiError> {
        let query = r#"INSERT INTO connection(device_id, api_key_id, ip_id, user_agent_id, is_pi) VALUES($1, $2, $3, $4, $5) RETURNING connection_id"#;
        Ok(sqlx::query_as::<_, ModelConnectionId>(query)
            .bind(device.device_id.get())
            .bind(device.api_key_id.get())
            .bind(user_agent_ip.ip_id.get())
            .bind(user_agent_ip.user_agent_id.get())
            .bind(device_type.is_pi())
            .fetch_one(postgres)
            .await?
            .connection_id)
    }
}

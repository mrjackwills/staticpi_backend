use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use axum_extra::extract::{cookie::Key, PrivateCookieJar};
use redis::aio::ConnectionManager;
use sqlx::{postgres::PgRow, Error, FromRow, PgPool, Row};
use time::OffsetDateTime;
use ulid::Ulid;

use crate::{
    api_error::ApiError,
    argon::ArgonHash,
    database::redis::{new_user::RedisNewUser, session::RedisSession},
    servers::ApplicationState,
};

use super::{
    ip_user_agent::ModelUserAgentIp,
    new_types::{EmailAddressId, UserId, UserLevelId},
    user_level::{ModelUserLevel, UserLevel},
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelUser {
    // skip serializng?
    pub registered_user_id: UserId,
    pub full_name: String,
    pub email: String,
    pub email_address_id: EmailAddressId,
    pub active: bool,
    pub login_attempt_number: i32,
    pub two_fa_secret: Option<String>,
    pub two_fa_always_required: bool,
    pub two_fa_backup_count: i64,
    pub user_level: UserLevel,
    pub user_level_id: UserLevelId,

    pub custom_device_name: bool,
    pub device_password: bool,
    pub structured_data: bool,
    pub max_clients_per_device: i16,
    pub max_message_size_in_bytes: i32,
    pub max_monthly_bandwidth_in_bytes: i64,
    pub max_number_of_devices: i16,

    // Join user level job, structured data etc?
    pub timestamp: OffsetDateTime,
    password_hash: ArgonHash,
}

impl<'r> FromRow<'r, PgRow> for ModelUser {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        Ok(Self {
            registered_user_id: row.try_get("registered_user_id")?,
            full_name: row.try_get("full_name")?,
            email: row.try_get("email")?,
            email_address_id: row.try_get("email_address_id")?,
            active: row.try_get("active")?,
            login_attempt_number: row.try_get("login_attempt_number")?,
            two_fa_secret: row.try_get("two_fa_secret")?,
            two_fa_always_required: row.try_get("two_fa_always_required")?,
            two_fa_backup_count: row.try_get("two_fa_backup_count")?,
            password_hash: ArgonHash(row.try_get::<'r, &str, &str>("password_hash")?.to_owned()),
            max_message_size_in_bytes: row.try_get("max_message_size_in_bytes")?,
            max_number_of_devices: row.try_get("max_number_of_devices")?,
            max_clients_per_device: row.try_get("max_clients_per_device")?,
            max_monthly_bandwidth_in_bytes: row.try_get("max_monthly_bandwidth_in_bytes")?,
            timestamp: row.try_get("timestamp")?,
            user_level_id: row.try_get("user_level_id")?,
            user_level: UserLevel::from(row.try_get::<'r, String, &str>("user_level_name")?),
            custom_device_name: row.try_get("custom_device_name")?,
            device_password: row.try_get("device_password")?,
            structured_data: row.try_get("structured_data")?,
        })
    }
}

impl ModelUser {
    pub fn get_password_hash(&self) -> ArgonHash {
        self.password_hash.clone()
    }

    /// Get vec of all registered users
    pub async fn admin_get_all(postgres: &PgPool) -> Result<Vec<Self>, ApiError> {
        let query = r"
SELECT
    ru.registered_user_id, ru.active, ru.password_hash, ru.full_name, ru.timestamp,
    ea.email, ea.email_address_id,
    COALESCE(la.login_attempt_number, 0) AS login_attempt_number,
    tfs.two_fa_secret,
    COALESCE(tfs.always_required, false) AS two_fa_always_required,
    (
        SELECT
        COALESCE(COUNT(*),0)
        FROM
        two_fa_backup
        WHERE
        registered_user_id = ru.registered_user_id
    ) AS two_fa_backup_count,
    ul.*
FROM
    registered_user ru
LEFT JOIN two_fa_secret tfs USING(registered_user_id)
LEFT JOIN login_attempt la USING(registered_user_id)
LEFT JOIN user_level ul USING(user_level_id)
LEFT JOIN email_address ea USING(email_address_id)";
        Ok(sqlx::query_as::<_, Self>(query).fetch_all(postgres).await?)
    }

    pub async fn get(postgres: &PgPool, email: &str) -> Result<Option<Self>, ApiError> {
        let query = r"
SELECT
    ru.registered_user_id, ru.active, ru.password_hash, ru.full_name, ru.timestamp,
    ea.email, ea.email_address_id,
    COALESCE(la.login_attempt_number, 0) AS login_attempt_number,
    tfs.two_fa_secret,
    COALESCE(tfs.always_required, false) AS two_fa_always_required,
    (
        SELECT
        COALESCE(COUNT(*),0)
        FROM
        two_fa_backup
        WHERE
        registered_user_id = ru.registered_user_id
    ) AS two_fa_backup_count,
    ul.*
FROM
    registered_user ru
LEFT JOIN two_fa_secret tfs USING(registered_user_id)
LEFT JOIN login_attempt la USING(registered_user_id)
LEFT JOIN user_level ul USING(user_level_id)
LEFT JOIN email_address ea USING(email_address_id)
WHERE
    ea.email = $1
AND
    active = true";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(email.to_lowercase())
            .fetch_optional(postgres)
            .await?)
    }

    pub async fn insert(postgres: &PgPool, user: &RedisNewUser) -> Result<(), ApiError> {
        let user_level = ModelUserLevel::get(postgres, UserLevel::Free).await?;

        let query = r"
INSERT INTO
    registered_user(full_name, email_address_id, password_hash, ip_id, user_agent_id, active, user_level_id)
VALUES
    ($1, $2, $3, $4, $5, $6, $7)";
        sqlx::query(query)
            .bind(user.full_name.clone())
            .bind(user.email_address_id.get())
            .bind(user.password_hash.clone())
            .bind(user.ip_id.get())
            .bind(user.user_agent_id.get())
            .bind(true)
            .bind(user_level.user_level_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    // Ideally should use &self here?
    pub async fn update_password(
        postgres: &PgPool,
        registered_user_id: UserId,
        password_hash: ArgonHash,
    ) -> Result<(), ApiError> {
        let query = "UPDATE registered_user SET password_hash = $1 WHERE registered_user_id = $2";
        sqlx::query(query)
            .bind(password_hash.to_string())
            .bind(registered_user_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    pub async fn update_name(
        postgres: &PgPool,
        registered_user_id: UserId,
        full_name: String,
    ) -> Result<(), ApiError> {
        let query = "UPDATE registered_user SET full_name = $1 WHERE registered_user_id = $2";
        sqlx::query(query)
            .bind(full_name)
            .bind(registered_user_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    /// This is a hard delete, and also checks to see if any IP address, UserAgents, and DeviceNames can also be deleted
    /// take in admin user, and match user id?
    pub async fn delete(
        &self,
        postgres: &PgPool,
        redis: &mut ConnectionManager,
    ) -> Result<(), ApiError> {
        let mut transaction = postgres.begin().await?;

        let registered_user_query = "DELETE FROM registered_user WHERE registered_user_id = $1";
        sqlx::query(registered_user_query)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;

        let email_log = "DELETE FROM email_log el WHERE el.email_address_id = (SELECT ru.email_address_id FROM registered_user ru WHERE ru.registered_user_id = $1)";
        sqlx::query(email_log)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;

        let contact_messages = "DELETE FROM contact_message cm WHERE cm.email_address_id = (SELECT ru.email_address_id FROM registered_user ru WHERE ru.registered_user_id = $1) OR cm.registered_user_id  =$1";
        sqlx::query(contact_messages)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;

        let email_address_query = "DELETE FROM email_address WHERE email_address_id = $1";
        sqlx::query(email_address_query)
            .bind(self.email_address_id.get())
            .execute(&mut *transaction)
            .await?;

        ModelUserAgentIp::delete_ip(&mut transaction, redis).await?;
        ModelUserAgentIp::delete_useragent(&mut transaction, redis).await?;

        let device_name_query = "
DELETE FROM device_name
WHERE device_name_id
IN (
    SELECT device_name.device_name_id
    FROM device_name
    LEFT JOIN device USING(device_name_id)
    WHERE device.device_name_id IS NULL
);";
        sqlx::query(device_name_query)
            .execute(&mut *transaction)
            .await?;

        let user_audit_query = "DELETE FROM registered_user_audit WHERE (old_values -> 'registered_user_id')::BIGINT = $1 OR (new_values -> 'registered_user_id')::BIGINT = $1";
        sqlx::query(user_audit_query)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;
        let device_audit = "DELETE FROM device_audit WHERE (old_values -> 'registered_user_id')::BIGINT = $1 OR (new_values -> 'registered_user_id')::BIGINT = $1";
        sqlx::query(device_audit)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;
        let api_key_audit = "DELETE FROM api_key_audit WHERE (old_values -> 'registered_user_id')::BIGINT = $1 OR (new_values -> 'registered_user_id')::BIGINT = $1";
        sqlx::query(api_key_audit)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;
        let two_fa_secret_audit = "DELETE FROM two_fa_secret_audit WHERE (old_values -> 'registered_user_id')::BIGINT = $1 OR (new_values -> 'registered_user_id')::BIGINT = $1";
        sqlx::query(two_fa_secret_audit)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;
        let two_fa_backup_audit = "DELETE FROM two_fa_backup_audit WHERE (old_values -> 'registered_user_id')::BIGINT = $1 OR (new_values -> 'registered_user_id')::BIGINT = $1";
        sqlx::query(two_fa_backup_audit)
            .bind(self.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;

        transaction.commit().await?;
        Ok(())
    }

    /// Move this into admin queries
    pub async fn admin_get(postgres: &PgPool, email: &str) -> Result<Option<Self>, ApiError> {
        let query = r"
SELECT
    ru.registered_user_id, ru.active, ru.password_hash, ru.full_name, ru.timestamp,
    ea.email, ea.email_address_id,
    COALESCE(la.login_attempt_number, 0) AS login_attempt_number,
    tfs.two_fa_secret,
    COALESCE(tfs.always_required, false) AS two_fa_always_required,
    (
        SELECT
        COALESCE(COUNT(*),0)
        FROM
        two_fa_backup
        WHERE
        registered_user_id = ru.registered_user_id
    ) AS two_fa_backup_count,
    ul.*
FROM
    registered_user ru

LEFT JOIN two_fa_secret tfs USING(registered_user_id)
LEFT JOIN login_attempt la USING(registered_user_id)
LEFT JOIN email_address ea USING(email_address_id)
LEFT JOIN user_level ul USING(user_level_id)
WHERE
    ea.email = $1";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(email.to_lowercase())
            .fetch_optional(postgres)
            .await?)
    }

    pub async fn admin_toggle_active(&self, postgres: &PgPool) -> Result<(), ApiError> {
        let query = "UPDATE registered_user SET active = NOT active WHERE registered_user_id = $1";
        sqlx::query(query)
            .bind(self.registered_user_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ModelUser
where
    ApplicationState: FromRef<S>,
    S: Send + Sync,
    Key: FromRef<S>,
{
    type Rejection = ApiError;

    /// Check client is authenticated, and then return model_user object
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Ok(jar) = PrivateCookieJar::<Key>::from_request_parts(parts, state).await {
            let state = ApplicationState::from_ref(state);
            if let Some(data) = jar.get(&state.cookie_name) {
                if let Ok(ulid) = Ulid::from_string(data.value()) {
                    if let Some(user) =
                        RedisSession::get(&mut state.redis(), &state.postgres, &ulid).await?
                    {
                        return Ok(user);
                    }
                }
            }
        }
        Err(ApiError::Authentication)
    }
}

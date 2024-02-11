use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api_error::ApiError;

use super::user::ModelUser;

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct TimeStampIpUserAgent {
    timestamp: String,
    ip: IpAddr,
    user_agent_string: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct Device {
    #[allow(clippy::struct_field_names)]
    name_of_device: String,
    timestamp: String,
    active: String,
    ip: IpAddr,
    user_agent_string: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct LoginHistory {
    timestamp: String,
    success: String,
    ip: IpAddr,
    user_agent_string: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct ContactMessages {
    timestamp: String,
    ip: IpAddr,
    user_agent_string: String,
    message: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct User {
    full_name: String,
    timestamp: String,
    email: String,
    ip: IpAddr,
    #[allow(clippy::struct_field_names)]
    user_agent_string: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct Api {
    #[allow(clippy::struct_field_names)]
    api_key_string: String,
    timestamp: String,
    active: String,
    ip: IpAddr,
    user_agent_string: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct Connection {
    timestamp_online: String,
    timestamp_offline: Option<String>,
    name_of_device: String,
    ip: IpAddr,
    user_agent_string: String,
    is_pi: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct Bandwidth {
    timestamp: String,
    name_of_device: String,
    size_in_bytes: String,
    is_pi: String,
    is_counted: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
struct Emails {
    timestamp: String,
    user_agent_string: String,
    ip: IpAddr,
    subject: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ModelDownloadData {
    api: Vec<Api>,
    bandwidth: Vec<Bandwidth>,
    connection: Vec<Connection>,
    contact: Vec<ContactMessages>,
    device: Vec<Device>,
    emails: Vec<Emails>,
    login_history: Vec<LoginHistory>,
    password_reset: Vec<TimeStampIpUserAgent>,
    two_fa_backup: Vec<TimeStampIpUserAgent>,
    two_fa_secret: Vec<TimeStampIpUserAgent>,
    user: User,
}

impl ModelDownloadData {
    #[allow(clippy::too_many_lines)]
    pub async fn get(postgres: &PgPool, registered_user: &ModelUser) -> Result<String, ApiError> {
        let id = registered_user.registered_user_id.get();

        let mut transaction = postgres.begin().await?;

        let user = "
SELECT
	ru.full_name,
	ru.timestamp::TEXT,
	ea.email::TEXT,
	ip.ip,
	ua.user_agent_string
FROM
	registered_user ru
	LEFT JOIN email_address ea USING(email_address_id)
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
WHERE
	ru.registered_user_id = $1";

        let user = sqlx::query_as::<_, User>(user)
            .bind(id)
            .fetch_one(&mut *transaction)
            .await?;

        let password_reset = "
SELECT
	pr.timestamp::TEXT,
	ip.ip,
	ua.user_agent_string
FROM
	password_reset pr
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
WHERE
	pr.registered_user_id = $1
ORDER BY
	pr.timestamp ASC";
        let password_reset = sqlx::query_as::<_, TimeStampIpUserAgent>(password_reset)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let login_history = "
SELECT
	lh.timestamp::TEXT,
	lh.success::TEXT,
	ip.ip,
	ua.user_agent_string
FROM
	login_history lh
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
WHERE
	lh.registered_user_id = $1
ORDER BY
	lh.timestamp ASC";
        let login_history = sqlx::query_as::<_, LoginHistory>(login_history)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let two_fa_secret = "
SELECT
	tfs.timestamp::TEXT,
	ip.ip,
	ua.user_agent_string
FROM
	two_fa_secret tfs
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
WHERE
	tfs.registered_user_id = $1
ORDER BY
	tfs.timestamp ASC";
        let two_fa_secret = sqlx::query_as::<_, TimeStampIpUserAgent>(two_fa_secret)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let two_fa_backup = "
SELECT
	tfb.timestamp::TEXT,
	ip.ip,
	ua.user_agent_string
FROM
	two_fa_backup tfb
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
WHERE
	tfb.registered_user_id = $1
ORDER BY
	tfb.timestamp ASC";
        let two_fa_backup = sqlx::query_as::<_, TimeStampIpUserAgent>(two_fa_backup)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let device = "
SELECT
	de.timestamp::TEXT,
	den.name_of_device,
	de.active::TEXT,
	ip.ip,
	ua.user_agent_string
FROM
	device de
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
	LEFT JOIN device_name den USING(device_name_id)
WHERE
	de.registered_user_id = $1
ORDER BY
	de.timestamp ASC";
        let device = sqlx::query_as::<_, Device>(device)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let api = "
SELECT
	ap.api_key_string,
	ap.timestamp::TEXT,
	ap.active::TEXT,
	ip.ip,
	ua.user_agent_string
FROM
	api_key ap
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
WHERE
	ap.registered_user_id = $1
ORDER BY
	ap.timestamp ASC";

        let api = sqlx::query_as::<_, Api>(api)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let connection = "
SELECT
	co.timestamp_online::TEXT,
	co.is_pi,
	den.name_of_device,
	ua.user_agent_string,
	co.timestamp_offline::TEXT,
	ip.ip
FROM
	connection co
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
	LEFT JOIN device de USING(device_id)
	JOIN device_name den ON den.device_name_id = de.device_name_id
WHERE
	co.device_id IN (
		SELECT
			de.device_id
		FROM
			device de
		WHERE
			de.registered_user_id = $1
	)
ORDER BY
	co.timestamp_online ASC,
	co.is_pi ASC
";

        let connection = sqlx::query_as::<_, Connection>(connection)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let bandwidth = "
SELECT
	hb.timestamp::TEXT,
	den.name_of_device,
	hb.size_in_bytes::TEXT,
	hb.is_pi::TEXT,
	hb.is_counted::TEXT
FROM
	hourly_bandwidth hb
	LEFT JOIN device de USING(device_id)
	JOIN device_name den ON den.device_name_id = de.device_name_id
WHERE
	hb.device_id IN (
		SELECT
			de.device_id
		FROM
			device de
		WHERE
			de.registered_user_id = $1
	)
ORDER BY
	hb.timestamp ASC";

        let bandwidth = sqlx::query_as::<_, Bandwidth>(bandwidth)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let emails = "
SELECT
	el.timestamp::TEXT,
	es.subject,
	ip.ip,
	ua.user_agent_string
FROM
	email_log el
	LEFT JOIN email_subject es USING(email_subject_id)
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
	LEFT JOIN email_address ea USING(email_address_id)
WHERE
	el.email_address_id = (
		SELECT
			ru.email_address_id
		FROM
			registered_user ru
		WHERE
			ru.registered_user_id = $1
	)
ORDER BY
	el.timestamp ASC";

        let emails = sqlx::query_as::<_, Emails>(emails)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        let contact = "
SELECT
	cm.timestamp::TEXT,
	cm.message,
	ip.ip,
	ua.user_agent_string
FROM
	contact_message cm
	LEFT JOIN ip_address ip USING(ip_id)
	LEFT JOIN user_agent ua USING(user_agent_id)
	LEFT JOIN email_address ea USING(email_address_id)
WHERE
	cm.email_address_id = (
		SELECT
			ru.email_address_id
		FROM
			registered_user ru
		WHERE
			ru.registered_user_id = $1
	)
	OR cm.registered_user_id = $1
ORDER BY
	cm.timestamp ASC";
        let contact = sqlx::query_as::<_, ContactMessages>(contact)
            .bind(id)
            .fetch_all(&mut *transaction)
            .await?;

        // Why rollback here?
        transaction.rollback().await?;

        Ok(serde_json::to_string(&Self {
            api,
            bandwidth,
            connection,
            contact,
            device,
            emails,
            login_history,
            password_reset,
            two_fa_backup,
            two_fa_secret,
            user,
        })?)
    }
}

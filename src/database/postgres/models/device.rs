use fred::clients::RedisPool;
use futures::Future;
use serde::Serialize;
use sqlx::{postgres::PgRow, Error, FromRow, PgPool, Postgres, Row, Transaction};
use std::{net::IpAddr, pin::Pin, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    api_error::ApiError,
    argon::ArgonHash,
    connections::Connections,
    database::{message_cache::MessageCache, postgres::Count},
    helpers::gen_random_device_name,
    user_io::incoming_json::ij,
};

use super::{
    ip_user_agent::ModelUserAgentIp,
    new_types::{ApiKey, ApiKeyId, DeviceId, DeviceNameId, DevicePasswordId, UserId},
    user::ModelUser,
    user_level::UserLevel,
};

#[derive(sqlx::FromRow)]
struct ModelDeviceIdApiKeyId {
    api_key_id: ApiKeyId,
    device_id: DeviceId,
}

#[derive(sqlx::FromRow)]
pub struct ModelDeviceId {
    pub device_id: DeviceId,
}

#[derive(sqlx::FromRow)]
pub struct ModelApiKey {
    api_key_id: ApiKeyId,
}

impl ModelApiKey {
    /// Check if a given api key is already in postgres, so that each is unique
    fn create_api_key<'a>(
        transaction: &'a mut Transaction<'_, Postgres>,
    ) -> Pin<Box<dyn Future<Output = Result<ApiKey, ApiError>> + 'a + Send>> {
        Box::pin(async move {
            let api_key = ApiKey::default();
            if Self::get(transaction, &api_key).await?.is_some() {
                Ok(Self::create_api_key(transaction).await?)
            } else {
                Ok(api_key)
            }
        })
    }

    async fn get(
        transaction: &mut Transaction<'_, Postgres>,
        api_key: &ApiKey,
    ) -> Result<Option<Self>, ApiError> {
        let query = "
SELECT
	*
FROM
	api_key
WHERE
	api_key_string = $1";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(api_key.get())
            .fetch_optional(&mut **transaction)
            .await?)
    }

    /// Update a device's api key
    pub async fn update(
        postgres: &PgPool,
        user: &ModelUser,
        useragent_ip: ModelUserAgentIp,
        device: &ModelDevice,
    ) -> Result<(), ApiError> {
        let mut transaction = postgres.begin().await?;
        let api_key = Self::insert(&mut transaction, user, &useragent_ip).await?;
        let query = "
UPDATE
	device
SET
	api_key_id = $1
WHERE
	device_id = $2";
        sqlx::query(query)
            .bind(api_key.api_key_id.get())
            .bind(device.device_id.get())
            .execute(&mut *transaction)
            .await?;
        Ok(transaction.commit().await?)
    }

    /// Recursively create a unique api_key, and insert into database
    async fn insert(
        transaction: &mut Transaction<'_, Postgres>,
        user: &ModelUser,
        useragent_ip: &ModelUserAgentIp,
    ) -> Result<Self, ApiError> {
        let api_key = Self::create_api_key(transaction).await?;
        let query = "
INSERT INTO
	api_key(
		api_key_string,
		registered_user_id,
		ip_id,
		user_agent_id
	)
VALUES
	($1, $2, $3, $4) RETURNING api_key_id";
        let api_key = sqlx::query_as::<_, Self>(query)
            .bind(api_key.get())
            .bind(user.registered_user_id.get())
            .bind(useragent_ip.ip_id.get())
            .bind(useragent_ip.user_agent_id.get())
            .fetch_one(&mut **transaction)
            .await?;
        Ok(api_key)
    }
}

pub struct ModelDevicePasswordHash {
    device_password_id: DevicePasswordId,
    pub password_hash: ArgonHash,
}
impl<'r> FromRow<'r, PgRow> for ModelDevicePasswordHash {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        Ok(Self {
            device_password_id: row.try_get("device_password_id")?,
            password_hash: ArgonHash(row.try_get::<'r, String, &str>("password_hash")?),
        })
    }
}

impl ModelDevicePasswordHash {
    /// Insert a device password into db
    async fn insert(
        transaction: &mut Transaction<'_, Postgres>,
        hash: ArgonHash,
    ) -> Result<Self, ApiError> {
        let query = "
INSERT INTO
	device_password(password_hash)
VALUES
	($1)
RETURNING
	device_password_id, password_hash";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(hash.to_string())
            .fetch_one(&mut **transaction)
            .await?)
    }

    /// Select a device password from db
    pub async fn get(
        postgres: &PgPool,
        device_password_id: DevicePasswordId,
    ) -> Result<Option<Self>, ApiError> {
        let query = "
SELECT
	device_password_id,
password_hash
	FROM
	device_password
WHERE
	device_password_id = $1";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(device_password_id.get())
            .fetch_optional(postgres)
            .await?)
    }

    /// Delete device password from db
    async fn delete(
        transaction: &mut Transaction<'_, Postgres>,
        device_password_id: DevicePasswordId,
    ) -> Result<(), ApiError> {
        let query = "
DELETE FROM
	device_password
WHERE
	device_password_id = $1";
        sqlx::query(query)
            .bind(device_password_id.get())
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct DeviceName {
    device_name_id: DeviceNameId,
    name_of_device: String,
}

impl DeviceName {
    /// Check if a given user has an active device with a given name
    async fn exists_for_user(
        transaction: &mut Transaction<'_, Postgres>,
        device_name: &str,
        user: &ModelUser,
    ) -> Result<bool, ApiError> {
        let query = "
SELECT
	de.device_id,
	dn.name_of_device
FROM
	device de
	LEFT JOIN device_name dn USING(device_name_id)
WHERE
	dn.name_of_device = $1
	AND de.registered_user_id = $2
	AND de.active = true;";

        Ok(sqlx::query_as::<_, Self>(query)
            .bind(device_name)
            .bind(user.registered_user_id.get())
            .fetch_optional(&mut **transaction)
            .await?
            .is_some())
    }

    /// Insert a device_name, will check if the user already has an active device with the given name
    async fn insert(
        transaction: &mut Transaction<'_, Postgres>,
        device_name: &str,
    ) -> Result<Self, ApiError> {
        let query = "
SELECT
	device_name_id,
	name_of_device
FROM
	device_name
WHERE
	name_of_device = $1";
        if let Some(exists) = sqlx::query_as::<_, Self>(query)
            .bind(device_name)
            .fetch_optional(&mut **transaction)
            .await?
        {
            Ok(exists)
        } else {
            let query = "
INSERT INTO
	device_name(name_of_device)
VALUES
	($1)
RETURNING
	device_name_id, name_of_device";
            Ok(sqlx::query_as::<_, Self>(query)
                .bind(device_name)
                .fetch_one(&mut **transaction)
                .await?)
        }
    }
}

/// A simplified device query, for ws & auth servers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct ModelWsDevice {
    pub device_id: DeviceId,
    pub registered_user_id: UserId,
    pub client_password_id: Option<DevicePasswordId>,
    pub device_password_id: Option<DevicePasswordId>,
    pub max_clients: i16,
    pub structured_data: bool,
    pub api_key: ApiKey,
    pub api_key_id: ApiKeyId,
    pub name_of_device: String,
    pub max_message_size_in_bytes: i32,
    pub max_monthly_bandwidth_in_bytes: i64,
    pub user_level: UserLevel,
}

impl ModelWsDevice {
    /// Get fully joined device by device id
    pub async fn get_by_id(
        postgres: &PgPool,
        device_id: DeviceId,
    ) -> Result<Option<Self>, ApiError> {
        let query = "
SELECT
	de.device_id,
	de.max_clients,
	de.structured_data,
	de.client_password_id,
	de.device_password_id,
	ap.api_key_string AS api_key,
	ap.api_key_id,
	ru.registered_user_id,
	ul.max_message_size_in_bytes,
	ul.max_monthly_bandwidth_in_bytes,
	ul.user_level_name AS user_level,
	dn.name_of_device
FROM
	device de
	LEFT JOIN registered_user ru USING(registered_user_id)
	LEFT JOIN api_key ap USING(api_key_id)
	LEFT JOIN device_name dn USING(device_name_id)
	LEFT JOIN user_level ul ON ul.user_level_id = ru.user_level_id
WHERE
	de.active = TRUE
	AND de.paused = FALSE
	AND de.device_id = $1";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(device_id.get())
            .fetch_optional(postgres)
            .await?)
    }

    /// Get fully joined device by api_id
    pub async fn get_by_api_key(
        postgres: &PgPool,
        api_key: &ApiKey,
    ) -> Result<Option<Self>, ApiError> {
        let query = "
SELECT
	de.device_id,
	de.max_clients,
	de.structured_data,
	de.client_password_id,
	de.device_password_id,
	ap.api_key_string AS api_key,
	ap.api_key_id,
	ru.registered_user_id,
	ul.max_message_size_in_bytes,
	ul.max_monthly_bandwidth_in_bytes,
	ul.user_level_name AS user_level,
	dn.name_of_device
FROM
	device de
	LEFT JOIN registered_user ru USING(registered_user_id)
	LEFT JOIN api_key ap USING(api_key_id)
	LEFT JOIN device_name dn USING(device_name_id)
	LEFT JOIN user_level ul ON ul.user_level_id = ru.user_level_id
WHERE
	de.active = TRUE
	AND de.paused = FALSE
	AND ap.api_key_string = $1";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(api_key.get())
            .fetch_optional(postgres)
            .await?)
    }
}

#[expect(clippy::struct_excessive_bools)]
#[derive(sqlx::FromRow, Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelDevice {
    #[serde(skip_serializing)]
    pub device_id: DeviceId,
    pub creation_date: String,
    pub paused: bool,
    pub max_clients: i16,
    pub structured_data: bool,
    pub api_key: ApiKey,
    pub client_password_required: bool,
    #[serde(skip_serializing)]
    pub client_password_id: Option<DevicePasswordId>,
    pub device_password_required: bool,
    #[serde(skip_serializing)]
    pub device_password_id: Option<DevicePasswordId>,
    pub name_of_device: String,
    pub timestamp_online: Option<String>,
    pub timestamp_offline: Option<String>,

    pub ip: Option<IpAddr>,

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

impl ModelDevice {
    /// Delete all devices, remove all/any message caches, and remove all connections to these devices
    pub async fn delete_all_device_cache_connections(
        postgres: &PgPool,
        redis: &RedisPool,
        connections: &Arc<Mutex<Connections>>,
        user: &ModelUser,
    ) -> Result<(), ApiError> {
        let device_ids = Self::delete_all(postgres, user).await?;
        connections
            .lock()
            .await
            .close_by_multiple_device_id(&device_ids)
            .await;

        MessageCache::delete_all(redis, &device_ids).await?;

        Ok(())
    }

    /// Delete all devices belonging to a user
    async fn delete_all(
        postgres: &PgPool,
        user: &ModelUser,
    ) -> Result<Vec<ModelDeviceId>, ApiError> {
        let mut transaction = postgres.begin().await?;

        let query = "
UPDATE
	api_key
SET
	active = FALSE
WHERE
	registered_user_id = $1";
        sqlx::query(query)
            .bind(user.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;

        let query = "
UPDATE
	device
SET
	active = FALSE
WHERE
	registered_user_id = $1";
        sqlx::query(query)
            .bind(user.registered_user_id.get())
            .execute(&mut *transaction)
            .await?;

        let query = "
SELECT
	device_id
FROM
	device
WHERE
	registered_user_id = $1";
        let device_ids = sqlx::query_as::<_, ModelDeviceId>(query)
            .bind(user.registered_user_id.get())
            .fetch_all(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(device_ids)
    }

    /// Get count of total number current active (as in not deleted) devices for a given user
    pub async fn count(postgres: &PgPool, user: &ModelUser) -> Result<i64, ApiError> {
        let query = "
SELECT
	COUNT(*)
FROM
	device
WHERE
	registered_user_id = $1
	AND active = TRUE";
        let count = sqlx::query_as::<_, Count>(query)
            .bind(user.registered_user_id.get())
            .fetch_one(postgres)
            .await?;
        Ok(count.count)
    }

    /// Toggle the devices paused state
    pub async fn update_paused(&self, postgres: &PgPool, pause: bool) -> Result<(), ApiError> {
        let query = "
UPDATE
	device
SET
	paused = $1
WHERE
	device_id = $2";
        sqlx::query(query)
            .bind(pause)
            .bind(self.device_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    /// Update a devices devce/client password
    pub async fn update_password(
        &self,
        postgres: &PgPool,
        set_password: ij::ClientDevicePassword,
    ) -> Result<(), ApiError> {
        let mut transaction = postgres.begin().await?;

        let client_hash_id = ModelDevicePasswordHash::insert(
            &mut transaction,
            ArgonHash::new(set_password.client_password).await?,
        )
        .await?
        .device_password_id;

        let device_hash_id = ModelDevicePasswordHash::insert(
            &mut transaction,
            ArgonHash::new(set_password.device_password).await?,
        )
        .await?
        .device_password_id;

        let query = "
UPDATE
	device
SET
	client_password_id = $1,
	device_password_id = $2
WHERE
	device_id = $3";
        sqlx::query(query)
            .bind(client_hash_id.get())
            .bind(device_hash_id.get())
            .bind(self.device_id.get())
            .execute(&mut *transaction)
            .await?;
        Ok(transaction.commit().await?)
    }

    /// Remove password from a device
    pub async fn remove_password(&self, postgres: &PgPool) -> Result<(), ApiError> {
        let mut transaction = postgres.begin().await?;

        let query = "
UPDATE
	device
SET
	client_password_id = NULL,
	device_password_id = NULL
WHERE
	device_id = $1";
        sqlx::query(query)
            .bind(self.device_id.get())
            .execute(&mut *transaction)
            .await?;

        if let Some(id) = self.client_password_id {
            ModelDevicePasswordHash::delete(&mut transaction, id).await?;
        }

        if let Some(id) = self.device_password_id {
            ModelDevicePasswordHash::delete(&mut transaction, id).await?;
        }

        Ok(transaction.commit().await?)
    }

    /// Toggle a devices strucuted data setting
    pub async fn update_structured_data(
        &self,
        postgres: &PgPool,
        structured_data: bool,
    ) -> Result<(), ApiError> {
        let query = "
UPDATE
	device
SET
	structured_data = $1
WHERE
	device_id = $2";
        sqlx::query(query)
            .bind(structured_data)
            .bind(self.device_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    /// Alter devices max_client setting
    pub async fn update_max_client(
        &self,
        postgres: &PgPool,
        max_clients: i16,
    ) -> Result<(), ApiError> {
        let query = "
UPDATE
	device
SET
	max_clients = $1
WHERE
	device_id = $2";
        sqlx::query(query)
            .bind(max_clients)
            .bind(self.device_id.get())
            .execute(postgres)
            .await?;
        Ok(())
    }

    /// Alter devices name
    pub async fn update_name(&self, postgres: &PgPool, name: String) -> Result<(), ApiError> {
        let mut transaction = postgres.begin().await?;
        let device_name = DeviceName::insert(&mut transaction, &name).await?;
        let query = "
UPDATE
	device
SET
	device_name_id = $1
WHERE
	device_id = $2";
        sqlx::query(query)
            .bind(device_name.device_name_id.get())
            .bind(self.device_id.get())
            .execute(&mut *transaction)
            .await?;
        Ok(transaction.commit().await?)
    }

    /// Get fully joined device by name & user_id
    pub async fn get_by_name(
        postgres: &PgPool,
        user: &ModelUser,
        device_name: &str,
    ) -> Result<Option<Self>, ApiError> {
        let query = format!("{QUERY} AND name_of_device = $2");
        Ok(sqlx::query_as::<_, Self>(&query)
            .bind(user.registered_user_id.get())
            .bind(device_name)
            .fetch_optional(postgres)
            .await?)
    }

    /// Delete device by name & user_id
    pub async fn delete_by_name(
        postgres: &PgPool,
        user: &ModelUser,
        device_name: &str,
    ) -> Result<Option<DeviceId>, ApiError> {
        let mut transaction = postgres.begin().await?;

        let query = r"
UPDATE
	device
SET
	active = FALSE
WHERE
	registered_user_id = $1
	AND device_name_id = (
		SELECT
			device_name_id
		FROM
			device_name
		WHERE
			name_of_device = $2
	) RETURNING device_id,
	api_key_id";
        if let Some(device_api_id) = sqlx::query_as::<_, ModelDeviceIdApiKeyId>(query)
            .bind(user.registered_user_id.get())
            .bind(device_name)
            .fetch_optional(&mut *transaction)
            .await?
        {
            let query = "
UPDATE
	api_key
SET
	active = FALSE
WHERE
	api_key_id = $1";
            sqlx::query(query)
                .bind(device_api_id.api_key_id.get())
                .execute(&mut *transaction)
                .await?;

            transaction.commit().await?;
            Ok(Some(device_api_id.device_id))
        } else {
            Ok(None)
        }
    }

    /// Get fully joined  all device's limited to user_id
    pub async fn get_all(postgres: &PgPool, user: &ModelUser) -> Result<Vec<Self>, ApiError> {
        let query = format!("{QUERY} ORDER BY de.timestamp ASC;");
        Ok(sqlx::query_as::<_, Self>(&query)
            .bind(user.registered_user_id.get())
            .fetch_all(postgres)
            .await?)
    }

    /// Get list of device_ids for a single user
    pub async fn get_all_device_id(
        postgres: &PgPool,
        user: &ModelUser,
    ) -> Result<Vec<DeviceId>, ApiError> {
        let query = r"
SELECT
    de.device_id
FROM
    device de
WHERE
    de.registered_user_id = $1
AND
    de.active = true";
        let output = sqlx::query_as::<_, ModelDeviceId>(query)
            .bind(user.registered_user_id.get())
            .fetch_all(postgres)
            .await?;
        Ok(output.iter().map(|i| i.device_id).collect::<Vec<_>>())
    }

    /// This is a recursive method, that creates a random name, then checks if the user has an active device with that name
    /// if the user does have a device with that name, it'll call itself again, ad infinitum
    fn create_device_name<'a>(
        user: &'a ModelUser,
        transaction: &'a mut Transaction<'_, Postgres>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ApiError>> + 'a + Send>> {
        Box::pin(async move {
            let device_name = gen_random_device_name();
            if DeviceName::exists_for_user(transaction, &device_name, user).await? {
                Ok(Self::create_device_name(user, transaction).await?)
            } else {
                Ok(device_name)
            }
        })
    }

    /// Insert a new device, create an `api_key`, hash passwords if present,
    pub async fn insert(
        postgres: &PgPool,
        useragent_ip: ModelUserAgentIp,
        user: &ModelUser,
        new_device: ij::DevicePost,
    ) -> Result<String, ApiError> {
        let mut transaction = postgres.begin().await?;
        let api_key_id = ModelApiKey::insert(&mut transaction, user, &useragent_ip)
            .await?
            .api_key_id;

        let client_password_id = if let Some(password) = new_device.client_password {
            let hash = ArgonHash::new(password).await?;
            Some(
                ModelDevicePasswordHash::insert(&mut transaction, hash)
                    .await?
                    .device_password_id,
            )
        } else {
            None
        };

        let device_password_id = if let Some(password) = new_device.device_password {
            let hash = ArgonHash::new(password).await?;
            Some(
                ModelDevicePasswordHash::insert(&mut transaction, hash)
                    .await?
                    .device_password_id,
            )
        } else {
            None
        };

        let device_name = if let Some(name) = new_device.name.as_ref() {
            DeviceName::insert(&mut transaction, name).await?
        } else {
            let device_name = Self::create_device_name(user, &mut transaction).await?;
            DeviceName::insert(&mut transaction, &device_name).await?
        };

        let query = "
INSERT INTO
	device(
		registered_user_id,
		ip_id,
		user_agent_id,
		device_name_id,
		api_key_id,
		max_clients,
		client_password_id,
		device_password_id,
		structured_data
	)
VALUES
	($1, $2, $3, $4, $5, $6, $7, $8, $9)";
        sqlx::query(query)
            .bind(user.registered_user_id.get())
            .bind(useragent_ip.ip_id.get())
            .bind(useragent_ip.user_agent_id.get())
            .bind(device_name.device_name_id.get())
            .bind(api_key_id.get())
            .bind(new_device.max_clients)
            .bind(client_password_id.map(DevicePasswordId::get))
            .bind(device_password_id.map(DevicePasswordId::get))
            .bind(new_device.structured_data)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(device_name.name_of_device)
    }
}

/// Query to get fully joined device, for frontend api usage
const QUERY: &str = r"
SELECT
	de.device_id,
	de.timestamp :: TEXT AS creation_date,
	de.paused,
	de.max_clients,
	de.structured_data,
	ap.api_key_string AS api_key,
	de.client_password_id,
	de.device_password_id,
	CASE
		WHEN de.client_password_id IS NULL THEN FALSE
		ELSE TRUE
	END AS client_password_required,
	CASE
		WHEN de.device_password_id IS NULL THEN FALSE
		ELSE TRUE
	END AS device_password_required,
	dn.name_of_device,
	(
		SELECT
			co.timestamp_online :: TEXT
		FROM
			connection co
		WHERE
			co.device_id = de.device_id
			AND co.is_pi = TRUE
		ORDER BY
			co.connection_id DESC
		LIMIT
			1
	) AS timestamp_online,
	(
		SELECT
			co.timestamp_offline :: TEXT
		FROM
			connection co
		WHERE
			co.device_id = de.device_id
			AND co.is_pi = TRUE
		ORDER BY
			co.connection_id DESC
		LIMIT
			1
	) AS timestamp_offline,
	(
		SELECT
			ip.ip
		FROM
			connection co
			LEFT JOIN ip_address ip USING(ip_id)
		WHERE
			co.device_id = de.device_id
			AND co.is_pi = TRUE
		ORDER BY
			co.connection_id DESC
		LIMIT
			1
	) AS ip,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = TRUE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = FALSE
	) AS pi_bytes_day_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = TRUE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = TRUE
	) AS pi_bytes_day_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = TRUE
			AND extract(
				month
				FROM
					hb.timestamp
			) = extract(
				month
				FROM
					CURRENT_DATE
			)
			AND extract(
				year
				FROM
					hb.timestamp
			) = extract(
				year
				FROM
					CURRENT_DATE
			)
			AND hb.is_counted = FALSE
	) AS pi_bytes_month_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
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
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = TRUE
			AND hb.is_counted = FALSE
	) AS pi_bytes_total_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = TRUE
			AND hb.is_counted = TRUE
	) AS pi_bytes_total_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = FALSE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = FALSE
	) AS client_bytes_day_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = FALSE
			AND DATE(hb.timestamp) = CURRENT_DATE
			AND hb.is_counted = TRUE
	) AS client_bytes_day_out,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
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
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
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
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = FALSE
			AND hb.is_counted = FALSE
	) AS client_bytes_total_in,
	(
		SELECT
			CASE
				WHEN SUM(size_in_bytes) IS NULL THEN 0 :: BIGINT
				ELSE SUM(size_in_bytes) :: BIGINT
			END
		FROM
			hourly_bandwidth hb
		WHERE
			hb.device_id = de.device_id
			AND hb.is_pi = FALSE
			AND hb.is_counted = TRUE
	) AS client_bytes_total_out,
	(
		SELECT
			co.timestamp_online :: TEXT
		FROM
			connection co
		WHERE
			co.device_id = de.device_id
			AND co.is_pi = TRUE
		ORDER BY
			co.connection_id DESC
		LIMIT
			1
	) AS timestamp_online,
	(
		SELECT
			co.timestamp_offline :: TEXT
		FROM
			connection co
		WHERE
			co.device_id = de.device_id
			AND co.is_pi = TRUE
		ORDER BY
			co.connection_id DESC
		LIMIT
			1
	) AS timestamp_offline
FROM
	device de
	LEFT JOIN api_key ap USING(api_key_id)
	LEFT JOIN device_name dn USING(device_name_id)
WHERE
	de.active = TRUE
	AND de.registered_user_id = $1";

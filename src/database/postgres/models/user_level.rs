use serde::Serialize;
use sqlx::PgPool;
use std::fmt;

use super::new_types::UserLevelId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, sqlx::Decode, sqlx::Encode)]
#[sqlx(rename_all = "lowercase")]
pub enum UserLevel {
    #[serde(rename(serialize = "free"))]
    Free,
    #[serde(rename(serialize = "pro"))]
    Pro,
    #[serde(rename(serialize = "admin"))]
    Admin,
}

impl sqlx::Type<sqlx::Postgres> for UserLevel {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<&str> for UserLevel {
    fn from(user_level: &str) -> Self {
        match user_level {
            "admin" => Self::Admin,
            "pro" => Self::Pro,
            _ => Self::Free,
        }
    }
}

impl fmt::Display for UserLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let x = match self {
            Self::Free => "free",
            Self::Pro => "pro",
            Self::Admin => "admin",
        };
        write!(f, "{x}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, sqlx::FromRow)]
pub struct ModelUserLevel {
    pub user_level_id: UserLevelId,
    pub custom_device_name: bool,
    pub device_password: bool,
    pub structured_data: bool,
    pub max_clients_per_device: i16,
    pub max_message_size_in_bytes: i32,
    pub max_monthly_bandwidth_in_bytes: i64,
    pub max_number_of_devices: i16,
    pub user_level: UserLevel,
}

impl ModelUserLevel {
    pub async fn get(postgres: &PgPool, user_level: UserLevel) -> Result<Self, sqlx::Error> {
        // todo macro?
        let query = r"
SELECT
	ul.user_level_name AS user_level,
	ul.max_message_size_in_bytes,
	ul.max_number_of_devices,
	ul.structured_data,
	ul.device_password,
	ul.max_clients_per_device,
	ul.max_monthly_bandwidth_in_bytes,
	ul.user_level_id,
	ul.custom_device_name
FROM
	user_level ul
WHERE
	ul.user_level_name = $1";
        sqlx::query_as::<_, Self>(query)
            .bind(user_level.to_string())
            .fetch_one(postgres)
            .await
    }
}

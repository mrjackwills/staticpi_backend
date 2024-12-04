use fred::{error::Error, types::FromValue};
use regex::Regex;
use serde::{Deserialize, Serialize, Serializer};
use std::sync::LazyLock;

use crate::{api_error::ApiError, helpers::gen_random_hex, S};

/// Api key, [A-F0-9]{128}
#[derive(Debug, Clone, Eq, PartialEq, sqlx::Decode)]
pub struct ApiKey(String);

impl sqlx::Type<sqlx::Postgres> for ApiKey {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl Serialize for ApiKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("ApiKey", &self.get())
    }
}

impl ApiKey {
    pub fn get(&self) -> String {
        self.0.to_uppercase()
    }
}

impl Default for ApiKey {
    fn default() -> Self {
        Self(gen_random_hex(128))
    }
}

impl From<&str> for ApiKey {
    fn from(x: &str) -> Self {
        Self(S!(x))
    }
}

#[expect(clippy::expect_used)]
pub static REGEX_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#).expect("email regex")
});

#[derive(Debug, Clone, Hash, Eq, PartialEq, sqlx::Decode)]
pub struct EmailAddress(String);

impl EmailAddress {
    pub fn get(&self) -> String {
        self.0.to_lowercase()
    }
}
impl sqlx::Type<sqlx::Postgres> for EmailAddress {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl TryFrom<String> for EmailAddress {
    type Error = ApiError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() || !value.contains('@') {
            return Err(ApiError::InvalidValue(S!("Email invalid")));
        };
        let email = value.to_lowercase();

        if REGEX_EMAIL.is_match(&email) {
            Ok(Self(email))
        } else {
            Err(ApiError::InvalidValue(S!("Email invalid")))
        }
    }
}

impl Serialize for EmailAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("Email", &self.get())
    }
}

/// Macro to create Generic NewType SQL ids
macro_rules! generic_id {
    ($struct_name:ident) => {
        #[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
        pub struct $struct_name(i64);

        impl sqlx::Type<sqlx::Postgres> for $struct_name {
            fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
                <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
            }
        }

        impl From<i64> for $struct_name {
            fn from(x: i64) -> Self {
                Self(x)
            }
        }

        impl FromValue for $struct_name {
            fn from_value(value: fred::prelude::Value) -> Result<Self, fred::prelude::Error> {
                value.as_i64().map_or(
                    Err(Error::new(
                        fred::error::ErrorKind::Parse,
                        format!("FromRedis: {}", stringify!($struct_name)),
                    )),
                    |i| Ok(Self(i)),
                )
            }
        }

        impl Serialize for $struct_name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_newtype_struct(stringify!($struct_name), &self.get())
            }
        }

        impl $struct_name {
            pub const fn get(self) -> i64 {
                self.0
            }
        }
    };
}

generic_id!(ApiKeyId);
generic_id!(ConnectionId);
generic_id!(ContactMessageId);
generic_id!(DeviceId);
generic_id!(DeviceNameId);
generic_id!(DevicePasswordId);
generic_id!(EmailAddressId);
generic_id!(EmailLogId);
generic_id!(EmailSubjectId);
generic_id!(InviteId);
generic_id!(PasswordResetId);
generic_id!(TwoFaBackupId);
generic_id!(TwoFaSecretId);
generic_id!(UserId);
generic_id!(UserLevelId);
generic_id!(UserAgentId);
generic_id!(IpId);

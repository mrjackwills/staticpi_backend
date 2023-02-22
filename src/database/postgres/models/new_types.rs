use once_cell::sync::Lazy;
use redis::{FromRedisValue, RedisResult, Value};
use regex::Regex;
use serde::{Deserialize, Serialize, Serializer};

use crate::{api_error::ApiError, database::string_to_struct, helpers::gen_random_hex};

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
        Self(x.to_owned())
    }
}

/// Api key id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct ApiKeyId(i64);

impl sqlx::Type<sqlx::Postgres> for ApiKeyId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for ApiKeyId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for ApiKeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("ApiKeyId", &self.get())
    }
}

impl ApiKeyId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[allow(clippy::expect_used)]
pub static REGEX_EMAIL: Lazy<Regex> = Lazy::new(|| {
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
            return Err(ApiError::InvalidValue("Email invalid".to_owned()));
        };
        let email = value.to_lowercase();

        if REGEX_EMAIL.is_match(&email) {
            Ok(Self(email))
        } else {
            Err(ApiError::InvalidValue("Email invalid".to_owned()))
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

/// connection id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode)]
pub struct ConnectionId(i64);

impl sqlx::Type<sqlx::Postgres> for ConnectionId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for ConnectionId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for ConnectionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("ConnectionId", &self.get())
    }
}

impl ConnectionId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// device_id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct DeviceId(i64);

impl sqlx::Type<sqlx::Postgres> for DeviceId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for DeviceId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("DeviceId", &self.get())
    }
}

impl DeviceId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// registered_user_id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct UserId(i64);

impl sqlx::Type<sqlx::Postgres> for UserId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for UserId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for UserId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("UserId", &self.get())
    }
}

impl UserId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// invite_id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct InviteId(i64);

impl sqlx::Type<sqlx::Postgres> for InviteId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for InviteId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for InviteId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("InviteId", &self.get())
    }
}

impl InviteId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// ip address id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct IpId(i64);

impl sqlx::Type<sqlx::Postgres> for IpId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for IpId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for IpId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("IpId", &self.get())
    }
}

impl IpId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl FromRedisValue for IpId {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

/// User Agent id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct UserAgentId(i64);

impl sqlx::Type<sqlx::Postgres> for UserAgentId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for UserAgentId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for UserAgentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("UserAgentId", &self.get())
    }
}

impl UserAgentId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl FromRedisValue for UserAgentId {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        string_to_struct::<Self>(v)
    }
}

/// Device password id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct DevicePasswordId(i64);

impl sqlx::Type<sqlx::Postgres> for DevicePasswordId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for DevicePasswordId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for DevicePasswordId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("DevicePasswordId", &self.get())
    }
}

impl DevicePasswordId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Device Name id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct DeviceNameId(i64);

impl sqlx::Type<sqlx::Postgres> for DeviceNameId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for DeviceNameId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for DeviceNameId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("DeviceNameId", &self.get())
    }
}

impl DeviceNameId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Email address id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct EmailAddressId(i64);

impl sqlx::Type<sqlx::Postgres> for EmailAddressId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for EmailAddressId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for EmailAddressId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("EmailAddressId", &self.get())
    }
}

impl EmailAddressId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// User level id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct UserLevelId(i64);

impl sqlx::Type<sqlx::Postgres> for UserLevelId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for UserLevelId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for UserLevelId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("UserLevelId", &self.get())
    }
}

impl UserLevelId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Two FA Secret id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct TwoFaSecretId(i64);

impl sqlx::Type<sqlx::Postgres> for TwoFaSecretId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for TwoFaSecretId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for TwoFaSecretId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("TwoFaSecretId", &self.get())
    }
}

impl TwoFaSecretId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Two FA backup (secret) id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct TwoFaBackupId(i64);

impl sqlx::Type<sqlx::Postgres> for TwoFaBackupId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for TwoFaBackupId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for TwoFaBackupId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("TwoFaBackupId", &self.get())
    }
}

impl TwoFaBackupId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Password reset id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct PasswordResetId(i64);

impl sqlx::Type<sqlx::Postgres> for PasswordResetId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for PasswordResetId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for PasswordResetId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("PasswordResetId", &self.get())
    }
}

impl PasswordResetId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// email_subject, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct EmailSubjectId(i64);

impl sqlx::Type<sqlx::Postgres> for EmailSubjectId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for EmailSubjectId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for EmailSubjectId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("EmailSubjectId", &self.get())
    }
}

impl EmailSubjectId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// device_id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct EmailLogId(i64);

impl sqlx::Type<sqlx::Postgres> for EmailLogId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for EmailLogId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for EmailLogId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("EmailLogId", &self.get())
    }
}

impl EmailLogId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// contact_message id, i64 > 0
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, sqlx::Decode, Deserialize)]
pub struct ContactMessageId(i64);

impl sqlx::Type<sqlx::Postgres> for ContactMessageId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl From<i64> for ContactMessageId {
    fn from(x: i64) -> Self {
        Self(x)
    }
}

impl Serialize for ContactMessageId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct("ContactMessageId", &self.get())
    }
}

impl ContactMessageId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

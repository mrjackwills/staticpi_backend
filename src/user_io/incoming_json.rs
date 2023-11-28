pub mod ij {
    use crate::{
        api_error::ApiError,
        connections::ConnectionType,
        database::{
            new_types::{ContactMessageId, DeviceId},
            rate_limit::RateLimit,
        },
        user_io::deserializer::IncomingDeserializer as is,
    };

    use std::{error::Error, fmt};

    use axum::{
        async_trait,
        extract::{
            rejection::{JsonDataError, JsonRejection},
            FromRequest, FromRequestParts,
        },
        http::{request::Parts, Request},
    };
    use serde::{self, de::DeserializeOwned, Deserialize};
    use tracing::trace;

    #[cfg(test)]
    use serde::Serialize;
    use ulid::Ulid;

    /// attempt to extract the inner `serde_json::Error`, if that succeeds we can
    /// provide a more specific error
    // see https://docs.rs/axum/latest/axum/extract/index.html#accessing-inner-errors
    fn extract_serde_error<E>(e: E) -> ApiError
    where
        E: Error + 'static,
    {
        if let Some(err) = find_error_source::<JsonDataError>(&e) {
            let text = err.body_text();
            if text.contains("missing field") {
                return ApiError::MissingKey(
                    text.split_once("missing field `")
                        .map_or("", |f| f.1)
                        .split_once('`')
                        .map_or("", |f| f.0.trim())
                        .to_owned(),
                );
            } else if text.contains("unknown field") {
                return ApiError::InvalidValue("invalid input".to_owned());
            } else if text.contains("at line") {
                return ApiError::InvalidValue(
                    text.split_once("at line")
                        .map_or("", |f| f.0)
                        .split_once(':')
                        .map_or("", |f| f.1)
                        .split_once(':')
                        .map_or("", |f| f.1.trim())
                        .to_owned(),
                );
            }
        }
        ApiError::Internal("downcast error".to_owned())
    }

    /// attempt to downcast `err` into a `T` and if that fails recursively try and
    /// downcast `err`'s source
    fn find_error_source<'a, T>(err: &'a (dyn Error + 'static)) -> Option<&'a T>
    where
        T: Error + 'static,
    {
        err.downcast_ref::<T>().map_or_else(
            || err.source().and_then(|source| find_error_source(source)),
            Some,
        )
    }

    /// Two Factor Backup tokens can either be totp - [0-9]{6}, or backup tokens - [A-F0-9]{16}
    #[derive(Debug, Deserialize, Clone)]
    #[cfg_attr(test, derive(Serialize))]
    pub enum Token {
        Totp(String),
        Backup(String),
    }

    impl fmt::Display for Token {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let x = match self {
                Self::Totp(token) | Self::Backup(token) => token,
            };
            write!(f, "{x}")
        }
    }

    pub struct IncomingJson<T>(pub T);

    /// Implement custom error handing for JSON extraction on incoming JSON
    /// Either return valid json (meeting a struct spec listed below), or return an ApiError
    /// Then each route handler, can use `IncomingJson(body): IncomingJson<T>`, to extract T into param body
    #[async_trait]
    impl<S, T> FromRequest<S> for IncomingJson<T>
    where
        axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
        S: Send + Sync,
    {
        type Rejection = ApiError;

        async fn from_request(
            req: Request<axum::body::Body>,
            state: &S,
        ) -> Result<Self, Self::Rejection> {
            match axum::Json::<T>::from_request(req, state).await {
                Ok(value) => Ok(Self(value.0)),
                Err(rejection) => match rejection {
                    JsonRejection::JsonDataError(e) => Err(extract_serde_error(e)),
                    JsonRejection::JsonSyntaxError(_) => {
                        Err(ApiError::InvalidValue("JSON".to_owned()))
                    }
                    JsonRejection::MissingJsonContentType(e) => {
                        trace!("{e:?}");
                        Err(ApiError::InvalidValue(
                            "\"application/json\" header".to_owned(),
                        ))
                    }
                    JsonRejection::BytesRejection(e) => {
                        trace!("{e:?}");
                        trace!("BytesRejection");
                        Err(ApiError::InvalidValue("Bytes Rejected".to_owned()))
                    }
                    _ => Err(ApiError::Internal(String::from(
                        "IncomingJson from_request error",
                    ))),
                },
            }
        }
    }

    // We define our own `Path` extractor that customizes the error from `axum::extract::Path`
    pub struct Path<T>(pub T);

    #[async_trait]
    impl<S, T> FromRequestParts<S> for Path<T>
    where
        // these trait bounds are copied from `impl FromRequest for axum::extract::path::Path`
        T: DeserializeOwned + Send,
        S: Send + Sync,
    {
        type Rejection = ApiError;
        async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
            match axum::extract::Path::<T>::from_request_parts(parts, state).await {
                Ok(value) => Ok(Self(value.0)),
                Err(e) => Err(ApiError::InvalidValue(format!("invalid {e} param"))),
            }
        }
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    #[cfg_attr(test, derive(Serialize))]
    pub struct Register {
        #[serde(deserialize_with = "is::name")]
        pub full_name: String,
        #[serde(deserialize_with = "is::email")]
        pub email: String,
        #[serde(deserialize_with = "is::password")]
        pub password: String,
        #[serde(deserialize_with = "is::invite")]
        pub invite: String,
        pub age: bool,
        pub agree: bool,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct Signin {
        #[serde(deserialize_with = "is::email")]
        pub email: String,
        pub password: String,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_token")]
        pub token: Option<Token>,
        pub remember: bool,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct Contact {
        #[serde(deserialize_with = "is::email")]
        pub email: String,
        #[serde(deserialize_with = "is::message")]
        pub message: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct Reset {
        #[serde(deserialize_with = "is::email")]
        pub email: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct AccessToken {
        #[serde(deserialize_with = "is::ulid")]
        pub access_token: Ulid,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PasswordToken {
        pub password: String,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_token")]
        pub token: Option<Token>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct TwoFA {
        #[serde(deserialize_with = "is::token")]
        pub token: Token,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct TwoFAAlwaysRequired {
        #[serde(default)]
        #[serde(deserialize_with = "is::option_password")]
        pub password: Option<String>,
        pub always_required: bool,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_token")]
        pub token: Option<Token>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PatchName {
        #[serde(deserialize_with = "is::name")]
        pub full_name: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct PatchPassword {
        #[serde(deserialize_with = "is::password")]
        pub current_password: String,
        #[serde(deserialize_with = "is::password")]
        pub new_password: String,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_token")]
        pub token: Option<Token>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[cfg_attr(test, derive(Serialize))]
    pub struct DeviceMaxClients {
        #[serde(deserialize_with = "is::max_clients")]
        pub max_clients: i16,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[cfg_attr(test, derive(Serialize))]
    pub struct DevicePost {
        #[serde(deserialize_with = "is::max_clients")]
        pub max_clients: i16,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_device_password")]
        pub client_password: Option<String>,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_device_password")]
        pub device_password: Option<String>,
        pub structured_data: bool,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_device_name")]
        pub name: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ClientDevicePassword {
        #[serde(deserialize_with = "is::device_password")]
        pub client_password: String,
        #[serde(deserialize_with = "is::device_password")]
        pub device_password: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DevicePause {
        pub pause: bool,
    }
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeviceStructured {
        pub structured_data: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeviceRename {
        #[serde(default)]
        #[serde(deserialize_with = "is::device_name")]
        pub new_name: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[cfg_attr(test, derive(Serialize))]
    pub struct UserPatch {
        pub active: Option<bool>,
        pub attempt: Option<bool>,
        #[serde(default, deserialize_with = "is::option_id")]
        pub password_reset_id: Option<i64>,
        pub reset: Option<bool>,
        pub two_fa_secret: Option<bool>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[cfg_attr(test, derive(Serialize))]
    pub struct EmailPost {
        #[serde(deserialize_with = "is::vec_email")]
        pub emails: Vec<String>,
        pub title: String,
        pub line_one: String,
        pub line_two: Option<String>,
        pub button_text: Option<String>,
        pub link: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuthKeyPassword {
        pub key: String,
        pub password: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Limit {
        #[serde(deserialize_with = "is::rate_limit")]
        pub key: RateLimit,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct UserSession {
        #[serde(deserialize_with = "is::user_session")]
        pub session: Ulid,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AdminConnectionRemove {
        #[serde(deserialize_with = "is::device_id")]
        pub device_id: DeviceId,
        #[serde(deserialize_with = "is::ulid")]
        pub connection_ulid: Ulid,
        #[serde(deserialize_with = "is::device_type")]
        pub device_type: ConnectionType,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AdminContactMessage {
        #[serde(deserialize_with = "is::contact_message_id")]
        pub contact_message_id: ContactMessageId,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct AdminDevice {
        #[serde(deserialize_with = "is::email")]
        pub email: String,
        pub device_name: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    #[cfg_attr(test, derive(Serialize))]
    pub struct AdminInvite {
        pub password: String,
        #[serde(default)]
        #[serde(deserialize_with = "is::option_token")]
        pub token: Option<Token>,
        #[serde(deserialize_with = "is::invite")]
        pub invite: String,
        pub count: i16,
    }

    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct AdminInvitePatch {
        #[serde(deserialize_with = "is::invite")]
        pub invite: String,
    }
}

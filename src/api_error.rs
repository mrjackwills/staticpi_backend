use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use fred::error::{RedisError, RedisErrorKind};
use std::time::SystemTimeError;
use thiserror::Error;
use tokio::task::JoinError;
use tracing::error;

use crate::user_io::outgoing_json::oj::OutgoingJson;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Access token")]
    AccessToken,
    #[error("Invalid Authentication")]
    Authentication,
    #[error("Invalid email address and/or password and/or token")]
    Authorization,
    #[error("Axum")]
    AxumExtension(#[from] axum::extract::rejection::ExtensionRejection),
    #[error("conflict")]
    Conflict(String),
    #[error("Internal Server Error")]
    Internal(String),
    #[error("invalid")]
    InvalidValue(String),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("missing")]
    MissingKey(String),
    #[error("rate limited for")]
    RateLimited(i64),
    #[error("redis error")]
    RedisError(#[from] RedisError),
    #[error("reqwest")]
    Reqwest(#[from] reqwest::Error),
    #[error("internal error")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Internal Database Error")]
    SqlxError(#[from] sqlx::Error),
    #[error("thread error")]
    ThreadError(#[from] JoinError),
    #[error("time error")]
    TimeError(#[from] SystemTimeError),
}

/// Return the internal server error, with a basic { response: "$prefix" }
macro_rules! internal {
    ($prefix:expr) => {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(OutgoingJson::new($prefix)),
        )
    };
}

#[expect(clippy::cognitive_complexity)]
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let exit = || {
            error!("EXITING");
            std::process::exit(1);
        };

        let prefix = self.to_string();
        let (status, op_body) = match self {
            Self::AccessToken => (StatusCode::BAD_REQUEST, None),
            Self::Authorization => (StatusCode::UNAUTHORIZED, Some(OutgoingJson::new(prefix))),
            Self::Authentication => (StatusCode::FORBIDDEN, Some(OutgoingJson::new(prefix))),
            Self::AxumExtension(e) => {
                error!("{e:?}");
                internal!(prefix)
            }
            Self::Conflict(conflict) => (StatusCode::CONFLICT, Some(OutgoingJson::new(conflict))),
            Self::Internal(e) => {
                error!("{e:?}");
                internal!(prefix)
            }
            Self::InvalidValue(value) => (StatusCode::BAD_REQUEST, Some(OutgoingJson::new(value))),
            Self::Io(e) => {
                error!("{e:?}");
                internal!(prefix)
            }
            Self::MissingKey(key) => (
                StatusCode::BAD_REQUEST,
                Some(OutgoingJson::new(format!("{prefix} {key}"))),
            ),

            Self::RateLimited(limit) => (
                StatusCode::TOO_MANY_REQUESTS,
                Some(OutgoingJson::new(format!("{prefix} {limit} seconds"))),
            ),
            Self::RedisError(e) => {
                error!("{e:?}");
                if e.kind() == &RedisErrorKind::IO {
                    exit();
                }
                internal!(prefix)
            }
            Self::Reqwest(e) => {
                error!("{e:?}");
                internal!(prefix)
            }
            Self::SerdeJson(_) => internal!(prefix),
            Self::SqlxError(e) => {
                error!("{e:?}");
                match e {
                    sqlx::Error::Io(_) | sqlx::Error::PoolClosed | sqlx::Error::PoolTimedOut => {
                        exit();
                    }
                    _ => (),
                };
                internal!(prefix)
            }
            Self::ThreadError(e) => {
                error!("{e:?}");
                internal!(prefix)
            }
            Self::TimeError(e) => {
                error!("{e:?}");
                internal!(prefix)
            }
        };
        op_body.map_or((status).into_response(), |body| {
            (status, body).into_response()
        })
    }
}

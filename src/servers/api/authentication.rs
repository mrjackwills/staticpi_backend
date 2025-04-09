use axum::{extract::State, http::Request, middleware::Next, response::Response};
use axum_extra::extract::PrivateCookieJar;
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{
    S,
    api_error::ApiError,
    argon::verify_password,
    database::{
        new_types::UserId, session::RedisSession, two_fa_backup::ModelTwoFABackup, user::ModelUser,
        user_level::UserLevel,
    },
    servers::{ApplicationState, get_cookie_ulid},
    user_io::incoming_json::ij::Token,
};

/// Generate a secret to TOTP from a given secret
pub fn totp_from_secret(secret: &str) -> Result<TOTP, ApiError> {
    if let Ok(secret_as_bytes) = Secret::Raw(secret.as_bytes().to_vec()).to_bytes() {
        if let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_as_bytes) {
            return Ok(totp);
        }
    }
    Err(ApiError::Internal(S!("TOTP ERROR")))
}

/// Validate an 2fa token
pub async fn check_token(
    token: Option<Token>,
    postgres: &PgPool,
    two_fa_secret: &str,
    registered_user_id: UserId,
    two_fa_backup_count: i64,
) -> Result<bool, ApiError> {
    if let Some(token) = token {
        match token {
            Token::Totp(token_text) => {
                let totp = totp_from_secret(two_fa_secret)?;
                return Ok(totp.check_current(&token_text)?);
            }
            Token::Backup(token_text) => {
                if two_fa_backup_count > 0 {
                    let backups = ModelTwoFABackup::get(postgres, registered_user_id).await?;
                    for backup_code in backups {
                        if verify_password(&token_text, backup_code.as_hash()).await? {
                            ModelTwoFABackup::delete_one(postgres, backup_code.two_fa_backup_id)
                                .await?;
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }
    Ok(false)
}

/// Just check password, only used in signin flow, before checking
pub async fn check_signin_password(user: &ModelUser, password: &str) -> Result<bool, ApiError> {
    verify_password(password, user.get_password_hash()).await
}

/// Check that a given password, and token, is valid, will check backup tokens as well
pub async fn check_password_token(
    user: &ModelUser,
    password: &str,
    token: Option<Token>,
    postgres: &PgPool,
) -> Result<bool, ApiError> {
    if verify_password(password, user.get_password_hash()).await? {
        if let Some(two_fa_secret) = &user.two_fa_secret {
            let valid_token = check_token(
                token,
                postgres,
                two_fa_secret,
                user.registered_user_id,
                user.two_fa_backup_count,
            )
            .await?;
            return Ok(valid_token);
        }
        return Ok(true);
    }
    Ok(false)
}

/// Check that a given password, and if two_fa_always required, will check against token as well
pub async fn check_password_op_token(
    user: &ModelUser,
    password: &str,
    token: Option<Token>,
    postgres: &PgPool,
) -> Result<bool, ApiError> {
    if verify_password(password, user.get_password_hash()).await? {
        if let Some(two_fa_secret) = &user.two_fa_secret {
            if user.two_fa_always_required {
                if token.is_none() && user.two_fa_always_required {
                    return Ok(false);
                }

                let valid_token = check_token(
                    token,
                    postgres,
                    two_fa_secret,
                    user.registered_user_id,
                    user.two_fa_backup_count,
                )
                .await?;
                return Ok(valid_token);
            }
        }
        return Ok(true);
    }
    Ok(false)
}

/// Middleware for only allowing access to routes if no logged in sessions
pub async fn not_authenticated(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(ulid) = get_cookie_ulid(&state, &jar) {
        if RedisSession::exists(&state.redis, &ulid).await?.is_some() {
            return Err(ApiError::Authentication);
        }
    }
    Ok(next.run(req).await)
}

/// Middleware for only allowing access to routes if currently authenticated
pub async fn is_authenticated(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(ulid) = get_cookie_ulid(&state, &jar) {
        if RedisSession::exists(&state.redis, &ulid).await?.is_some() {
            return Ok(next.run(req).await);
        }
    }
    Err(ApiError::Authentication)
}

/// Middleware for only allowing access to routes if currently admin & authenticated
/// Will send a 403 to the frontend, instead of 401 from the other is_x() methods, which logs out the frontend user
pub async fn is_admin_authenticated(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(ulid) = get_cookie_ulid(&state, &jar) {
        if let Some(model_user) = RedisSession::get(&state.redis, &state.postgres, &ulid).await? {
            if model_user.user_level == UserLevel::Admin {
                return Ok(next.run(req).await);
            }
        }
    }
    Err(ApiError::Authentication)
}

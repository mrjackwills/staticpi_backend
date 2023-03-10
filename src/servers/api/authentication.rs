use axum::{extract::State, http::Request, middleware::Next, response::Response};
use axum_extra::extract::PrivateCookieJar;
use google_authenticator::GoogleAuthenticator;
use sqlx::PgPool;
use ulid::Ulid;

use crate::{
    api_error::ApiError,
    argon::verify_password,
    database::{
        new_types::UserId, session::RedisSession, two_fa_backup::ModelTwoFABackup, user::ModelUser,
        user_level::UserLevel,
    },
    servers::ApplicationState,
    user_io::incoming_json::ij::Token,
};

/// Validate an 2fa token
pub async fn check_token(
    token: Option<Token>,
    postgres: &PgPool,
    two_fa_secret: &str,
    registered_user_id: UserId,
    two_fa_backup_count: i64,
) -> Result<bool, ApiError> {
    if let Some(token) = token {
        let auth = GoogleAuthenticator::new();
        match token {
            Token::Totp(token_text) => {
                return Ok(auth.verify_code(two_fa_secret, &token_text, 0, 0))
            }
            Token::Backup(token_text) => {
                // SHOULD USE A TRANSACTION!?
                if two_fa_backup_count > 0 {
                    let backups = ModelTwoFABackup::get(postgres, registered_user_id).await?;

                    let mut backup_token_id = None;
                    for backup_code in backups {
                        if verify_password(&token_text, backup_code.as_hash()).await? {
                            backup_token_id = Some(backup_code.two_fa_backup_id);
                        }
                    }
                    // Delete backup code if it's valid
                    if let Some(id) = backup_token_id {
                        ModelTwoFABackup::delete_one(postgres, id).await?;
                    } else {
                        return Ok(false);
                    }
                }
            }
        };
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
    let valid_password = verify_password(password, user.get_password_hash()).await?;

    if let Some(two_fa_secret) = &user.two_fa_secret {
        let valid_token = check_token(
            token,
            postgres,
            two_fa_secret,
            user.registered_user_id,
            user.two_fa_backup_count,
        )
        .await?;
        return Ok(valid_password && valid_token);
    }
    Ok(valid_password)
}

/// Check that a given password, and if two_fa_always required, will check against token as well
pub async fn check_password_op_token(
    user: &ModelUser,
    password: &str,
    token: Option<Token>,
    postgres: &PgPool,
) -> Result<bool, ApiError> {
    let valid_password = verify_password(password, user.get_password_hash()).await?;

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
            return Ok(valid_password && valid_token);
        }
    }
    Ok(valid_password)
}

/// Middleware for only allowing access to routes if no logged in sessions
pub async fn not_authenticated<B: Send + Sync>(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    if let Some(data) = jar.get(&state.cookie_name) {
        if let Ok(ulid) = Ulid::from_string(data.value()) {
            if RedisSession::exists(&state.redis, &ulid).await?.is_some() {
                return Err(ApiError::Authentication);
            }
        }
    }
    Ok(next.run(req).await)
}

/// Middleware for only allowing access to routes if currently authenticated
pub async fn is_authenticated<B: Send + Sync>(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    if let Some(data) = jar.get(&state.cookie_name) {
        if let Ok(ulid) = Ulid::from_string(data.value()) {
            if RedisSession::exists(&state.redis, &ulid).await?.is_some() {
                return Ok(next.run(req).await);
            }
        }
    }
    Err(ApiError::Authentication)
}

/// Middleware for only allowing access to routes if currently admin & authenticated
/// Will send a 403 to the frontend, instead of 401 from the other is_x() methods, which logs out the frontend user
pub async fn is_admin_authenticated<B: Send + Sync>(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    if let Some(data) = jar.get(&state.cookie_name) {
        if let Ok(ulid) = Ulid::from_string(data.value()) {
            if let Some(model_user) =
                RedisSession::get(&state.redis, &state.postgres, &ulid).await?
            {
                match model_user.user_level {
                    UserLevel::Admin => {
                        return Ok(next.run(req).await);
                    }
                    _ => return Err(ApiError::Authentication),
                }
            }
        }
    }
    Err(ApiError::Authentication)
}

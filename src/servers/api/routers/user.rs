use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Router,
};
use axum_extra::extract::{cookie::Cookie, PrivateCookieJar};
use futures::{stream::FuturesUnordered, StreamExt};
use std::fmt;
use ulid::Ulid;

use crate::{
    api_error::ApiError,
    argon::ArgonHash,
    database::{
        device::ModelDevice,
        download_data::ModelDownloadData,
        ip_user_agent::ModelUserAgentIp,
        rate_limit::RateLimit,
        session::RedisSession,
        two_fa_backup::{ModelTwoFA, ModelTwoFABackup},
        two_fa_setup::RedisTwoFASetup,
        user::ModelUser,
        user_level::UserLevel,
    },
    define_routes,
    emailer::{EmailTemplate, Emailer},
    helpers::{self, gen_random_hex},
    servers::{api::authentication, ApiRouter, ApplicationState, StatusOJ},
    user_io::{incoming_json::ij, outgoing_json::oj},
};

define_routes! {
    UserRoutes,
    "/user",
    Base => "",
    Data => "/data",
    Name => "/name",
    Password => "/password",
    SetupTwoFA => "/setup/twofa",
    Signout => "/signout",
    TwoFA => "/twofa",
    TwoFABackup => "/twofa/backup"
}
// This is shared, should put elsewhere
enum UserResponse {
    UnsafePassword,
    SetupTwoFA,
    TwoFANotEnabled,
    TwoFABackupInPlace,
}

impl fmt::Display for UserResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let disp = match self {
            Self::UnsafePassword => "unsafe password".to_owned(),
            Self::SetupTwoFA => "Two FA setup already started or enabled".to_owned(),
            Self::TwoFANotEnabled => "Two FA not enabled".to_owned(),
            Self::TwoFABackupInPlace => "Two FA backups already in place".to_owned(),
        };
        write!(f, "{disp}")
    }
}

pub struct UserRouter;

impl ApiRouter for UserRouter {
    fn create_router(_state: &ApplicationState) -> Router<ApplicationState> {
        Router::new()
            .route(
                &UserRoutes::Base.addr(),
                get(Self::user_get).delete(Self::user_delete),
            )
            .route(&UserRoutes::Signout.addr(), post(Self::signout_post))
            .route(&UserRoutes::Name.addr(), patch(Self::name_patch))
            .route(&UserRoutes::Data.addr(), post(Self::data_post))
            .route(&UserRoutes::Password.addr(), patch(Self::password_patch))
            .route(
                &UserRoutes::SetupTwoFA.addr(),
                delete(Self::setup_two_fa_delete)
                    .get(Self::setup_two_fa_get)
                    .post(Self::setup_two_fa_post),
            )
            .route(
                &UserRoutes::TwoFA.addr(),
                delete(Self::two_fa_delete).patch(Self::two_fa_patch),
            )
            .route(
                &UserRoutes::TwoFABackup.addr(),
                delete(Self::two_fa_backup_delete)
                    .post(Self::two_fa_backup_post)
                    .patch(Self::two_fa_backup_patch),
            )
    }
}

/// Create backup codes, and matching argon hashes
async fn gen_backup_codes() -> Result<(Vec<String>, Vec<ArgonHash>), ApiError> {
    let backup_count = 10;
    let mut backup_codes = Vec::with_capacity(backup_count);
    let mut vec_futures = FuturesUnordered::new();
    let mut backup_hashes = vec![];

    for _ in 0..backup_count {
        backup_codes.push(gen_random_hex(16));
    }

    for fut in &backup_codes {
        vec_futures.push(ArgonHash::new(fut.clone()));
    }

    while let Some(result) = vec_futures.next().await {
        backup_hashes.push(result?);
    }
    Ok((backup_codes, backup_hashes))
}

impl UserRouter {
    /// Return a user object
    #[expect(clippy::unused_async)]
    async fn user_get(user: ModelUser) -> StatusOJ<oj::AuthenticatedUser> {
        (
            StatusCode::OK,
            oj::OutgoingJson::new(oj::AuthenticatedUser::from(user)),
        )
    }

    /// Remove user account & remove all associated data
    /// Admin user unable to use this route to delete their account
    async fn user_delete(
        State(state): State<ApplicationState>,
        user: ModelUser,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusCode, ApiError> {
        if user.user_level == UserLevel::Admin {
            return Err(ApiError::InvalidValue(
                "Admin users can't delete their own accounts".to_owned(),
            ));
        }

        if !authentication::check_password_token(&user, &body.password, body.token, &state.postgres)
            .await?
        {
            return Err(ApiError::Authorization);
        }
        ModelDevice::delete_all_device_cache_connections(
            &state.postgres,
            &state.redis,
            &state.connections,
            &user,
        )
        .await?;
        user.delete(&state.postgres, &state.redis).await?;
        RedisSession::delete_all(&state.redis, user.registered_user_id).await?;

        Ok(StatusCode::OK)
    }

    /// Sign out user, by removing session from redis
    /// Doesn't matter if not signed in
    async fn signout_post(
        State(state): State<ApplicationState>,
        jar: PrivateCookieJar,
    ) -> Result<impl IntoResponse, ApiError> {
        if let Some(cookie) = jar.get(&state.cookie_name) {
            if let Ok(ulid) = Ulid::from_string(cookie.value()) {
                RedisSession::delete(&state.redis, &ulid).await?;
            }

            Ok((
                StatusCode::OK,
                jar.remove(Cookie::from(cookie.name().to_owned())),
            ))
        } else {
            Ok((StatusCode::OK, jar))
        }
    }

    /// Update user password
    async fn name_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        ij::IncomingJson(body): ij::IncomingJson<ij::PatchName>,
    ) -> Result<StatusCode, ApiError> {
        ModelUser::update_name(&state.postgres, user.registered_user_id, body.full_name).await?;
        Ok(StatusCode::OK)
    }

    /// Download user data
    async fn data_post(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusOJ<String>, ApiError> {
        if !authentication::check_password_op_token(
            &user,
            &body.password,
            body.token,
            &state.postgres,
        )
        .await?
        {
            return Err(ApiError::Authorization);
        }

        if RateLimit::DownloadData(user.registered_user_id)
            .check(&state.redis)
            .await
            .is_err()
        {
            return Err(ApiError::InvalidValue(
                "Limited to one download per 24-hours".to_owned(),
            ));
        };

        // Email user download sent
        Emailer::new(
            &user.full_name,
            &user.email,
            EmailTemplate::DownloadData,
            &state.email_env,
        )
        .send(&state.postgres, &useragent_ip)
        .await?;

        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(ModelDownloadData::get(&state.postgres, &user).await?),
        ))
    }

    /// Update user password
    async fn password_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::PatchPassword>,
    ) -> Result<StatusCode, ApiError> {
        if !authentication::check_password_op_token(
            &user,
            &body.current_password,
            body.token,
            &state.postgres,
        )
        .await?
        {
            return Err(ApiError::Authorization);
        }

        // Check if password is exposed in HIBP, that new password doesn't contain user email address, that new password doesn't contain old password and also that new password != old_password
        if body.new_password.contains(&body.current_password)
            || body
                .new_password
                .to_lowercase()
                .contains(&user.email.to_lowercase())
            || helpers::pwned_password(&body.new_password).await?
        {
            return Err(ApiError::InvalidValue(
                UserResponse::UnsafePassword.to_string(),
            ));
        }

        let new_password_hash = ArgonHash::new(body.new_password.clone()).await?;
        ModelUser::update_password(&state.postgres, user.registered_user_id, new_password_hash)
            .await?;

        Emailer::new(
            &user.full_name,
            &user.email,
            EmailTemplate::PasswordChanged,
            &state.email_env,
        )
        .send(&state.postgres, &useragent_ip)
        .await?;

        Ok(StatusCode::OK)
    }

    /// remove token from redis - used in 2fa setup process,
    async fn setup_two_fa_delete(
        State(state): State<ApplicationState>,
        user: ModelUser,
    ) -> Result<StatusCode, ApiError> {
        RedisTwoFASetup::delete(&state.redis, &user).await?;
        Ok(StatusCode::OK)
    }

    /// Get a new secret, store in redis until user returns valid token response
    async fn setup_two_fa_get(
        State(state): State<ApplicationState>,
        user: ModelUser,
    ) -> Result<StatusOJ<oj::TwoFASetup>, ApiError> {
        // If setup process has already started, or user has two_fa already enabled, return conflict error
        if RedisTwoFASetup::exists(&state.redis, &user).await? || user.two_fa_secret.is_some() {
            return Err(ApiError::Conflict(UserResponse::SetupTwoFA.to_string()));
        }
        let secret = gen_random_hex(32);
        let totp = authentication::totp_from_secret(&secret)?;
        RedisTwoFASetup::new(&secret)
            .insert(&state.redis, &user)
            .await?;
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(oj::TwoFASetup {
                // Convert to base32, to generate a QR code on the front end that will work with Google Authenticator etc
                secret: totp.get_secret_base32(),
            }),
        ))
    }

    /// Check that incoming token is valid to the redis key, and insert into postgres
    async fn setup_two_fa_post(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::TwoFA>,
    ) -> Result<StatusCode, ApiError> {
        let err = || Err(ApiError::InvalidValue("invalid token".to_owned()));
        if let Some(two_fa_setup) = RedisTwoFASetup::get(&state.redis, &user).await? {
            match body.token {
                ij::Token::Totp(token) => {
                    let known_totp = authentication::totp_from_secret(two_fa_setup.value())?;

                    if let Ok(valid_token) = known_totp.check_current(&token) {
                        if valid_token {
                            RedisTwoFASetup::delete(&state.redis, &user).await?;
                            ModelTwoFA::insert(&state.postgres, two_fa_setup, &useragent_ip, &user)
                                .await?;

                            Emailer::new(
                                &user.full_name,
                                &user.email,
                                EmailTemplate::TwoFAEnabled,
                                &state.email_env,
                            )
                            .send(&state.postgres, &useragent_ip)
                            .await?;
                            return Ok(StatusCode::OK);
                        }
                    }
                }
                ij::Token::Backup(_) => return err(),
            };
        }
        err()
    }

    /// Enable, or disable, `two_fa_always_required`
    async fn two_fa_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        ij::IncomingJson(body): ij::IncomingJson<ij::TwoFAAlwaysRequired>,
    ) -> Result<StatusCode, ApiError> {
        if user.two_fa_secret.is_none() {
            return Err(ApiError::Conflict(
                UserResponse::TwoFANotEnabled.to_string(),
            ));
        }

        if body.always_required {
            if user.two_fa_always_required {
                return Err(ApiError::Conflict(
                    UserResponse::TwoFANotEnabled.to_string(),
                ));
            }
            ModelTwoFA::update_always_required(&state.postgres, body.always_required, &user)
                .await?;
        } else {
            if !user.two_fa_always_required {
                return Err(ApiError::Conflict(
                    UserResponse::TwoFANotEnabled.to_string(),
                ));
            }
            if body.password.is_none() || body.token.is_none() {
                return Err(ApiError::InvalidValue("password or token".to_owned()));
            }
            if !authentication::check_password_op_token(
                &user,
                &body.password.unwrap_or_default(),
                body.token,
                &state.postgres,
            )
            .await?
            {
                return Err(ApiError::Authorization);
            }
            ModelTwoFA::update_always_required(&state.postgres, body.always_required, &user)
                .await?;
        }
        Ok(StatusCode::OK)
    }

    /// Remove `two_fa` from user, including any, and all all, backups
    /// remove all backups, then secret
    async fn two_fa_delete(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusCode, ApiError> {
        if user.two_fa_secret.is_none() {
            return Err(ApiError::Conflict(
                UserResponse::TwoFANotEnabled.to_string(),
            ));
        }

        if !authentication::check_password_op_token(
            &user,
            &body.password,
            body.token,
            &state.postgres,
        )
        .await?
        {
            return Err(ApiError::Authorization);
        }
        tokio::try_join!(
            ModelTwoFABackup::delete_all(&state.postgres, &user),
            ModelTwoFA::delete(&state.postgres, &user)
        )?;

        Emailer::new(
            &user.full_name,
            &user.email,
            EmailTemplate::TwoFADisabled,
            &state.email_env,
        )
        .send(&state.postgres, &useragent_ip)
        .await?;

        Ok(StatusCode::OK)
    }

    /// insert `two_fa_backup_code`
    async fn two_fa_backup_post(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
    ) -> Result<StatusOJ<oj::TwoFaBackup>, ApiError> {
        if user.two_fa_secret.is_none() || user.two_fa_backup_count != 0 {
            return Err(ApiError::Conflict(
                UserResponse::TwoFANotEnabled.to_string(),
            ));
        }

        if user.two_fa_backup_count > 0 {
            return Err(ApiError::Conflict(
                UserResponse::TwoFABackupInPlace.to_string(),
            ));
        }

        let (backup, hashes) = gen_backup_codes().await?;
        ModelTwoFABackup::insert(&state.postgres, &user, &useragent_ip, hashes).await?;
        Emailer::new(
            &user.full_name,
            &user.email,
            EmailTemplate::TwoFABackupEnabled,
            &state.email_env,
        )
        .send(&state.postgres, &useragent_ip)
        .await?;

        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(oj::TwoFaBackup { backups: backup }),
        ))
    }

    /// Delete any current backup codes, and regenerate, and insert, 10 new ones, required authentication password + token
    async fn two_fa_backup_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusOJ<oj::TwoFaBackup>, ApiError> {
        if user.two_fa_secret.is_none() {
            return Err(ApiError::Conflict(
                UserResponse::TwoFANotEnabled.to_string(),
            ));
        }
        if !authentication::check_password_op_token(
            &user,
            &body.password,
            body.token,
            &state.postgres,
        )
        .await?
        {
            return Err(ApiError::Authorization);
        }

        // if has backup tokens, then check password token
        // if exists email regegnerate
        ModelTwoFABackup::delete_all(&state.postgres, &user).await?;

        let (backups, hashes) = gen_backup_codes().await?;
        ModelTwoFABackup::insert(&state.postgres, &user, &useragent_ip, hashes).await?;

        Emailer::new(
            &user.full_name,
            &user.email,
            EmailTemplate::TwoFABackupReGenerated,
            &state.email_env,
        )
        .send(&state.postgres, &useragent_ip)
        .await?;

        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(oj::TwoFaBackup { backups }),
        ))
    }

    /// Delete all backup codes
    async fn two_fa_backup_delete(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusCode, ApiError> {
        if !authentication::check_password_op_token(
            &user,
            &body.password,
            body.token,
            &state.postgres,
        )
        .await?
        {
            return Err(ApiError::Authorization);
        }
        ModelTwoFABackup::delete_all(&state.postgres, &user).await?;

        Emailer::new(
            &user.full_name,
            &user.email,
            EmailTemplate::TwoFABackupDisabled,
            &state.email_env,
        )
        .send(&state.postgres, &useragent_ip)
        .await?;

        Ok(StatusCode::OK)
    }
}

/// Use reqwest to test against real server
// cargo watch -q -c -w src/ -x 'test api_router_user -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::pedantic)]
mod tests {

    use super::UserRoutes;
    use crate::connections::ConnectionType;
    use crate::database::email_address::ModelEmailAddress;
    use crate::database::email_log::ModelEmailLog;
    use crate::database::two_fa_backup::ModelTwoFA;
    use crate::database::two_fa_setup::RedisTwoFASetup;
    use crate::database::user::ModelUser;
    use crate::database::user_level::UserLevel;
    use crate::helpers::gen_random_hex;
    use crate::servers::api::api_tests::{EMAIL_BODY_LOCATION, EMAIL_HEADERS_LOCATION};
    use crate::servers::api::authentication::totp_from_secret;
    use crate::servers::test_setup::{
        api_base_url, get_keys, start_servers, Response, TestSetup, ANON_EMAIL, ANON_FULL_NAME,
        ANON_PASSWORD, TEST_EMAIL, TEST_FULL_NAME, TEST_PASSWORD, UNSAFE_PASSWORD,
    };
    use crate::sleep;
    use crate::user_io::incoming_json::ij::DevicePost;

    use fred::interfaces::{HashesInterface, KeysInterface, SetsInterface};
    use futures::{SinkExt, StreamExt};
    use reqwest::StatusCode;
    use serde::Serialize;
    use serde_json::Value;
    use std::collections::HashMap;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    //*********************
    // * User Base Route  *
    // ********************

    #[tokio::test]
    /// Unauthenticated user unable to [ DELETE, GET ] /user route
    async fn api_router_user_get_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );

        let client = TestSetup::get_client();

        let resp = client
            .delete(&url)
            .json(&HashMap::from([("password", TEST_PASSWORD)]))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Authenticated FREE user gets correct user object
    async fn api_router_user_get_free_user_authenticated() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let client = TestSetup::get_client();

        let authed_cookie = test_setup.authed_user_cookie().await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;

        assert_eq!(result["email"], TEST_EMAIL);
        assert_eq!(result["max_bandwidth"], 5_000_000);
        assert_eq!(result["max_clients"], 1);
        assert_eq!(result["max_devices"], 1);
        assert_eq!(result["max_message_size"], 10000);
        assert_eq!(result["user_level"], "free");
        assert_eq!(result["two_fa_active"], false);
        assert_eq!(result["two_fa_always_required"], false);
        assert_eq!(result["two_fa_count"], 0);
        assert!(result["timestamp"].is_string());
    }

    #[tokio::test]
    // Authenticated, with 2fa enabled, FREE user gets correct user object
    async fn api_router_user_get_free_user_authenticated_with_two_fa() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let client = TestSetup::get_client();

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;

        assert_eq!(result["email"], TEST_EMAIL);
        assert_eq!(result["max_bandwidth"], 5_000_000);
        assert_eq!(result["max_clients"], 1);
        assert_eq!(result["max_devices"], 1);
        assert_eq!(result["max_message_size"], 10000);
        assert_eq!(result["user_level"], "free");
        assert_eq!(result["two_fa_active"], true);
        assert_eq!(result["two_fa_always_required"], false);
        assert_eq!(result["two_fa_count"], 0);
        assert!(result["timestamp"].is_string());
    }

    #[tokio::test]
    // Authenticated PRO user gets correct user object
    async fn api_router_user_get_pro_user_authenticated() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;

        assert_eq!(result["email"], TEST_EMAIL);
        assert_eq!(result["max_bandwidth"], 10_000_000_000i64);
        assert_eq!(result["max_clients"], 100);
        assert_eq!(result["max_devices"], 20);
        assert_eq!(result["max_message_size"], 5_000_000);
        assert_eq!(result["user_level"], "pro");
        assert_eq!(result["two_fa_active"], false);
        assert_eq!(result["two_fa_always_required"], false);
        assert_eq!(result["two_fa_count"], 0);
        assert!(result["timestamp"].is_string());
    }

    #[tokio::test]
    // Authenticated, with 2fa enabled, PRO user gets correct user object
    async fn api_router_user_get_pro_user_authenticated_with_two_fa() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let client = TestSetup::get_client();

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_two_fa().await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;

        assert_eq!(result["email"], TEST_EMAIL);
        assert_eq!(result["max_bandwidth"], 10_000_000_000i64);
        assert_eq!(result["max_clients"], 100);
        assert_eq!(result["max_devices"], 20);
        assert_eq!(result["max_message_size"], 5_000_000);
        assert_eq!(result["user_level"], "pro");
        assert_eq!(result["two_fa_active"], true);
        assert_eq!(result["two_fa_always_required"], false);
        assert_eq!(result["two_fa_count"], 0);
        assert!(result["timestamp"].is_string());
    }

    #[tokio::test]
    // Authenticated Admin user gets correct user object
    async fn api_router_user_get_admin_user_authenticated() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;

        assert_eq!(result["email"], TEST_EMAIL);
        assert_eq!(result["max_bandwidth"], 100_000_000_000i64);
        assert_eq!(result["max_clients"], 100);
        assert_eq!(result["max_devices"], 20);
        assert_eq!(result["max_message_size"], 10_000_000);
        assert_eq!(result["user_level"], "admin");
        assert_eq!(result["two_fa_active"], false);
        assert_eq!(result["two_fa_always_required"], false);
        assert_eq!(result["two_fa_count"], 0);
        assert!(result["timestamp"].is_string());
    }

    #[tokio::test]
    // Authenticated, with 2fa enabled, Admin user gets correct user object
    async fn api_router_user_get_admin_user_authenticated_with_two_fa() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        test_setup.insert_two_fa().await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;

        assert_eq!(result["email"], TEST_EMAIL);
        assert_eq!(result["max_bandwidth"], 100_000_000_000i64);
        assert_eq!(result["max_clients"], 100);
        assert_eq!(result["max_devices"], 20);
        assert_eq!(result["max_message_size"], 10_000_000);
        assert_eq!(result["user_level"], "admin");
        assert_eq!(result["two_fa_active"], true);
        assert_eq!(result["two_fa_always_required"], false);
        assert_eq!(result["two_fa_count"], 0);
        assert!(result["timestamp"].is_string());
    }

    #[tokio::test]
    /// Admin user unable to delete account
    async fn api_router_user_delete_admin_err() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let result = client
            .delete(&url)
            .json(&HashMap::from([("password", TEST_PASSWORD)]))
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Admin users can't delete their own accounts");
        assert!(test_setup.get_model_user().await.is_some());
    }

    #[tokio::test]
    /// No body, account NOT deleted
    async fn api_router_user_delete_no_body_err() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let authed_cookie = test_setup.authed_user_cookie().await;

        let result = client
            .delete(&url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "\"application/json\" header");
        assert!(test_setup.get_model_user().await.is_some());
    }

    #[tokio::test]
    /// Invalid password, account NOT deleted
    async fn api_router_user_delete_password_err() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let authed_cookie = test_setup.authed_user_cookie().await;

        let result = client
            .delete(&url)
            .json(&HashMap::from([("password", ANON_PASSWORD)]))
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");
        assert!(test_setup.get_model_user().await.is_some());
    }

    #[tokio::test]
    /// Invalid token, account NOT deleted
    async fn api_router_user_delete_token_err() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let invalid_token = test_setup.get_invalid_token();

        // no token
        let result = client
            .delete(&url)
            .json(&HashMap::from([("password", TEST_PASSWORD)]))
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");
        assert!(test_setup.get_model_user().await.is_some());

        // invalid token
        let result = client
            .delete(&url)
            .json(&HashMap::from([
                ("password", TEST_PASSWORD),
                ("token", &invalid_token),
            ]))
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");
        assert!(test_setup.get_model_user().await.is_some());
    }

    #[tokio::test]
    /// User delete with anon user which shares ip, useragent, and device name, shared data is left in db
    async fn api_router_user_with_anon_delete_ok() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        test_setup.insert_anon_user().await;
        let anon_cookie = test_setup.anon_user_cookie().await.unwrap();
        let device_name = test_setup.insert_device(&anon_cookie, None).await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 1,
                    client_password: None,
                    device_password: None,
                    structured_data: false,
                    name: Some(device_name.clone()),
                }),
            )
            .await;

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let result = client
            .delete(&url)
            .json(&HashMap::from([("password", TEST_PASSWORD)]))
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // Email address removed
        assert!(ModelEmailAddress::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .is_none());

        // connections cut
        assert!(ws_client
            .unwrap()
            .0
            .next()
            .await
            .unwrap()
            .unwrap()
            .is_close());
        assert!(ws_pi.unwrap().0.next().await.unwrap().unwrap().is_close());

        // device name not deleted!
        assert!(!sqlx::query("SELECT * FROM device_name")
            .bind(test_setup.get_user_id().get())
            .fetch_all(&test_setup.postgres)
            .await
            .unwrap()
            .is_empty());

        // Devices removed
        assert!(
            sqlx::query("SELECT * FROM device WHERE registered_user_id = $1")
                .bind(test_setup.get_user_id().get())
                .fetch_optional(&test_setup.postgres)
                .await
                .unwrap()
                .is_none()
        );

        // User removed
        assert!(test_setup.get_model_user().await.is_none());

        // ip address & user_agent string NOT removed
        let req = TestSetup::gen_req();
        assert!(sqlx::query("SELECT * FROM ip_address WHERE ip = $1")
            .bind(req.ip)
            .fetch_optional(&test_setup.postgres)
            .await
            .unwrap()
            .is_some());
        assert!(
            sqlx::query("SELECT * FROM user_agent WHERE user_agent_string = $1")
                .bind(req.user_agent)
                .fetch_optional(&test_setup.postgres)
                .await
                .unwrap()
                .is_some()
        );

        // user removed!
        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// User data & account deleted
    async fn api_router_user_delete_ok() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_device(&authed_cookie, None).await;

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let result = client
            .delete(&url)
            .json(&HashMap::from([("password", TEST_PASSWORD)]))
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // Email address removed
        assert!(ModelEmailAddress::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .is_none());

        // connections cut
        assert!(ws_client
            .unwrap()
            .0
            .next()
            .await
            .unwrap()
            .unwrap()
            .is_close());
        assert!(ws_pi.unwrap().0.next().await.unwrap().unwrap().is_close());

        // device names removed
        assert!(sqlx::query("SELECT * FROM device_name")
            .bind(test_setup.get_user_id().get())
            .fetch_all(&test_setup.postgres)
            .await
            .unwrap()
            .is_empty());

        // Devices removed
        assert!(
            sqlx::query("SELECT * FROM device WHERE registered_user_id = $1")
                .bind(test_setup.get_user_id().get())
                .fetch_optional(&test_setup.postgres)
                .await
                .unwrap()
                .is_none()
        );

        // User removed
        assert!(test_setup.get_model_user().await.is_none());

        // ip address & user_agent string removed
        let req = TestSetup::gen_req();
        assert!(sqlx::query("SELECT * FROM ip_address WHERE ip = $1")
            .bind(req.ip)
            .fetch_optional(&test_setup.postgres)
            .await
            .unwrap()
            .is_none());
        assert!(
            sqlx::query("SELECT * FROM user_agent WHERE user_agent_string = $1")
                .bind(req.user_agent)
                .fetch_optional(&test_setup.postgres)
                .await
                .unwrap()
                .is_none()
        );

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// User data & account deleted, checks that anon data still valid, i.e. ip and user agent & device names aren't removed
    async fn api_router_user_get_delete_anon_user_ok() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_anon_user().await;
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        let anon_cookie = test_setup.anon_user_cookie().await.unwrap();
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let device = DevicePost {
            max_clients: 1,
            client_password: None,
            device_password: None,
            structured_data: false,
            name: Some(device_name.clone()),
        };
        test_setup.insert_device(&anon_cookie, Some(device)).await;

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let result = client
            .delete(&url)
            .json(&HashMap::from([("password", TEST_PASSWORD)]))
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // Email address removed
        assert!(ModelEmailAddress::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .is_none());

        // connections cut
        assert!(ws_client
            .unwrap()
            .0
            .next()
            .await
            .unwrap()
            .unwrap()
            .is_close());
        assert!(ws_pi.unwrap().0.next().await.unwrap().unwrap().is_close());

        // Devices removed
        assert!(
            sqlx::query("SELECT * FROM device WHERE registered_user_id = $1")
                .bind(test_setup.get_user_id().get())
                .fetch_optional(&test_setup.postgres)
                .await
                .unwrap()
                .is_none()
        );

        // device names NOT removed
        assert!(!sqlx::query("SELECT * FROM device_name")
            .bind(test_setup.get_user_id().get())
            .fetch_all(&test_setup.postgres)
            .await
            .unwrap()
            .is_empty());

        // User removed
        assert!(test_setup.get_model_user().await.is_none());

        // ip address & user_agent string NOT removed
        let req = TestSetup::gen_req();
        assert!(sqlx::query("SELECT * FROM ip_address WHERE ip = $1")
            .bind(req.ip)
            .fetch_optional(&test_setup.postgres)
            .await
            .unwrap()
            .is_some());
        assert!(
            sqlx::query("SELECT * FROM user_agent WHERE user_agent_string = $1")
                .bind(req.user_agent)
                .fetch_optional(&test_setup.postgres)
                .await
                .unwrap()
                .is_some()
        );

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client
            .get(&url)
            .header("cookie", &anon_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
    }

    // *****************
    // * Signout Route *
    // *****************

    #[tokio::test]
    // Unuthenticated user signout just returns 200
    async fn api_router_user_get_signout_unauthenticated() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Signout.addr()
        );

        let result = client.post(&url).send().await.unwrap();

        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    // Authenticated user signout removes session, next request invalid
    async fn api_router_user_get_signout_authenticated() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Signout.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        // assert redis has zero session keys in it
        let session_vec = get_keys(&test_setup.redis, "session::*").await;
        assert_eq!(session_vec.len(), 0);

        let key = format!(
            "session_set::user::{}",
            test_setup.model_user.unwrap().registered_user_id.get()
        );
        let redis_set: Vec<String> = test_setup.redis.smembers(key).await.unwrap();
        assert!(redis_set.is_empty());

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Base.addr()
        );
        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    // ******************
    // * Patch Name *
    // ******************

    #[tokio::test]
    /// Unauthed user unable to [PATCH] name route
    async fn api_router_user_name_patch_unauthenticated() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Name.addr()
        );
        let body: HashMap<String, String> = HashMap::new();

        let result = client.patch(&url).json(&body).send().await.unwrap();

        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Invalid request when body incorrect
    async fn api_router_user_name_patch_invalid_body() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;

        let client = TestSetup::get_client();

        // No body
        let body: HashMap<&str, &str> = HashMap::new();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Name.addr()
        );

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "missing full_name");

        // No name
        let body = HashMap::from([("full_name", "")]);
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Name.addr()
        );

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "name");

        // name just spaces
        let body = HashMap::from([("full_name", "   ")]);
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Name.addr()
        );

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "name");

        // name has symbols
        let body = HashMap::from([("full_name", "&*^")]);
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Name.addr()
        );

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "name");

        // name has number
        let body = HashMap::from([("full_name", "21235")]);
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Name.addr()
        );

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "name");
    }

    #[tokio::test]
    /// name change valid
    async fn api_router_user_name_patch_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let client = TestSetup::get_client();

        let body = HashMap::from([("full_name", format!(" {ANON_FULL_NAME} "))]);
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Name.addr()
        );
        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            test_setup.get_model_user().await.unwrap().full_name,
            ANON_FULL_NAME
        );
    }

    // ******************
    // * Patch Password *
    // ******************

    #[tokio::test]
    /// Unauthed user unable to access password route
    async fn api_router_user_password_patch_unauthenticated() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Password.addr()
        );
        let body: HashMap<String, String> = HashMap::new();

        let result = client.patch(&url).json(&body).send().await.unwrap();

        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    // Could refactor these with a closure?
    #[tokio::test]
    async fn api_router_user_password_patch_authenticated_short_password() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Password.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        let new_password = gen_random_hex(11);

        let body = HashMap::from([
            ("current_password", TEST_PASSWORD),
            ("new_password", new_password.as_str()),
        ]);

        let result = client
            .patch(url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "password");

        let post_user = ModelUser::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            test_setup.model_user.unwrap().get_password_hash().0,
            post_user.get_password_hash().0
        );
    }

    #[tokio::test]
    /// Unable to change password to an unsafe password, either HIBP listed, matches current, or contains self email address
    async fn api_router_user_password_patch_authenticated_unsafe_password() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Password.addr()
        );
        let authed_cookie = test_setup.authed_user_cookie().await;

        // Invalid passwords to test
        for password in [
            format!("new_password{}", TEST_EMAIL.to_uppercase()),
            TEST_PASSWORD.to_owned(),
            UNSAFE_PASSWORD.to_owned(),
        ] {
            let body = HashMap::from([
                ("current_password", TEST_PASSWORD),
                ("new_password", &password),
            ]);

            let result = client
                .patch(&url)
                .header("cookie", &authed_cookie)
                .json(&body)
                .send()
                .await
                .unwrap();

            assert_eq!(result.status(), StatusCode::BAD_REQUEST);

            let result = result.json::<Response>().await.unwrap().response;
            assert_eq!(result, "unsafe password");
            let post_user = ModelUser::get(&test_setup.postgres, TEST_EMAIL)
                .await
                .unwrap()
                .unwrap();

            assert_eq!(
                test_setup
                    .model_user
                    .as_ref()
                    .unwrap()
                    .get_password_hash()
                    .0,
                post_user.get_password_hash().0
            );
        }
    }

    #[tokio::test]
    /// user's password is unchanged if current password supplied isn't correct
    async fn api_router_user_password_patch_authenticated_invalid_current_password() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Password.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        let current_password = gen_random_hex(64);
        let new_password = gen_random_hex(64);

        let body = HashMap::from([
            ("current_password", &current_password),
            ("new_password", &new_password),
        ]);

        let result = client
            .patch(url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);

        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        let post_user = ModelUser::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            test_setup
                .model_user
                .as_ref()
                .unwrap()
                .get_password_hash()
                .0,
            post_user.get_password_hash().0
        );
    }

    #[tokio::test]
    /// user's password is unchanged if two-fa token supplied isn't correct
    async fn api_router_user_password_patch_authenticated_invalid_token() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Password.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let invalid_token = test_setup.get_invalid_token();
        test_setup.two_fa_always_required(true).await;

        let new_password = gen_random_hex(64);

        let body = HashMap::from([
            ("current_password", TEST_PASSWORD),
            ("new_password", &new_password),
            ("token", &invalid_token),
        ]);
        let result = client
            .patch(url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);

        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        let post_user = ModelUser::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            test_setup
                .model_user
                .as_ref()
                .unwrap()
                .get_password_hash()
                .0,
            post_user.get_password_hash().0
        );
    }

    #[tokio::test]
    /// Password correctly changed, and email sent to user
    /// Able to signin with new password
    async fn api_router_user_password_patch_authenticated_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Password.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        let new_password = gen_random_hex(64);
        let body = HashMap::from([
            ("current_password", TEST_PASSWORD),
            ("new_password", new_password.as_str()),
        ]);

        let result = client
            .patch(url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let post_user = ModelUser::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .unwrap();

        // check that pre_user.password_hash != post_user.password_hash
        assert_ne!(
            test_setup
                .model_user
                .as_ref()
                .unwrap()
                .get_password_hash()
                .0,
            post_user.get_password_hash().0
        );

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );

        // email sent - written to disk when testing & inserted into db
        assert!(std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
            .unwrap()
            .contains("The password for your staticPi account has been changed"));

        assert!(std::fs::read_to_string(EMAIL_HEADERS_LOCATION)
            .unwrap()
            .contains("Password Changed"));

        let signin_url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let old_password_body = TestSetup::gen_signin_body(None, None, None, None);

        let result = client
            .post(&signin_url)
            .json(&old_password_body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );

        let new_password_body = TestSetup::gen_signin_body(None, Some(new_password), None, None);
        let result = client
            .post(&signin_url)
            .json(&new_password_body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    /// Password correctly changed when TwoFA is active, and email sent to user
    async fn api_router_user_password_patch_authenticated_valid_with_two_fa() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Password.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_two_fa().await;
        let valid_token = test_setup.get_valid_token();

        let new_password = gen_random_hex(64);
        let body = HashMap::from([
            ("current_password", TEST_PASSWORD),
            ("new_password", new_password.as_str()),
            ("token", &valid_token),
        ]);

        let result = client
            .patch(url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let post_user = ModelUser::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .unwrap();

        // check that pre_user.password_hash != post_user.password_hash
        assert_ne!(
            test_setup
                .model_user
                .as_ref()
                .unwrap()
                .get_password_hash()
                .0,
            post_user.get_password_hash().0
        );

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        // email sent - written to disk when testing & inserted into db
        assert!(std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
            .unwrap()
            .contains("The password for your staticPi account has been changed"));

        assert!(std::fs::read_to_string(EMAIL_HEADERS_LOCATION)
            .unwrap()
            .contains("Password Changed"));
    }

    // ** *************
    // * Setup Two FA *
    // ****************

    #[tokio::test]
    // TwoFaSetup [DELETE, GET, POST] route for authed users only
    async fn api_router_user_setup_two_fa_unauthenticated() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::SetupTwoFA.addr()
        );

        let result = client.delete(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client.get(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client.post(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Insert secret into redis - with correct ttl, return secret to user
    async fn api_router_user_setup_two_fa_get_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::SetupTwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let response = result.json::<Response>().await.unwrap().response;

        let key = format!("two_fa_setup::{}", test_setup.get_user_id().get());

        let redis_secret: Option<RedisTwoFASetup> =
            test_setup.redis.hget(&key, "data").await.unwrap();

        assert!(redis_secret.is_some());

        let totp = totp_from_secret(redis_secret.unwrap().value());
        assert!(totp.is_ok());
        let redis_totp = totp.unwrap().get_secret_base32();

        assert_eq!(redis_totp, response["secret"]);

        let secret_ttl: usize = test_setup.redis.ttl(&key).await.unwrap();

        assert_eq!(secret_ttl, 120);
    }

    #[tokio::test]
    /// If TwoFA already enabled, return 409 response
    async fn api_router_user_get_two_fa_already_setup() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::SetupTwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_two_fa().await;

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        assert_eq!(
            "Two FA setup already started or enabled",
            result.json::<Response>().await.unwrap().response
        );
    }

    #[tokio::test]
    /// If TwoFA setup already in progress, return a 409 conflict
    async fn api_router_user_setup_two_fa_get_already_in_progress() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::SetupTwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        let result = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        assert_eq!(
            "Two FA setup already started or enabled",
            result.json::<Response>().await.unwrap().response
        );
    }

    #[tokio::test]
    /// remove a TwoFA secret from redis - cancel TwoFa setup etc
    async fn api_router_user_delete_setup_two_fa_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::SetupTwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        let result = client
            .delete(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        // Check key has been removed from redis
        let key = format!("two_fa_setup::{}", test_setup.get_user_id().get());

        let redis_secret: Option<String> = test_setup.redis.get(&key).await.unwrap();

        assert!(redis_secret.is_none());
    }

    #[tokio::test]
    /// Setup fails if provide invalid token
    async fn api_router_user_post_setup_two_fa_invalid_token() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::SetupTwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        let key = format!("two_fa_setup::{}", test_setup.get_user_id().get());
        let twofa_setup: RedisTwoFASetup = test_setup.redis.hget(key, "data").await.unwrap();

        let invalid_token = totp_from_secret(twofa_setup.value())
            .unwrap()
            .generate(123_456_789);

        let body = HashMap::from([("token", &invalid_token)]);

        let result = client
            .post(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            "invalid token",
            result.json::<Response>().await.unwrap().response
        );
    }

    #[tokio::test]
    /// Full TwoFA setup flow
    async fn api_router_user_post_setup_two_fa_valid_token() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::SetupTwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;

        client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        let key = format!("two_fa_setup::{}", test_setup.get_user_id().get());
        let twofa_setup: RedisTwoFASetup = test_setup.redis.hget(key, "data").await.unwrap();
        let valid_token = totp_from_secret(twofa_setup.value())
            .unwrap()
            .generate_current()
            .unwrap();

        let body = HashMap::from([("token", &valid_token)]);

        let result = client
            .post(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let user = test_setup.get_model_user().await.unwrap();

        assert_eq!(user.two_fa_secret, Some(twofa_setup.value().to_owned()));

        // check email sent - well written to disk & inserted into db
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        assert!(std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
        let link = format!(
            "href=\"https://www.{}/user/settings/",
            test_setup.app_env.domain
        );
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
            .unwrap()
            .contains(&link));
    }

    // ** *******
    // * Two FA *
    // **********

    #[tokio::test]
    // TwoFA [DELETE, PATCH, POST, PUT] route for authed users only
    async fn api_router_user_two_fa_unauthenticated() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let result = client.delete(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client.patch(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Conflict response if two_fa not enabled
    async fn api_router_user_two_delete_two_fa_not_enabled() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", "012345")]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Two FA not enabled");
    }
    #[tokio::test]
    // Conflict response if two_fa not enabled, when trying to patch always_enabled
    async fn api_router_user_setup_two_fa_patch_two_fa_not_enabled() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let authed_cookie = test_setup.authed_user_cookie().await;
        let body = HashMap::from([("always_required", true)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Two FA not enabled");
    }

    #[tokio::test]
    // Valid patch, set always_required to true
    async fn api_router_user_two_fa_patch_enabled_valid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let body = HashMap::from([("always_required", true)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let user = test_setup.get_model_user().await.unwrap();
        assert!(user.two_fa_always_required);
    }

    #[tokio::test]
    // Conflict response if trying to enabling two_fa_always_required & it is already enabled
    async fn api_router_user_two_fa_patch_enabled_already_enabled() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let body = HashMap::from([("always_required", true)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
    }

    #[derive(Debug, Serialize)]
    struct TestAlwaysRequiredBody {
        always_required: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    }

    #[tokio::test]
    // When trying to disable and no password & token provided error response
    async fn api_router_user_two_patch_disabled_no_password_or_token() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );
        // Missing token
        let body = TestAlwaysRequiredBody {
            always_required: false,
            password: Some(TEST_PASSWORD.to_owned()),
            token: None,
        };

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "password or token");

        // Missing password
        let body = TestAlwaysRequiredBody {
            always_required: false,
            password: None,
            token: Some(test_setup.get_valid_token()),
        };

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "password or token");
    }

    #[tokio::test]
    /// Delete all twofa fails when password and/or token invalid
    async fn api_router_user_two_delete_invalid_password() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();

        let client = TestSetup::get_client();
        // insert backups
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let valid_token = test_setup.get_valid_token();
        let body = HashMap::from([("password", gen_random_hex(12)), ("token", valid_token)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);

        let user = test_setup.get_model_user().await.unwrap();

        assert!(user.two_fa_always_required);
        assert!(user.two_fa_secret.is_some());
        assert_eq!(user.two_fa_backup_count, 10);

        let invalid_token = test_setup.get_invalid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &invalid_token)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);

        let user = test_setup.get_model_user().await.unwrap();

        assert!(user.two_fa_always_required);
        assert!(user.two_fa_secret.is_some());
        assert_eq!(user.two_fa_backup_count, 10);
    }

    #[tokio::test]
    /// Delete two_fa_secret & all/any backups, also email user
    async fn api_router_user_two_delete_valid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();

        // insert backups
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        test_setup.delete_email_log().await;

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let valid_token = test_setup.get_valid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &valid_token)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let user = test_setup.get_model_user().await.unwrap();

        assert!(!user.two_fa_always_required);
        assert!(user.two_fa_secret.is_none());
        assert_eq!(user.two_fa_backup_count, 0);

        // email sent - written to disk when testing & inserted into db
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        assert!(std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
            .unwrap()
            .contains("You have disabled Two-Factor Authentication for your staticPi account"));

        assert!(std::fs::read_to_string(EMAIL_HEADERS_LOCATION)
            .unwrap()
            .contains("Two-Factor Disabled"));
    }

    #[tokio::test]
    // Remove two_fa_always required invalid when password & token invalid
    async fn api_router_user_two_patch_always_required_invalid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        // Invalid password
        let body = TestAlwaysRequiredBody {
            always_required: false,
            password: Some(gen_random_hex(12)),
            token: Some(test_setup.get_valid_token()),
        };

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);

        let user = test_setup.get_model_user().await.unwrap();
        assert!(user.two_fa_always_required);

        // Invalid token
        let body = TestAlwaysRequiredBody {
            always_required: false,
            password: Some(TEST_PASSWORD.to_owned()),
            token: Some(test_setup.get_invalid_token()),
        };

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);

        let user = test_setup.get_model_user().await.unwrap();
        assert!(user.two_fa_always_required);
    }

    #[tokio::test]
    // Remove two_fa_always required with a valid request which, includes password & token
    async fn api_router_user_two_patch_always_required_removed() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFA.addr()
        );

        let body = TestAlwaysRequiredBody {
            always_required: false,
            password: Some(TEST_PASSWORD.to_owned()),
            token: Some(test_setup.get_valid_token()),
        };

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let user = test_setup.get_model_user().await.unwrap();
        assert!(!user.two_fa_always_required);
    }

    // ** **************
    // * Two FA BACKUP *
    // *****************

    #[tokio::test]
    // None authed user unable to access TwoFA [DELETE, PATCH, POST] route
    async fn api_router_user_two_fa_backup_unauthenticated() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        let result = client.delete(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client.patch(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client.post(&url).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Insert 10 backup codes, as hashes, and return 10 backup codes, as strings, to user
    /// expect email to have been sent
    async fn api_router_user_two_fa_backup_post_valid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 10);

        let result = result.json::<Response>().await.unwrap().response;
        assert!(result["backups"].is_array());

        assert_eq!(result["backups"].as_array().unwrap().len(), 10);

        assert_eq!(
            result["backups"]
                .as_array()
                .unwrap()
                .first()
                .unwrap()
                .as_str()
                .unwrap()
                .chars()
                .count(),
            16
        );

        // email sent - written to disk when testing & inserted into db
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        assert!(std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
                .unwrap()
                .contains("You have created Two-Factor Authentication backup codes for your staticPi account. The codes should be stored somewhere secure"));

        assert!(std::fs::read_to_string(EMAIL_HEADERS_LOCATION)
            .unwrap()
            .contains("Two-Factor Backup Enabled"));
    }

    #[tokio::test]
    /// unable to patch if password/token invalid, or missing
    async fn api_router_user_two_fa_backup_patch_invalid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        // delete emails!
        TestSetup::delete_emails();
        test_setup.delete_email_log().await;

        let valid_token = test_setup.get_valid_token();
        let body = HashMap::from([("password", gen_random_hex(12)), ("token", valid_token)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );
        // email not sent
        assert!(!std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(!std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());

        let invalid_token = test_setup.get_invalid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &invalid_token)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );
        // email not sent
        assert!(!std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(!std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
    }

    #[tokio::test]
    /// Old backup codes removed, 10 new codes inserted, as hashes, and return 10 backup codes, as strings, to user
    /// expect email to have been sent
    async fn api_router_user_two_fa_backup_patch_valid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        test_setup.delete_email_log().await;

        let result = result.json::<Response>().await.unwrap().response;

        let pre_first_code = result["backups"]
            .as_array()
            .unwrap()
            .first()
            .unwrap()
            .as_str();

        let valid_token = test_setup.get_valid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &valid_token)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 10);

        assert!(result["backups"].is_array());
        assert_eq!(result["backups"].as_array().unwrap().len(), 10);
        assert_eq!(
            result["backups"]
                .as_array()
                .unwrap()
                .first()
                .unwrap()
                .as_str()
                .unwrap()
                .chars()
                .count(),
            16
        );

        let post_first_code = result["backups"]
            .as_array()
            .unwrap()
            .first()
            .unwrap()
            .as_str();

        assert_ne!(pre_first_code, post_first_code);

        // email sent - written to disk when testing & inserted into db
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );

        assert!(std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
                .unwrap()
                .contains("You have re-generated Two-Factor Authentication backup codes for your staticPi account. Your previous backup codes are now invalid. The new codes should be stored somewhere secure."));

        assert!(std::fs::read_to_string(EMAIL_HEADERS_LOCATION)
            .unwrap()
            .contains("Two-Factor Backups re-generated"));
    }

    #[tokio::test]
    /// Conflict response if two_fa not enabled
    async fn api_router_user_two_patch_two_fa_backup_not_enabled() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        // needs password and token
        let authed_cookie = test_setup.authed_user_cookie().await;
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", "123456")]);

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Two FA not enabled");
    }

    #[tokio::test]
    /// Unable to delete if password or token invalid
    async fn api_router_user_two_fa_backup_delete_invalid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        TestSetup::delete_emails();
        test_setup.delete_email_log().await;
        let valid_token = test_setup.get_valid_token();
        let body = HashMap::from([("password", gen_random_hex(12)), ("token", valid_token)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 10);

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );
        assert!(!std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(!std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());

        let invalid_token = test_setup.get_invalid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &invalid_token)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 10);

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );
        assert!(!std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(!std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
    }

    #[tokio::test]
    /// Delete all backup codes
    async fn api_router_user_two_fa_backup_delete_valid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let user = test_setup.get_model_user().await.unwrap();
        ModelTwoFA::update_always_required(&test_setup.postgres, true, &user)
            .await
            .unwrap();

        let client = TestSetup::get_client();
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        test_setup.delete_email_log().await;

        let valid_token = test_setup.get_valid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &valid_token)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 0);

        // email sent - written to disk when testing & inserted into db
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        assert!(std::fs::exists(EMAIL_HEADERS_LOCATION).unwrap_or_default());
        assert!(std::fs::exists(EMAIL_BODY_LOCATION).unwrap_or_default());
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
                .unwrap()
                .contains("You have removed the Two-Factor Authentication backup codes for your staticPi account. New backup codes can be created at any time from the user settings page."));

        assert!(std::fs::read_to_string(EMAIL_HEADERS_LOCATION)
            .unwrap()
            .contains("Two-Factor Backup Disabled"));
    }

    // DOWNLOAD DATA - check data includes things, but no ids!
    // check rate limit is set, ttl , and can't download again
    // check email send etc

    //*************************
    // * Data Download Route  *
    // ************************

    #[tokio::test]
    // Unauthenticated user unable to [ POST ] /data route
    async fn api_router_user_data_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Data.addr()
        );

        let client = TestSetup::get_client();

        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let resp = client.post(url).json(&body).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Authenticated user invalid password and/or token [ POST ] /data route
    async fn api_router_user_data_invalid_auth() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Data.addr()
        );

        let del_limit = || async {
            test_setup
                .redis
                .clone()
                .del::<(), String>(format!(
                    "ratelimit::download_data::{}",
                    test_setup.get_user_id().get()
                ))
                .await
                .unwrap();
        };

        let client = TestSetup::get_client();

        // no body
        let resp = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "\"application/json\" header");

        del_limit().await;

        // invalid password
        let body = HashMap::from([("password", ANON_PASSWORD)]);
        let resp = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        del_limit().await;

        // invalid token
        test_setup.insert_two_fa().await;
        test_setup.two_fa_always_required(true).await;
        let token = test_setup.get_invalid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &token)]);
        let resp = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");
    }

    #[tokio::test]
    // Authenticated user, with valid password and token, able to download user data, [ POST ] /data route
    async fn api_router_user_data_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;
        let req = TestSetup::gen_req();
        test_setup.insert_anon_user().await;
        let anon_cookie = test_setup.anon_user_cookie().await.unwrap();
        let anon_device_name = test_setup.insert_device(&anon_cookie, None).await;

        let client = TestSetup::get_client();
        let url = format!("{}/incognito/contact", api_base_url(&test_setup.app_env),);
        let message = gen_random_hex(80);
        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);
        client.post(&url).json(&body).send().await.unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::TwoFABackup.addr()
        );

        client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Data.addr()
        );

        test_setup.request_reset().await;

        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        let api_key = test_setup.query_user_active_devices().await[0]
            .api_key_string
            .clone();

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let (mut ws_pi, _) = connect_async(&ws_pi_url).await.unwrap();

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let (mut ws_client, _) = connect_async(&ws_client_url).await.unwrap();

        let msg_text = gen_random_hex(24);
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();

        // stagger these, so that the bandwidth array is of fixed order, lazy I know
        sleep!(500);

        let msg_text = gen_random_hex(12);
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();

        // allow bandwidths to be inserted
        sleep!(500);
        ws_client.close(None).await.unwrap();
        sleep!(500);

        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let resp = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let result = resp.json::<Response>().await.unwrap().response;

        // make sure other user data isn't included!
        let as_str = result.as_str().unwrap();
        assert!(!as_str.contains(&anon_device_name));
        assert!(!as_str.contains(ANON_FULL_NAME));
        assert!(!as_str.contains(ANON_EMAIL));

        let result = serde_json::from_str::<Value>(as_str).unwrap();

        // API keys
        assert!(result.get("api").unwrap().is_array());
        let api = result.get("api").unwrap().as_array().unwrap();
        assert_eq!(api.len(), 1);
        let a_0 = api[0].as_object().unwrap();
        assert!(a_0.get("device_id").is_none());
        assert_eq!(a_0.get("active").unwrap().as_str().unwrap(), "true");
        assert_eq!(
            a_0.get("api_key_string").unwrap().as_str().unwrap(),
            api_key,
        );
        assert_eq!(a_0.get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
        assert!(a_0.get("timestamp").is_some());
        assert_eq!(
            a_0.get("user_agent_string").unwrap().as_str().unwrap(),
            req.user_agent
        );

        // Bandwidth
        assert!(result.get("bandwidth").unwrap().is_array());

        let bandwidth = result
            .get("bandwidth")
            .unwrap()
            .as_array()
            .unwrap()
            .to_owned();
        assert_eq!(bandwidth.len(), 4);
        let b_0 = &bandwidth[0];
        assert_eq!(b_0.get("is_counted").unwrap().as_str().unwrap(), "false");
        assert_eq!(b_0.get("is_pi").unwrap().as_str().unwrap(), "false");
        assert_eq!(
            b_0.get("name_of_device").unwrap().as_str().unwrap(),
            &device_name
        );
        assert_eq!(b_0.get("size_in_bytes").unwrap().as_str().unwrap(), "24");
        assert!(b_0.get("timestamp").is_some());
        assert!(b_0.get("hourly_bandwidth_id").is_none());

        let b_1 = &bandwidth[1];
        assert_eq!(b_1.get("is_counted").unwrap().as_str().unwrap(), "true");
        assert_eq!(b_1.get("is_pi").unwrap().as_str().unwrap(), "true");
        assert_eq!(
            b_1.get("name_of_device").unwrap().as_str().unwrap(),
            &device_name
        );
        assert_eq!(b_1.get("size_in_bytes").unwrap().as_str().unwrap(), "24");
        assert!(b_1.get("timestamp").is_some());

        let b_2 = &bandwidth[2];
        assert_eq!(b_2.get("is_counted").unwrap().as_str().unwrap(), "true");
        assert_eq!(b_2.get("is_pi").unwrap().as_str().unwrap(), "false");
        assert_eq!(
            b_2.get("name_of_device").unwrap().as_str().unwrap(),
            &device_name
        );
        assert_eq!(b_2.get("size_in_bytes").unwrap().as_str().unwrap(), "12");
        assert!(b_2.get("timestamp").is_some());

        let b_3 = &bandwidth[3];
        assert_eq!(b_3.get("is_counted").unwrap().as_str().unwrap(), "false");
        assert_eq!(b_3.get("is_pi").unwrap().as_str().unwrap(), "true");
        assert_eq!(
            b_3.get("name_of_device").unwrap().as_str().unwrap(),
            &device_name
        );
        assert_eq!(b_3.get("size_in_bytes").unwrap().as_str().unwrap(), "12");
        assert!(b_3.get("timestamp").is_some());

        // Connection
        assert!(result.get("connection").unwrap().is_array());

        let connection = result
            .get("connection")
            .unwrap()
            .as_array()
            .unwrap()
            .to_owned();
        assert_eq!(connection.len(), 2);

        assert_eq!(
            connection[0].get("ip").unwrap().as_str().unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            connection[0]
                .get("name_of_device")
                .unwrap()
                .as_str()
                .unwrap(),
            device_name
        );
        assert!(connection[0].get("timestamp_offline").unwrap().is_null());
        assert!(connection[0].get("is_pi").unwrap().as_bool().unwrap());
        assert!(connection[0].get("timestamp_online").is_some());
        assert_eq!(
            connection[0]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            "UNKNOWN"
        );

        assert_eq!(
            connection[1].get("ip").unwrap().as_str().unwrap(),
            "127.0.0.1"
        );

        assert_eq!(
            connection[1]
                .get("name_of_device")
                .unwrap()
                .as_str()
                .unwrap(),
            device_name
        );
        assert!(connection[1].get("timestamp_offline").is_some());
        assert!(!connection[1].get("is_pi").unwrap().as_bool().unwrap());
        assert!(connection[1].get("timestamp_online").is_some());
        assert_eq!(
            connection[1]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            "UNKNOWN"
        );

        let user = result.get("user").unwrap().as_object().unwrap();
        assert_eq!(
            user.get("ip").unwrap().as_str().unwrap(),
            req.ip.to_string()
        );
        assert_eq!(user.get("email").unwrap().as_str().unwrap(), TEST_EMAIL,);
        assert_eq!(
            user.get("full_name").unwrap().as_str().unwrap(),
            TEST_FULL_NAME,
        );
        assert!(user.get("timestamp").is_some());
        assert_eq!(
            user.get("user_agent_string").unwrap().as_str().unwrap(),
            req.user_agent
        );

        // Device
        assert!(result.get("device").unwrap().is_array());

        let device = result.get("device").unwrap().as_array().unwrap();
        assert_eq!(device.len(), 1);
        assert_eq!(device[0].get("active").unwrap().as_str().unwrap(), "true");
        assert_eq!(device[0].get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
        assert_eq!(
            device[0].get("name_of_device").unwrap().as_str().unwrap(),
            &device_name
        );
        assert!(device[0].get("timestamp").is_some());
        assert_eq!(
            device[0]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );

        //Emails
        assert!(result.get("emails").unwrap().is_array());
        let emails = result.get("emails").unwrap().as_array().unwrap().to_owned();
        assert_eq!(emails.len(), 3);

        assert_eq!(emails[0].get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
        assert_eq!(emails[1].get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
        assert_eq!(emails[2].get("ip").unwrap().as_str().unwrap(), "127.0.0.1");

        assert_eq!(
            emails[0].get("subject").unwrap().as_str().unwrap(),
            "Two-Factor Backup Enabled"
        );
        assert_eq!(
            emails[1].get("subject").unwrap().as_str().unwrap(),
            "Password Reset Requested"
        );
        assert_eq!(
            emails[2].get("subject").unwrap().as_str().unwrap(),
            "Download Data"
        );

        assert!(emails[0].get("timestamp").is_some());
        assert!(emails[1].get("timestamp").is_some());
        assert!(emails[2].get("timestamp").is_some());

        assert_eq!(
            emails[0]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );
        assert_eq!(
            emails[1]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );
        assert_eq!(
            emails[2]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );

        // Contact
        assert!(result.get("contact").unwrap().is_array());
        let contact = result
            .get("contact")
            .unwrap()
            .as_array()
            .unwrap()
            .to_owned();
        assert_eq!(contact.len(), 1);

        assert_eq!(contact[0].get("ip").unwrap().as_str().unwrap(), "127.0.0.1");

        assert!(contact[0].get("timestamp").is_some());

        assert_eq!(
            contact[0]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );

        assert_eq!(
            contact[0].get("message").unwrap().as_str().unwrap(),
            message
        );

        // Login History
        assert!(result.get("login_history").unwrap().is_array());

        let login_history = result.get("login_history").unwrap().as_array().unwrap();
        assert_eq!(login_history.len(), 1);
        assert_eq!(
            login_history[0].get("ip").unwrap().as_str().unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            login_history[0].get("success").unwrap().as_str().unwrap(),
            "true"
        );
        assert!(login_history[0].get("timestamp").is_some());
        assert_eq!(
            login_history[0]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );

        // Password Reset
        assert!(result.get("password_reset").unwrap().is_array());
        let password_reset = result.get("password_reset").unwrap().as_array().unwrap();
        assert_eq!(password_reset.len(), 1);

        assert_eq!(
            password_reset[0].get("ip").unwrap().as_str().unwrap(),
            "127.0.0.1"
        );
        assert!(password_reset[0].get("timestamp").is_some());
        assert_eq!(
            password_reset[0]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );

        // Two FA
        assert!(result.get("two_fa_secret").unwrap().is_array());

        let two_fa_secret = result.get("two_fa_secret").unwrap().as_array().unwrap();
        assert_eq!(two_fa_secret.len(), 1);
        assert_eq!(
            two_fa_secret[0].get("ip").unwrap().as_str().unwrap(),
            req.ip.to_string()
        );
        assert!(two_fa_secret[0].get("timestamp").is_some());
        assert_eq!(
            two_fa_secret[0]
                .get("user_agent_string")
                .unwrap()
                .as_str()
                .unwrap(),
            req.user_agent
        );

        // Two FA Backup
        assert!(result.get("two_fa_backup").unwrap().is_array());

        let two_fa_backup = result.get("two_fa_backup").unwrap().as_array().unwrap();
        assert_eq!(two_fa_backup.len(), 10);

        for i in two_fa_backup {
            assert_eq!(i.get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
            assert!(i.get("timestamp").is_some());
            assert_eq!(
                i.get("user_agent_string").unwrap().as_str().unwrap(),
                req.user_agent
            );
        }

        // User
        assert!(result.get("user").unwrap().is_object());

        let user = result.get("user").unwrap().as_object().unwrap();
        assert_eq!(
            user.get("ip").unwrap().as_str().unwrap(),
            req.ip.to_string()
        );
        assert_eq!(user.get("email").unwrap().as_str().unwrap(), TEST_EMAIL,);
        assert_eq!(
            user.get("full_name").unwrap().as_str().unwrap(),
            TEST_FULL_NAME,
        );
        assert!(user.get("timestamp").is_some());
        assert_eq!(
            user.get("user_agent_string").unwrap().as_str().unwrap(),
            req.user_agent
        );
    }

    #[tokio::test]
    // Authenticated user ratelimited for 1 day after first attempt, [ POST ] /data route
    async fn api_router_user_data_limit_invalid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            UserRoutes::Data.addr()
        );

        let client = TestSetup::get_client();

        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let resp = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // second request gets ratelimited for 24 hours - aka 86400 seconds
        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let resp = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Limited to one download per 24-hours");

        let key = format!(
            "ratelimit::download_data::{}",
            test_setup.get_user_id().get()
        );

        let limit: isize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(limit, 2);

        let ttl: isize = test_setup.redis.ttl(&key).await.unwrap();
        assert_eq!(ttl, 86400);
    }
}

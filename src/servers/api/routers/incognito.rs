use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    PrivateCookieJar,
};
use rand::Rng;
use sqlx::PgPool;
use std::fmt;
use time::Duration;
use ulid::Ulid;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Router,
};

use crate::{
    api_error::ApiError,
    argon::ArgonHash,
    database::{
        all_bandwidth::ModelAllBandwidth,
        banned_domain::ModelBannedEmail,
        contact_message::ModelContactMessage,
        email_address::ModelEmailAddress,
        invite::ModelInvite,
        ip_user_agent::ModelUserAgentIp,
        login::ModelLogin,
        new_types::UserId,
        new_user::RedisNewUser,
        password_reset::ModelPasswordReset,
        rate_limit::{LimitContact, RateLimit},
        session::RedisSession,
        user::ModelUser,
    },
    define_routes,
    emailer::{EmailTemplate, Emailer},
    helpers::{self, calc_uptime},
    servers::{api::authentication, ApiRouter, ApplicationState, StatusOJ},
    sleep,
    user_io::{incoming_json::ij, outgoing_json::oj},
};

define_routes! {
    IncognitoRoutes,
    "/incognito",
    Bandwidth => "/bandwidth",
    Contact => "/contact",
    Online => "/online",
    Register => "/register",
    Reset => "/reset",
    ResetParam => "/reset/:ulid",
    Signin => "/signin",
    VerifyParam => "/verify/:ulid"
}

enum IncognitoResponse {
    AgeInvalid,
    AgreeInvalid,
    DomainBanned(String),
    Instructions,
    InviteInvalid,
    ResetPatch,
    UnsafePassword,
    Verified,
    VerifyInvalid,
}

impl fmt::Display for IncognitoResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let disp = match self {
            Self::AgeInvalid => "Please confirm that you aged 13 years or older".to_owned(),
            Self::AgreeInvalid => "Please agree to the terms & conditions".to_owned(),
            Self::DomainBanned(domain) => format!("{domain} is a banned domain"),
            Self::InviteInvalid => "invite invalid".to_owned(),
            Self::UnsafePassword => "unsafe password".to_owned(),
            Self::Verified => "Account verified, please sign in to continue".to_owned(),
            Self::VerifyInvalid => "Incorrect verification data".to_owned(),
            Self::Instructions => {
                "Instructions have been sent to the email address provided".to_owned()
            }
            Self::ResetPatch => "Password reset complete - please sign in".to_owned(),
        };
        write!(f, "{disp}")
    }
}

pub struct IncognitoRouter;

impl ApiRouter for IncognitoRouter {
    fn create_router(state: &ApplicationState) -> Router<ApplicationState> {
        Router::new()
            .route(&IncognitoRoutes::Register.addr(), post(Self::register_post))
            .route(
                &IncognitoRoutes::ResetParam.addr(),
                get(Self::reset_param_get).patch(Self::reset_param_patch),
            )
            .route(&IncognitoRoutes::Reset.addr(), post(Self::reset_post))
            .route(
                &IncognitoRoutes::VerifyParam.addr(),
                get(Self::verify_param_get),
            )
            .layer(middleware::from_fn_with_state(
                state.clone(),
                authentication::not_authenticated,
            ))
            .route(&IncognitoRoutes::Contact.addr(), post(Self::contact_post))
            .route(&IncognitoRoutes::Signin.addr(), post(Self::signin_post))
            .route(&IncognitoRoutes::Online.addr(), get(Self::get_online))
            .route(&IncognitoRoutes::Bandwidth.addr(), get(Self::get_bandwidth))
    }
}

impl IncognitoRouter {
    /// Return the bandwidth stats
    async fn get_bandwidth(
        State(state): State<ApplicationState>,
    ) -> Result<StatusOJ<ModelAllBandwidth>, ApiError> {
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(ModelAllBandwidth::get(&state.postgres).await?),
        ))
    }

    #[allow(clippy::unused_async)]
    /// Return a simple online status response
    async fn get_online(State(state): State<ApplicationState>) -> StatusOJ<oj::Online> {
        (
            StatusCode::OK,
            oj::OutgoingJson::new(oj::Online {
                uptime: calc_uptime(state.start_time),
                api_version: env!("CARGO_PKG_VERSION").into(),
            }),
        )
    }

    /// Register a new user - requires further validation to be inserted into postgres
    async fn register_post(
        State(state): State<ApplicationState>,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::Register>,
    ) -> Result<StatusOJ<String>, ApiError> {
        let response = (
            StatusCode::OK,
            oj::OutgoingJson::new(IncognitoResponse::Instructions.to_string()),
        );

        if !body.age {
            return Err(ApiError::InvalidValue(
                IncognitoResponse::AgeInvalid.to_string(),
            ));
        }
        if !body.agree {
            return Err(ApiError::InvalidValue(
                IncognitoResponse::AgreeInvalid.to_string(),
            ));
        }

        if let Some(domain) = ModelBannedEmail::get(&state.postgres, &body.email).await? {
            return Err(ApiError::InvalidValue(
                IncognitoResponse::DomainBanned(domain.domain).to_string(),
            ));
        }

        // Check if password is exposed in HIBP
        if helpers::pwned_password(&body.password).await? {
            return Err(ApiError::InvalidValue(
                IncognitoResponse::UnsafePassword.to_string(),
            ));
        }

        // If email address can be found in redis verify cache, or postgres proper, just return a success response
        // Shouldn't even let a client know if a user is registered or not
        let (redis_user, postgres_email, postgres_user) = tokio::try_join!(
            RedisNewUser::exists(&state.redis, &body.email),
            ModelEmailAddress::get(&state.postgres, &body.email),
            ModelUser::get(&state.postgres, &body.email)
        )?;

        if redis_user || postgres_user.is_some() {
            return Ok(response);
        }

        if RateLimit::Register(body.email.clone())
            .check(&state.redis)
            .await
            .is_err()
        {
            return Ok(response);
        };

        if !helpers::xor(body.invite.as_bytes(), state.invite.as_bytes())
            && !ModelInvite::valid(&state.postgres, &body.invite).await?
        {
            return Err(ApiError::InvalidValue(
                IncognitoResponse::InviteInvalid.to_string(),
            ));
        }

        let password_hash = ArgonHash::new(body.password.clone()).await?;
        let secret = Ulid::new();

        let email = if let Some(email) = postgres_email {
            email
        } else {
            ModelEmailAddress::insert(&state.postgres, &body.email).await?
        };

        RedisNewUser::new(&email, &body.full_name, &password_hash, &useragent_ip)
            .insert(&state.redis, &secret)
            .await?;

        // Email user verification code/link email
        Emailer::new(
            &body.full_name,
            &email.email,
            EmailTemplate::Verify(secret),
            &state.email_env,
        )
        .send(&state.postgres, &useragent_ip)
        .await?;

        Ok(response)
    }

    /// Insert a password reset entry, email user the secret link
    /// Always return same response, even if user/email isn't known in database
    async fn reset_post(
        State(state): State<ApplicationState>,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::Reset>,
    ) -> Result<StatusOJ<String>, ApiError> {
        let (op_reset_in_progress, op_user) = tokio::try_join!(
            ModelPasswordReset::get_by_email(&state.postgres, &body.email),
            ModelUser::get(&state.postgres, &body.email)
        )?;

        if let (Some(user), None) = (op_user, op_reset_in_progress) {
            let ulid = Ulid::new();
            ModelPasswordReset::insert(
                &state.postgres,
                user.registered_user_id,
                &ulid,
                &useragent_ip,
            )
            .await?;
            Emailer::new(
                &user.full_name,
                &user.email,
                EmailTemplate::PasswordResetRequested(ulid),
                &state.email_env,
            )
            .send(&state.postgres, &useragent_ip)
            .await?;
        }
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(IncognitoResponse::Instructions.to_string()),
        ))
    }

    /// Update the user password from a `password_reset` request, will kill all api user sessions
    async fn reset_param_patch(
        State(state): State<ApplicationState>,
        useragent_ip: ModelUserAgentIp,
        Path(ulid): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusOJ<String>, ApiError> {
        if let Ok(ulid) = Ulid::from_string(&ulid) {
            // Don't even hit the db if the ulid is older than 1 hour

            // refactor this, make a TTL trait!
            if std::time::SystemTime::now()
                .duration_since(ulid.datetime())?
                .as_secs()
                > ModelPasswordReset::TTL_AS_SEC.into()
            {
                return Err(ApiError::InvalidValue(
                    IncognitoResponse::VerifyInvalid.to_string(),
                ));
            }

            if let Some(reset_user) =
                ModelPasswordReset::get_by_ulid(&state.postgres, &ulid).await?
            {
                if let Some(two_fa_secret) = reset_user.two_fa_secret {
                    if !authentication::check_token(
                        body.token,
                        &state.postgres,
                        &two_fa_secret,
                        reset_user.registered_user_id,
                        reset_user.two_fa_backup_count,
                    )
                    .await?
                    {
                        return Err(ApiError::Authorization);
                    }
                }

                // Check if password is exposed in HIBP or new_password contains users email address
                if helpers::pwned_password(&body.password).await?
                    || body
                        .password
                        .to_lowercase()
                        .contains(&reset_user.email.to_lowercase())
                {
                    return Err(ApiError::InvalidValue(
                        IncognitoResponse::UnsafePassword.to_string(),
                    ));
                }

                let password_hash = ArgonHash::new(body.password.clone()).await?;

                tokio::try_join!(
                    ModelUser::update_password(
                        &state.postgres,
                        reset_user.registered_user_id,
                        password_hash
                    ),
                    ModelPasswordReset::consume(&state.postgres, reset_user.password_reset_id)
                )?;
                RedisSession::delete_all(&state.redis, reset_user.registered_user_id).await?;
                Emailer::new(
                    &reset_user.full_name,
                    &reset_user.email,
                    EmailTemplate::PasswordChanged,
                    &state.email_env,
                )
                .send(&state.postgres, &useragent_ip)
                .await?;
                Ok((
                    StatusCode::OK,
                    oj::OutgoingJson::new(IncognitoResponse::ResetPatch.to_string()),
                ))
            } else {
                Err(ApiError::InvalidValue(
                    IncognitoResponse::VerifyInvalid.to_string(),
                ))
            }
        } else {
            Err(ApiError::InvalidValue(
                IncognitoResponse::VerifyInvalid.to_string(),
            ))
        }
    }

    /// check if a given reset string is still valid, and also return the two-fa status of the user
    async fn reset_param_get(
        State(state): State<ApplicationState>,
        Path(ulid): Path<String>,
    ) -> Result<StatusOJ<oj::PasswordReset>, ApiError> {
        if let Ok(ulid) = Ulid::from_string(&ulid) {
            // Don't even hit the db if the ulid is older than 1 hour
            if std::time::SystemTime::now()
                .duration_since(ulid.datetime())?
                .as_secs()
                > ModelPasswordReset::TTL_AS_SEC.into()
            {
                return Err(ApiError::InvalidValue(
                    IncognitoResponse::VerifyInvalid.to_string(),
                ));
            }

            if let Some(valid_reset) =
                ModelPasswordReset::get_by_ulid(&state.postgres, &ulid).await?
            {
                let response = oj::PasswordReset {
                    two_fa_active: valid_reset.two_fa_secret.is_some(),
                    two_fa_backup: valid_reset.two_fa_backup_count > 0,
                };
                Ok((StatusCode::OK, oj::OutgoingJson::new(response)))
            } else {
                Err(ApiError::InvalidValue(
                    IncognitoResponse::VerifyInvalid.to_string(),
                ))
            }
        } else {
            Err(ApiError::InvalidValue(
                IncognitoResponse::VerifyInvalid.to_string(),
            ))
        }
    }

    /// User gets emailed a link when they sign up, they hit this route and it verifies the email address
    /// and insert the new user into postgres
    async fn verify_param_get(
        State(state): State<ApplicationState>,
        Path(ulid): Path<String>,
    ) -> Result<StatusOJ<String>, ApiError> {
        if let Ok(ulid) = Ulid::from_string(&ulid) {
            // Don't even hit the db if the ulid is older than 1 hour
            if std::time::SystemTime::now()
                .duration_since(ulid.datetime())?
                .as_secs()
                > RedisNewUser::TTL_AS_SEC.into()
            {
                return Err(ApiError::InvalidValue(
                    IncognitoResponse::VerifyInvalid.to_string(),
                ));
            }
            if let Some(new_user) = RedisNewUser::get(&state.redis, &ulid).await? {
                ModelUser::insert(&state.postgres, &new_user).await?;
                RedisNewUser::delete(&new_user, &state.redis, &ulid).await?;
                Ok((
                    StatusCode::OK,
                    oj::OutgoingJson::new(IncognitoResponse::Verified.to_string()),
                ))
            } else {
                Err(ApiError::InvalidValue(
                    IncognitoResponse::VerifyInvalid.to_string(),
                ))
            }
        } else {
            Err(ApiError::InvalidValue(
                IncognitoResponse::VerifyInvalid.to_string(),
            ))
        }
    }

    /// Insert an invalid signin entry
    async fn invalid_signin(
        postgres: &PgPool,
        registered_user_id: UserId,
        useragent_ip: ModelUserAgentIp,
    ) -> Result<ApiError, ApiError> {
        ModelLogin::insert(postgres, registered_user_id, useragent_ip, false, None).await?;
        Ok(ApiError::Authorization)
    }

    /// Insert a contact_message
    async fn contact_post(
        State(state): State<ApplicationState>,
        useragent_ip: ModelUserAgentIp,
        jar: PrivateCookieJar,
        ij::IncomingJson(body): ij::IncomingJson<ij::Contact>,
    ) -> Result<StatusCode, ApiError> {
        let ip_limit = RateLimit::Contact(LimitContact::Ip(useragent_ip.ip))
            .check(&state.redis)
            .await;
        let email_limit = RateLimit::Contact(LimitContact::Email(body.email.clone()))
            .check(&state.redis)
            .await;

        ip_limit?;
        email_limit?;

        let registered_user_id = if let Some(data) = jar.get(&state.cookie_name) {
            if let Ok(ulid) = Ulid::from_string(data.value()) {
                RedisSession::get(&state.redis, &state.postgres, &ulid)
                    .await?
                    .map(|i| i.registered_user_id)
            } else {
                None
            }
        } else {
            None
        };
        let mut transaction = state.postgres.begin().await?;
        let email_address_id =
            if let Some(email) = ModelEmailAddress::get(&mut *transaction, &body.email).await? {
                email.email_address_id
            } else {
                ModelEmailAddress::insert(&mut *transaction, &body.email)
                    .await?
                    .email_address_id
            };
        ModelContactMessage::insert(
            &mut *transaction,
            useragent_ip,
            registered_user_id,
            body.message,
            email_address_id,
        )
        .await?;
        transaction.commit().await?;

        Ok(StatusCode::OK)
    }

    // this is where one needs to check password, token, create session, create cookie,
    // Redirect to /user, so can get user object?
    #[allow(clippy::too_many_lines)]
    async fn signin_post(
        State(state): State<ApplicationState>,
        useragent_ip: ModelUserAgentIp,
        jar: PrivateCookieJar,
        ij::IncomingJson(body): ij::IncomingJson<ij::Signin>,
    ) -> Result<impl IntoResponse, ApiError> {
        // If front end and back end out of sync, and front end user has an api cookie, but not front-end authed, delete server cookie api session
        let ms = || rand::thread_rng().gen_range(100..500);
        // remove previous current session
        if let Some(data) = jar.get(&state.cookie_name) {
            if let Ok(ulid) = Ulid::from_string(data.value()) {
                RedisSession::delete(&state.redis, &ulid).await?;
            }
        }

        if let Some(user) = ModelUser::get(&state.postgres, &body.email).await? {
            // Email user that account is blocked
            if user.login_attempt_number == 19 {
                Emailer::new(
                    &user.full_name,
                    &user.email,
                    EmailTemplate::AccountLocked,
                    &state.email_env,
                )
                .send(&state.postgres, &useragent_ip)
                .await?;
            }

            // Don't allow blocked accounts to even try to authenticate
            if user.login_attempt_number >= 19 {
                sleep!(ms());
                return Err(Self::invalid_signin(
                    &state.postgres,
                    user.registered_user_id,
                    useragent_ip,
                )
                .await?);
            }
            // Check password before 2fa token request
            if !authentication::check_signin_password(&user, &body.password).await? {
                return Err(Self::invalid_signin(
                    &state.postgres,
                    user.registered_user_id,
                    useragent_ip,
                )
                .await?);
            }

            // If twofa token required, but not sent, 202 response
            if user.two_fa_secret.is_some() && body.token.is_none() {
                // Should this increase the login count?, yes
                ModelLogin::insert(
                    &state.postgres,
                    user.registered_user_id,
                    useragent_ip,
                    false,
                    None,
                )
                .await?;
                // Think I should throw an error here
                // So that the function return type can be strict
                // need to included two_backup as a bool
                return Ok((
                    StatusCode::ACCEPTED,
                    oj::OutgoingJson::new(oj::SigninAccepted {
                        two_fa_backup: user.two_fa_backup_count > 0,
                    }),
                )
                    .into_response());
            }

            if !authentication::check_password_token(
                &user,
                &body.password,
                body.token,
                &state.postgres,
            )
            .await?
            {
                return Err(Self::invalid_signin(
                    &state.postgres,
                    user.registered_user_id,
                    useragent_ip,
                )
                .await?);
            }

            let ulid = Ulid::new();
            ModelLogin::insert(
                &state.postgres,
                user.registered_user_id,
                useragent_ip,
                true,
                Some(ulid),
            )
            .await?;

            let ttl = if body.remember {
                Duration::weeks(4 * 6)
            } else {
                Duration::hours(6)
            };

            let mut cookie = Cookie::new(state.cookie_name.clone(), ulid.to_string());
            cookie.set_domain(state.domain.clone());
            cookie.set_path("/");
            cookie.set_secure(state.run_mode.is_production());
            cookie.set_same_site(SameSite::Strict);
            cookie.set_http_only(true);
            cookie.set_max_age(ttl);

            RedisSession::new(user.registered_user_id, &user.email)
                .insert(&state.redis, ttl, ulid)
                .await?;

            Ok(jar.add(cookie).into_response())
        } else {
            sleep!(ms());
            Err(ApiError::Authorization)
        }
    }
}

// Use reqwest to test against real server
// cargo watch -q -c -w src/ -x 'test api_router_incognito -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {

    use super::IncognitoRoutes;
    use crate::servers::api::api_tests::EMAIL_BODY_LOCATION;
    use crate::{database::contact_message::ModelContactMessage, servers::api::api_tests::EMAIL_HEADERS_LOCATION};
    use crate::database::email_address::ModelEmailAddress;
    use crate::database::email_log::ModelEmailLog;
    use crate::database::invite::ModelInvite;
    use crate::database::login::ModelLogin;
    use crate::database::new_user::RedisNewUser;
    use crate::database::password_reset::ModelPasswordReset;
    use crate::database::session::RedisSession;
    use crate::helpers::gen_random_hex;
    use crate::servers::test_setup::*;
    use crate::sleep;
    use fred::interfaces::{HashesInterface, KeysInterface, SetsInterface};
    use reqwest::StatusCode;
    use std::collections::HashMap;
    use ulid::Ulid;

    // ****************
    // * Signin route *
    // ****************

    #[tokio::test]
    /// Unknown user, 403
    async fn api_router_incognito_signin_post_unknown() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_signin_body(None, None, None, None);
        let result = client.post(&url).json(&body).send().await.unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );
    }

    #[tokio::test]
    /// invalid login, attempt counter increased
    async fn api_router_incognito_signin_post_login_attempt_increase() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));
        let body = TestSetup::gen_signin_body(
            None,
            Some("thisistheincorrectpassword".to_owned()),
            None,
            None,
        );

        let result = client.post(&url).json(&body).send().await.unwrap();
        let user = test_setup.get_model_user().await.unwrap();
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 1);
    }

    #[tokio::test]
    /// invalid login - bad token, login attempt counter increased by one
    async fn api_router_incognito_signin_post_login_bad_token_attempt_increase() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.insert_two_fa().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));
        let valid_token = test_setup.get_invalid_token();

        let body = TestSetup::gen_signin_body(None, None, Some(valid_token), None);

        let result = client.post(&url).json(&body).send().await.unwrap();
        let user = test_setup.get_model_user().await.unwrap();
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 1);
    }

    #[tokio::test]
    /// 20 invalid attempts, email sent, all further valid login still unable to complete
    async fn api_router_incognito_signin_post_20_email_sent() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_signin_body(
            None,
            Some("thisistheincorrectpassword".to_owned()),
            None,
            None,
        );

        for _ in 0..=19 {
            client.post(&url).json(&body).send().await.unwrap();
        }

        let result = std::fs::read_to_string(EMAIL_HEADERS_LOCATION);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Subject: Security Alert"));
        let result = std::fs::read_to_string(EMAIL_BODY_LOCATION);
        assert!(result.is_ok());
        assert!(result
            .unwrap()
            .contains("Due to multiple failed login attempts your account has been locked."));

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );

        let body = TestSetup::gen_signin_body(None, None, None, None);

        // Valid login attempt unable to complete
        let result = client.post(&url).json(&body).send().await.unwrap();
        let user = test_setup.get_model_user().await.unwrap();
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 21);
    }

    #[tokio::test]
    /// After one invalid, and then one valid, signin attempt, login_count = 0
    async fn api_router_incognito_signin_post_login_attempt_reset() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.insert_two_fa().await;
        let valid_token = test_setup.get_valid_token();
        let invalid_token = test_setup.get_invalid_token();
        let client = TestSetup::get_client();

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_signin_body(None, None, Some(invalid_token), None);

        // Valid login attempt unable to complete
        let result = client.post(&url).json(&body).send().await.unwrap();
        let user = test_setup.get_model_user().await.unwrap();
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 1);

        let body = TestSetup::gen_signin_body(None, None, Some(valid_token), None);

        // Valid login attempt unable to complete
        let result = client.post(&url).json(&body).send().await.unwrap();
        let user = test_setup.get_model_user().await.unwrap();
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;

        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 0);
    }

    #[tokio::test]
    /// When two factor enabled, but no token provided, should return a 202 message
    async fn api_router_incognito_signin_post_login_no_token() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.insert_two_fa().await;
        let client = TestSetup::get_client();
        let user = test_setup.get_model_user().await.unwrap();

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_signin_body(None, None, None, None);

        // Valid login attempt unable to complete
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::ACCEPTED);
        let result = result.json::<Response>().await.unwrap().response;

        assert_eq!(result["two_fa_backup"], false);

        // Login count should increase on a 202 response
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 1);
    }

    #[tokio::test]
    /// After one invalid attempt, submit a valid attempt, login_count should now equal = 0
    async fn api_router_incognito_signin_post_with_token_login_attempt_reset() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.insert_two_fa().await;
        let client = TestSetup::get_client();
        let valid_token = test_setup.get_valid_token();

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_signin_body(
            None,
            Some("thisistheincorrectpassword".to_owned()),
            Some(valid_token.clone()),
            None,
        );

        let result = client.post(&url).json(&body).send().await.unwrap();
        let user = test_setup.get_model_user().await.unwrap();
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 1);

        let body = TestSetup::gen_signin_body(None, None, Some(valid_token), None);

        // Valid login attempt unable to complete
        let result = client.post(&url).json(&body).send().await.unwrap();
        let user = test_setup.get_model_user().await.unwrap();
        let login_count = ModelLogin::get(&test_setup.postgres, user.registered_user_id).await;

        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(login_count.unwrap().unwrap().login_attempt_number, 0);
    }

    #[tokio::test]
    /// Valid login, session created, cookie returned
    async fn api_router_incognito_signin_post_valid_session_not_remember() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();
        let user = test_setup.get_model_user().await.unwrap();

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_signin_body(None, None, None, None);

        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // Assert cookie is received & correct
        let cookie = result.headers().get("set-cookie");
        assert!(cookie.is_some());

        let cookie = cookie.unwrap();
        assert!(cookie
            .to_str()
            .unwrap()
            .contains("HttpOnly; SameSite=Strict; Path=/; Domain=127.0.0.1; Max-Age=21600"));

        // Assert session in db
        let session_vec = get_keys(&test_setup.redis, "session::*").await;
        assert_eq!(session_vec.len(), 1);
        let session_name = session_vec.first().unwrap();
        let session: RedisSession = test_setup.redis.hget(session_name, "data").await.unwrap();
        let session_ttl: usize = test_setup.redis.ttl(session_name).await.unwrap();

        assert!(session_ttl > 21598);
        assert!(session_ttl < 21601);
        // and also less than!

        let key = format!(
            "session_set::user::{}",
            test_setup.model_user.unwrap().registered_user_id.get()
        );
        let redis_set: Vec<String> = test_setup.redis.smembers(key).await.unwrap();
        assert!(redis_set.len() == 1);

        assert_eq!(session.registered_user_id, user.registered_user_id);
        assert_eq!(session.email, user.email);
    }

    #[tokio::test]
    /// Valid login, session created, cookie returned, session valid for 14515200 seconds / 168 days
    async fn api_router_incognito_signin_post_valid_session_remember() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();
        let user = test_setup.get_model_user().await.unwrap();

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_signin_body(None, None, None, Some(true));

        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // Assert cookie is received & correct
        let cookie = result.headers().get("set-cookie");
        assert!(cookie.is_some());

        let cookie = cookie.unwrap();
        assert!(cookie
            .to_str()
            .unwrap()
            .contains("HttpOnly; SameSite=Strict; Path=/; Domain=127.0.0.1; Max-Age=14515200"));

        // Assert session in db
        let session_vec = get_keys(&test_setup.redis, "session::*").await;
        assert_eq!(session_vec.len(), 1);
        let session_name = session_vec.first().unwrap();
        let session: RedisSession = test_setup.redis.hget(session_name, "data").await.unwrap();
        let session_ttl: usize = test_setup.redis.ttl(session_name).await.unwrap();

        assert!(session_ttl > 14_515_199);
        assert!(session_ttl < 14_515_201);

        let key = format!(
            "session_set::user::{}",
            test_setup.model_user.unwrap().registered_user_id.get()
        );
        let redis_set: Vec<String> = test_setup.redis.smembers(key).await.unwrap();
        assert!(redis_set.len() == 1);

        assert_eq!(session.registered_user_id, user.registered_user_id);
        assert_eq!(session.email, user.email);
    }

    #[tokio::test]
    /// Able to sign in if already signed in, but old session gets destroyed
    /// New session created, previous one destroyed
    async fn api_router_incognito_signin_post_authed_already_authed_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));
        let body = TestSetup::gen_signin_body(None, None, None, None);
        let authed_cookie = test_setup.authed_user_cookie().await;

        let key = format!(
            "session_set::user::{}",
            test_setup.model_user.unwrap().registered_user_id.get()
        );
        let pre_set: Vec<String> = test_setup.redis.smembers(&key).await.unwrap();
        assert!(pre_set.len() == 1);

        let result = client
            .post(&url)
            .json(&body)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let post_set: Vec<String> = test_setup.redis.smembers(key).await.unwrap();

        assert_ne!(pre_set[0], post_set[0]);
        assert!(post_set.len() == 1);
    }

    #[tokio::test]
    async fn api_router_incognito_signin_post_backup_token_invalid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;

        let client = reqwest::Client::new();
        let url = format!(
            "{}/authenticated/user/twofa/backup",
            api_base_url(&test_setup.app_env)
        );

        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 10);

        // This can fail! Unlikely but not zero
        let token = "519181150EEEAC92";

        let body = TestSetup::gen_signin_body(None, None, Some(token.to_owned()), None);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 10);
    }

    #[tokio::test]
    async fn api_router_incognito_signin_post_backup_token_valid() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_two_fa().await;

        let client = reqwest::Client::new();
        let url = format!(
            "{}/authenticated/user/twofa/backup",
            api_base_url(&test_setup.app_env)
        );

        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        let result = result.json::<Response>().await.unwrap().response;
        let codes = result["backups"].as_array().unwrap();

        let url = format!("{}/incognito/signin", api_base_url(&test_setup.app_env));

        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 10);

        let token = codes[4].as_str().unwrap();

        let body = TestSetup::gen_signin_body(None, None, Some(token.to_owned()), None);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 9);

        // Using the same backup code again fails
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let user = test_setup.get_model_user().await.unwrap();
        assert_eq!(user.two_fa_backup_count, 9);
    }

    // ****************
    // * Online route *
    // ****************

    #[tokio::test]
    async fn api_router_incognito_get_online() {
        let test_setup = start_servers().await;
        let url = format!("{}/incognito/online", api_base_url(&test_setup.app_env));
        sleep!(1000);
        let resp = reqwest::get(url).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(result["uptime"], 1);
    }

    #[tokio::test]
    async fn api_router_incognito_get_online_when_authenticated() {
        let mut test_setup = start_servers().await;
        let url = format!("{}/incognito/online", api_base_url(&test_setup.app_env));
        let client = TestSetup::get_client();
        sleep!(1000);

        let authed_cookie = test_setup.authed_user_cookie().await;

        let resp = client
            .get(url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert!(result["uptime"].as_i64().unwrap() >= 1);
    }

    // *******************
    // * Bandwidth route *
    // *******************

    #[tokio::test]
    async fn api_router_incognito_bandwidth_ok() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/bandwidth", api_base_url(&test_setup.app_env));

        client.get(&url).send().await.unwrap();

        let result = reqwest::get(url).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let result = result.json::<Response>().await.unwrap().response;

        assert!(result
            .as_object()
            .unwrap()
            .get("hour_in")
            .unwrap()
            .is_number());
        assert!(result
            .as_object()
            .unwrap()
            .get("hour_out")
            .unwrap()
            .is_number());

        assert!(result
            .as_object()
            .unwrap()
            .get("day_in")
            .unwrap()
            .is_number());
        assert!(result
            .as_object()
            .unwrap()
            .get("day_out")
            .unwrap()
            .is_number());

        assert!(result
            .as_object()
            .unwrap()
            .get("month_in")
            .unwrap()
            .is_number());
        assert!(result
            .as_object()
            .unwrap()
            .get("month_out")
            .unwrap()
            .is_number());

        assert!(result
            .as_object()
            .unwrap()
            .get("total_in")
            .unwrap()
            .is_number());
        assert!(result
            .as_object()
            .unwrap()
            .get("total_out")
            .unwrap()
            .is_number());
    }

    // ******************
    // * Register route *
    // ******************

    #[tokio::test]
    async fn api_router_incognito_register_invalid_invite() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            "some_long_invite",
            TEST_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "invite invalid"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_banned_email() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));
        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            "email@0-mail.com",
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "0-mail.com is a banned domain"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_short_password() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            "password123",
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "password"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_hibp_password() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            UNSAFE_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "unsafe password"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_age_false() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            false,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Please confirm that you aged 13 years or older"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_agree_false() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            false,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Please agree to the terms & conditions"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_already_registered() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        test_setup.insert_test_user().await;

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );

        // Check email HAS NOT been sent
        let result = RedisNewUser::exists(&test_setup.redis, "email@mrjackwills.com").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
        let result = std::fs::metadata(EMAIL_HEADERS_LOCATION);
        assert!(result.is_err());
        let result = std::fs::metadata(EMAIL_BODY_LOCATION);
        assert!(result.is_err());
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );
    }

    #[tokio::test]
    /// If authenticated, unable to access register endpoint
    async fn api_router_incognito_register_already_authenticated() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));
        let authed_cookie = test_setup.authed_user_cookie().await;

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client
            .post(&url)
            .json(&body)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            "Invalid Authentication",
            result.json::<Response>().await.unwrap().response
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_newuser_in_redis() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );
        let result = RedisNewUser::exists(&test_setup.redis, TEST_EMAIL).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // check email sent - well written to disk & inserted into db
        let result = std::fs::metadata(EMAIL_HEADERS_LOCATION);
        assert!(result.is_ok());
        let result = std::fs::metadata(EMAIL_BODY_LOCATION);
        assert!(result.is_ok());
        let link = format!(
            "href=\"https://www.{}/user/verify/",
            test_setup.app_env.domain
        );
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
            .unwrap()
            .contains(&link));
    }

    #[tokio::test]
    /// Registereding, when already registered, will result in email instructions sent, but nothing in db, check redis register rate limit is valid
    async fn api_router_incognito_register_twice() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );

        let result = RedisNewUser::exists(&test_setup.redis, TEST_EMAIL).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // check email sent - well written to disk & inserted into db
        let result = std::fs::metadata(EMAIL_HEADERS_LOCATION);
        assert!(result.is_ok());
        let result = std::fs::metadata(EMAIL_BODY_LOCATION);
        assert!(result.is_ok());
        let link = format!(
            "href=\"https://www.{}/user/verify/",
            test_setup.app_env.domain
        );
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
            .unwrap()
            .contains(&link));
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );

        let first_secret = get_keys(&test_setup.redis, "verify::secret::*").await;

        test_setup.delete_email_log().await;
        TestSetup::delete_emails();

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );

        let result = RedisNewUser::exists(&test_setup.redis, TEST_EMAIL).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );
        let result = std::fs::metadata(EMAIL_HEADERS_LOCATION);
        assert!(result.is_err());
        let result = std::fs::metadata(EMAIL_BODY_LOCATION);
        assert!(result.is_err());

        let second_secret = get_keys(&test_setup.redis, "verify::secret::*").await;
        assert_eq!(first_secret, second_secret);

        let register_rate_limit: i8 = test_setup
            .redis
            .get(format!("ratelimit::register::{TEST_EMAIL}"))
            .await
            .unwrap();
        assert_eq!(register_rate_limit, 1);

        let register_ttl: isize = test_setup
            .redis
            .ttl(format!("ratelimit::register::{TEST_EMAIL}"))
            .await
            .unwrap();
        assert!((86395..=86400).contains(&register_ttl));
    }

    #[tokio::test]
    /// Can register with invite in database, count gets reduced by 1, Invite::valid now returns false
    async fn api_router_incognito_register_with_db_invite() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));
        test_setup.insert_test_user().await;
        let invite = test_setup.insert_invite().await;

        let body = TestSetup::gen_register_body(
            ANON_FULL_NAME,
            ANON_PASSWORD,
            &invite,
            ANON_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );

        let result = RedisNewUser::exists(&test_setup.redis, ANON_EMAIL).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // check email sent - well written to disk & inserted into db
        let result = std::fs::metadata(EMAIL_HEADERS_LOCATION);
        assert!(result.is_ok());
        let result = std::fs::metadata(EMAIL_BODY_LOCATION);
        assert!(result.is_ok());
        let link = format!(
            "href=\"https://www.{}/user/verify/",
            test_setup.app_env.domain
        );
        assert!(std::fs::read_to_string(EMAIL_BODY_LOCATION)
            .unwrap()
            .contains(&link));

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );
        // invite count is now 0, and ModelInvite::valid returns false
        assert_eq!(
            ModelInvite::get_all(&test_setup.postgres).await.unwrap()[0].count,
            0
        );
        assert!(!ModelInvite::valid(&test_setup.postgres, &invite)
            .await
            .unwrap());

        test_setup.flush_redis().await;

        // Invite now no longer works
        let body = TestSetup::gen_register_body(
            ANON_FULL_NAME,
            ANON_PASSWORD,
            &invite,
            ANON_EMAIL,
            true,
            true,
        );
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "invite invalid"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_register_then_verify_ok() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/register", api_base_url(&test_setup.app_env));

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        client.post(&url).json(&body).send().await.unwrap();
        let secret = get_keys(&test_setup.redis, "verify::secret::*").await;
        let secret = secret[0].replace("verify::secret::", "");

        let secret_as_ulid = Ulid::from_string(&secret);

        assert!(secret_as_ulid.is_ok());

        let url = format!(
            "{}/incognito/verify/{}",
            api_base_url(&test_setup.app_env),
            secret
        );

        let result = reqwest::get(url).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Account verified, please sign in to continue"
        );

        let result = RedisNewUser::get(&test_setup.redis, &secret_as_ulid.unwrap()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        let result = RedisNewUser::exists(&test_setup.redis, TEST_EMAIL).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // ****************
    // * Verify Route *
    // ****************

    #[tokio::test]
    async fn api_router_incognito_verify_invalid() {
        let test_setup = start_servers().await;

        let secret = gen_random_hex(128);

        let url = format!(
            "{}/incognito/verify/{}",
            api_base_url(&test_setup.app_env),
            secret
        );

        let result = reqwest::get(url).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );

        let secret = gen_random_hex(164);

        let url = format!(
            "{}/incognito/verify/{}",
            api_base_url(&test_setup.app_env),
            secret
        );

        let result = reqwest::get(url).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );
    }

    // ************************
    // * Reset Password route *
    // ************************

    #[tokio::test]
    async fn api_router_incognito_reset_post_unknown_user() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));

        let body = HashMap::from([("email", TEST_EMAIL)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );
        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );
        // check email NOT sent - well written to disk
        let result = std::fs::metadata(EMAIL_HEADERS_LOCATION);
        assert!(result.is_err());
        let result = std::fs::metadata(EMAIL_BODY_LOCATION);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn api_router_incognito_reset_post_known_user() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;

        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));

        let body = HashMap::from([("email", TEST_EMAIL)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );

        // Check postgres_secret is in email
        let password_reset =
            ModelPasswordReset::get_by_email(&test_setup.postgres, TEST_EMAIL).await;

        assert!(password_reset.is_ok());
        let password_reset = password_reset.unwrap();

        assert!(password_reset.is_some());
        let password_reset = password_reset.unwrap();

        // check email has been sent - well written to disk, and contain secret & correct subject
        let result = std::fs::read_to_string(EMAIL_HEADERS_LOCATION);
        assert!(result.is_ok());
        assert!(result
            .unwrap()
            .contains("Subject: Password Reset Requested"));

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            1
        );

        let result = std::fs::read_to_string(EMAIL_BODY_LOCATION);
        assert!(result.is_ok());
        assert!(result.unwrap().contains(&password_reset.reset_string));
    }

    #[tokio::test]
    async fn api_router_incognito_reset_post_known_user_second_attempt() {
        // setup
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);

        // test
        let result = client.post(&url).json(&body).send().await;

        // validate
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );
        let first_password_reset =
            ModelPasswordReset::get_by_email(&test_setup.postgres, TEST_EMAIL)
                .await
                .unwrap();
        test_setup.delete_email_log().await;
        TestSetup::delete_emails();

        // Second second request, no emails should be sent, and password_reset should match new password_reset
        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Instructions have been sent to the email address provided"
        );

        let second_password_reset =
            ModelPasswordReset::get_by_email(&test_setup.postgres, TEST_EMAIL)
                .await
                .unwrap();

        assert_eq!(first_password_reset, second_password_reset);

        assert_eq!(
            ModelEmailLog::get_count_total(&test_setup.postgres)
                .await
                .unwrap()
                .count,
            0
        );

        let result = std::fs::metadata(EMAIL_HEADERS_LOCATION);
        assert!(result.is_err());
        let result = std::fs::metadata(EMAIL_BODY_LOCATION);
        assert!(result.is_err());
    }

    #[tokio::test]
    /// If authenticated, unable to access reset_post endpoint
    async fn api_router_incognito_reset_post_already_authenticated() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let authed_cookie = test_setup.authed_user_cookie().await;

        let body = TestSetup::gen_register_body(
            TEST_FULL_NAME,
            TEST_PASSWORD,
            &test_setup.app_env.invite,
            TEST_EMAIL,
            true,
            true,
        );
        let result = client
            .post(&url)
            .json(&body)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            "Invalid Authentication",
            result.json::<Response>().await.unwrap().response
        );
    }

    #[tokio::test]
    /// If authenticated, unable to access reset_get endpoint
    async fn api_router_incognito_reset_get_already_authenticated() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let authed_cookie = test_setup.authed_user_cookie().await;
        let result = client
            .get(&url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            "Invalid Authentication",
            result.json::<Response>().await.unwrap().response
        );
    }

    #[tokio::test]
    async fn api_router_incognito_reset_get_invalid_hex() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);

        client.post(&url).json(&body).send().await.unwrap();
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            gen_random_hex(25)
        );

        // Test
        let result = reqwest::get(url).await;

        // Validate
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_reset_get_unknown_reset_secret() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);

        client.post(&url).json(&body).send().await.unwrap();
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            gen_random_hex(128)
        );

        // Test
        let result = reqwest::get(url).await;

        // Validate
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );
    }

    #[tokio::test]
    async fn api_router_incognito_reset_get_valid() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);

        client.post(&url).json(&body).send().await.unwrap();

        let secret = ModelPasswordReset::get_by_email(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .unwrap()
            .reset_string;
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            secret
        );

        // Test
        let result = reqwest::get(url).await;

        // Validate
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result["two_fa_active"], false);
        assert_eq!(result["two_fa_backup"], false);
    }

    #[tokio::test]
    async fn api_router_incognito_reset_get_valid_with_two_fa() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.insert_two_fa().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);

        client.post(&url).json(&body).send().await.unwrap();

        let secret = ModelPasswordReset::get_by_email(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .unwrap()
            .reset_string;
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            secret
        );

        // Test
        let result = reqwest::get(url).await;

        // Validate
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result["two_fa_active"], true);
        assert_eq!(result["two_fa_backup"], false);
    }

    #[tokio::test]
    /// Secret param incorrect
    async fn api_router_incognito_reset_patch_invalid_secret() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.request_reset().await;

        let client = TestSetup::get_client();

        // Wrong secret
        let bad_secret = gen_random_hex(128);
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            bad_secret
        );

        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );

        // short secret
        let bad_secret = gen_random_hex(100);
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            bad_secret
        );

        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );

        // long secret
        let bad_secret = gen_random_hex(200);
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            bad_secret
        );
        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );
    }

    #[tokio::test]
    /// If authenticated, unable to access reset_patch endpoint
    async fn api_router_incognito_reset_patch_already_authenticated() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let authed_cookie = test_setup.authed_user_cookie().await;

        let result = client
            .patch(&url)
            .body("body")
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            "Invalid Authentication",
            result.json::<Response>().await.unwrap().response
        );
    }

    #[tokio::test]
    /// Invalid body
    async fn api_router_incognito_reset_patch_invalid_body() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let reset_secret = test_setup.request_reset().await;
        let client = TestSetup::get_client();

        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );

        // No password in body
        let body: HashMap<String, String> = HashMap::new();
        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "missing password"
        );

        // random entry in body
        let body = HashMap::from([("password", TEST_PASSWORD), ("not_token", "012234")]);
        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "invalid input"
        );

        // invalid token format
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", "8102569")]);
        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(result.json::<Response>().await.unwrap().response, "token");
    }

    #[tokio::test]
    // invalid token
    async fn api_router_incognito_reset_patch_invalid_token() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.insert_two_fa().await;
        let reset_secret = test_setup.request_reset().await;
        let client = TestSetup::get_client();
        let valid_token = test_setup.get_invalid_token();

        // invalid token format
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );

        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &valid_token)]);
        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Invalid email address and/or password and/or token"
        );
    }

    #[tokio::test]
    /// Invalid password provided
    async fn api_router_incognito_reset_patch_invalid_password() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let reset_secret = test_setup.request_reset().await;
        let client = TestSetup::get_client();

        // password in hibp
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );
        let body = HashMap::from([("password", UNSAFE_PASSWORD)]);
        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "unsafe password"
        );

        // user's email address in password
        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );

        let body = HashMap::from([(
            "password",
            format!("abcd{}123456", TEST_EMAIL.to_uppercase()),
        )]);

        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "unsafe password"
        );
    }

    #[tokio::test]
    /// Patch ok
    async fn api_router_incognito_reset_patch_ok() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let reset_secret = test_setup.request_reset().await;
        let client = TestSetup::get_client();

        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );

        let body = HashMap::from([("password", gen_random_hex(24))]);

        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Password reset complete - please sign in"
        );

        let post_hash = test_setup.query_password_hash().await;
        assert_ne!(TEST_PASSWORD_HASH, post_hash);
    }

    #[tokio::test]
    /// On valid password reset, all current sessions (and session set) are removed
    async fn api_router_incognito_reset_patch_ok_sessions_removed() {
        let mut test_setup = start_servers().await;
        test_setup.authed_user_cookie().await;
        let reset_secret = test_setup.request_reset().await;
        let client = TestSetup::get_client();

        let keys = get_keys(&test_setup.redis, "session::*").await;
        assert_eq!(keys.len(), 1);
        let keys = get_keys(&test_setup.redis, "session_set::user::*").await;
        assert_eq!(keys.len(), 1);

        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );

        let body = HashMap::from([("password", gen_random_hex(24))]);

        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let keys = get_keys(&test_setup.redis, "session_set::user::*").await;
        assert_eq!(keys.len(), 0);
        let keys = get_keys(&test_setup.redis, "session::*").await;
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn api_router_incognito_reset_patch_ok_with_token() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        test_setup.insert_two_fa().await;
        let reset_secret = test_setup.request_reset().await;
        let client = TestSetup::get_client();
        let valid_token = test_setup.get_valid_token();

        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );
        let body = HashMap::from([("password", gen_random_hex(24)), ("token", valid_token)]);

        let result = client.patch(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Password reset complete - please sign in"
        );

        let post_hash = test_setup.query_password_hash().await;
        assert_ne!(TEST_PASSWORD_HASH, post_hash);
    }

    #[tokio::test]
    /// Password reset consumed, unable to be used again
    async fn api_router_incognito_reset_patch_secret_consumed() {
        let mut test_setup = start_servers().await;
        test_setup.insert_test_user().await;
        let reset_secret = test_setup.request_reset().await;
        let client = TestSetup::get_client();

        let url = format!(
            "{}/incognito/reset/{}",
            api_base_url(&test_setup.app_env),
            reset_secret
        );
        let body = HashMap::from([("password", gen_random_hex(24))]);
        client.patch(&url).json(&body).send().await.unwrap();

        let result = client.patch(&url).json(&body).send().await.unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Incorrect verification data"
        );
    }

    // *******************
    // * Contact Message *
    // *******************

    #[tokio::test]
    /// Message too short, email address, nor message, in database
    async fn api_router_incognito_contact_post_message_short() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}{}",
            api_base_url(&test_setup.app_env),
            IncognitoRoutes::Contact.addr()
        );

        let message = (0..63).map(|_| "a".to_owned()).collect::<String>();

        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(result.json::<Response>().await.unwrap().response, "message");

        let messages = ModelContactMessage::get_all(&test_setup.postgres)
            .await
            .unwrap();
        assert!(messages.is_empty());
        assert!(ModelEmailAddress::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    /// Message too long, email address, nor message, in database
    async fn api_router_incognito_contact_post_message_long() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}{}",
            api_base_url(&test_setup.app_env),
            IncognitoRoutes::Contact.addr()
        );

        let message = (0..=1024).map(|_| "a".to_owned()).collect::<String>();

        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(result.json::<Response>().await.unwrap().response, "message");

        let messages = ModelContactMessage::get_all(&test_setup.postgres)
            .await
            .unwrap();
        assert!(messages.is_empty());
        assert!(ModelEmailAddress::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    /// Non authed user, message in database, rate limits in place for email and ip address
    async fn api_router_incognito_contact_post_non_authed_ok() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}{}",
            api_base_url(&test_setup.app_env),
            IncognitoRoutes::Contact.addr()
        );

        let message = gen_random_hex(80);

        let req = TestSetup::gen_req();

        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let messages = ModelContactMessage::get_all(&test_setup.postgres)
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);

        assert!(messages[0].registered_user_id.is_none());
        assert_eq!(messages[0].email, TEST_EMAIL);
        assert_eq!(messages[0].user_agent, req.user_agent);
        assert_eq!(messages[0].message, message);
        assert_eq!(messages[0].ip.to_string(), "127.0.0.1");
        assert!(ModelEmailAddress::get(&test_setup.postgres, TEST_EMAIL)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    /// Authed user, message in database, rate limits in place for email and ip address, registered_user_id also logged
    async fn api_router_incognito_contact_post_authed_ok() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}{}",
            api_base_url(&test_setup.app_env),
            IncognitoRoutes::Contact.addr()
        );

        let message = gen_random_hex(80);

        let req = TestSetup::gen_req();

        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);

        let result = client
            .post(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let messages = ModelContactMessage::get_all(&test_setup.postgres)
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);

        assert_eq!(
            messages[0].registered_user_id,
            Some(test_setup.get_user_id())
        );
        assert_eq!(messages[0].email, TEST_EMAIL);
        assert_eq!(messages[0].user_agent, req.user_agent);
        assert_eq!(messages[0].message, message);
        assert_eq!(messages[0].ip.to_string(), "127.0.0.1");
    }

    #[tokio::test]
    /// rate limit in place after successful message post
    async fn api_router_incognito_contact_post_ratelimit_ok() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}{}",
            api_base_url(&test_setup.app_env),
            IncognitoRoutes::Contact.addr()
        );

        let message = gen_random_hex(80);

        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let contact_ip = "ratelimit::contact_ip::127.0.0.1";
        let contact_email = format!("ratelimit::contact_email::{TEST_EMAIL}");

        assert_eq!(
            test_setup
                .redis
                .get::<usize, &str>(contact_ip)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            test_setup
                .redis
                .ttl::<isize, &str>(contact_ip)
                .await
                .unwrap(),
            60
        );

        assert_eq!(
            test_setup
                .redis
                .get::<usize, &str>(&contact_email)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            test_setup
                .redis
                .ttl::<isize, &str>(&contact_email)
                .await
                .unwrap(),
            60
        );
    }

    #[tokio::test]
    /// rate limit in place after successful message post
    async fn api_router_incognito_contact_post_ratelimit_small() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}{}",
            api_base_url(&test_setup.app_env),
            IncognitoRoutes::Contact.addr()
        );

        let message = gen_random_hex(80);
        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);
        for _ in 0..=1 {
            let result = client.post(&url).json(&body).send().await;
            assert!(result.is_ok());
            let result = result.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }

        let message = gen_random_hex(80);

        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);

        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "rate limited for 60 seconds"
        );

        let contact_ip = "ratelimit::contact_ip::127.0.0.1";
        let contact_email = format!("ratelimit::contact_email::{TEST_EMAIL}");

        assert_eq!(
            test_setup
                .redis
                .get::<usize, &str>(contact_ip)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            test_setup
                .redis
                .ttl::<isize, &str>(contact_ip)
                .await
                .unwrap(),
            60
        );

        assert_eq!(
            test_setup
                .redis
                .get::<usize, &str>(&contact_email)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            test_setup
                .redis
                .ttl::<isize, &str>(&contact_email)
                .await
                .unwrap(),
            60
        );
    }

    #[tokio::test]
    /// Big rate limit in place after 8 messages sent
    async fn api_router_incognito_contact_post_ratelimit_big() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let url = format!(
            "{}{}",
            api_base_url(&test_setup.app_env),
            IncognitoRoutes::Contact.addr()
        );

        let message = gen_random_hex(80);
        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);
        for _ in 0..=7 {
            let result = client.post(&url).json(&body).send().await;
            assert!(result.is_ok());
        }

        let message = gen_random_hex(80);

        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message)]);

        let result = client.post(&url).json(&body).send().await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);

        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "rate limited for 21600 seconds"
        );

        let contact_ip = "ratelimit::contact_ip::127.0.0.1";
        let contact_email = format!("ratelimit::contact_email::{TEST_EMAIL}");

        assert_eq!(
            test_setup
                .redis
                .get::<usize, &str>(contact_ip)
                .await
                .unwrap(),
            9
        );
        assert_eq!(
            test_setup
                .redis
                .ttl::<isize, &str>(contact_ip)
                .await
                .unwrap(),
            21600
        );

        assert_eq!(
            test_setup
                .redis
                .get::<usize, &str>(&contact_email)
                .await
                .unwrap(),
            9
        );
        assert_eq!(
            test_setup
                .redis
                .ttl::<isize, &str>(&contact_email)
                .await
                .unwrap(),
            21600
        );
    }
}

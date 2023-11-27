use axum::{
    extract::State,
    middleware,
    routing::{delete, get, patch},
    Router, http::StatusCode,
};
use axum_extra::extract::PrivateCookieJar;
use redis::AsyncCommands;
use std::time::SystemTime;
use tracing::error;
use ulid::Ulid;

use crate::{
    api_error::ApiError,
    database::{
        admin::{AdminDevice, AdminModelUser, AdminUserAndSession},
        contact_message::ModelContactMessage,
        device::ModelDevice,
        email_log::ModelEmailLog,
        invite::ModelInvite,
        ip_user_agent::ModelUserAgentIp,
        login::ModelLogin,
        message_cache::MessageCache,
        rate_limit::RateLimit,
        session::RedisSession,
        user::ModelUser,
    },
    define_routes,
    helpers::calc_uptime,
    servers::{api::authentication, ApiRouter, ApplicationState, StatusOJ},
    user_io::{
        incoming_json::ij,
        outgoing_json::oj::{self, AdminEmailsCounts},
    },
};

struct SysInfo {
    virt: usize,
    rss: usize,
    uptime: u64,
    uptime_app: u64,
}

impl SysInfo {
    async fn new(start_time: SystemTime) -> Self {
        // When running in docker, pid should always be 1
        let pid = std::process::id();
        let memory = tokio::fs::read_to_string(format!("/proc/{pid}/statm"))
            .await
            .unwrap_or_default()
            .split(' ')
            .take(2)
            .map(|i| i.parse::<usize>().unwrap_or_default() * 4096)
            .collect::<Vec<_>>();

        let uptime = tokio::fs::read_to_string("/proc/uptime")
            .await
            .unwrap_or_default()
            .split('.')
            .take(1)
            .collect::<String>()
            .parse::<u64>()
            .unwrap_or_default();

        Self {
            virt: *memory.first().unwrap_or(&0),
            rss: *memory.get(1).unwrap_or(&0),
            uptime,
            uptime_app: calc_uptime(start_time),
        }
    }
}

define_routes! {
    AdminRoutes,
    "/admin",
    AllUsers => "/users",
    Base => "",
    Connection => "/connection",
    Contact => "/contact",
    Emails => "/emails",
    Invite => "/invite",
    Limit => "/limit",
    Memory => "/memory",
    Session => "/session/:session",
    UserEmail => "/user/:email",
    UserEmailActive => "/user/:email/active",
    UserEmailAttempt => "/user/:email/attempt",
    UserEmailDevice => "/user/:email/device/:device_name",
    UserEmailDevices => "/user/:email/devices"
}

pub struct AdminRouter;

impl ApiRouter for AdminRouter {
    fn create_router(state: &ApplicationState) -> Router<ApplicationState> {
        Router::new()
            .route(&AdminRoutes::Base.addr(), get(Self::base_get))
            .route(&AdminRoutes::Memory.addr(), get(Self::memory_get))
            .route(
                &AdminRoutes::Connection.addr(),
                delete(Self::connection_remove).get(Self::connections_get),
            )
            .route(&AdminRoutes::Emails.addr(), get(Self::emails_get))
            .route(
                &AdminRoutes::Limit.addr(),
                delete(Self::limit_delete).get(Self::limit_get),
            )
            .route(
                &AdminRoutes::Contact.addr(),
                delete(Self::contact_delete).get(Self::contact_get),
            )
            .route(
                &AdminRoutes::UserEmailDevices.addr(),
                get(Self::user_connections_get),
            )
            .route(
                &AdminRoutes::UserEmailActive.addr(),
                patch(Self::active_patch),
            )
            .route(
                &AdminRoutes::UserEmailAttempt.addr(),
                delete(Self::attempt_delete),
            )
            .route(
                &AdminRoutes::UserEmailDevice.addr(),
                delete(Self::device_delete).patch(Self::device_pause),
            )
            .route(
                &AdminRoutes::Invite.addr(),
                delete(Self::invite_delete)
                    .get(Self::invite_get)
                    .post(Self::invite_post),
            )
            .route(&AdminRoutes::UserEmail.addr(), delete(Self::user_delete))
            .route(&AdminRoutes::Session.addr(), delete(Self::session_delete))
            .route(&AdminRoutes::AllUsers.addr(), get(Self::users_get))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                authentication::is_admin_authenticated,
            ))
    }
}

impl AdminRouter {
    /// Return a user object
    #[allow(clippy::unused_async)]
    async fn base_get() -> StatusCode {
        StatusCode::OK
    }

    /// Remove a given rate limit, based on key name
    async fn limit_delete(
        State(state): State<ApplicationState>,
        ij::IncomingJson(body): ij::IncomingJson<ij::Limit>,
    ) -> Result<StatusCode, ApiError> {
        state.redis.lock().await.del(body.key.to_string()).await?;
        Ok(StatusCode::OK)
    }

    /// Get all rate limits, are either ip or user_id based
    async fn limit_get(
        State(state): State<ApplicationState>,
        user: ModelUser,
    ) -> Result<StatusOJ<Vec<oj::AdminLimit>>, ApiError> {
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(RateLimit::get_all(&state.redis, &user).await?),
        ))
    }

    /// Remove a given rate limit, based on key name
    async fn contact_delete(
        State(state): State<ApplicationState>,
        ij::IncomingJson(body): ij::IncomingJson<ij::AdminContactMessage>,
    ) -> Result<StatusCode, ApiError> {
        ModelContactMessage::delete(&state.postgres, body.contact_message_id).await?;
        Ok(StatusCode::OK)
    }

    /// Get all rate limits, are either ip or user_id based
    async fn contact_get(
        State(state): State<ApplicationState>,
    ) -> Result<StatusOJ<Vec<ModelContactMessage>>, ApiError> {
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(ModelContactMessage::get_all(&state.postgres).await?),
        ))
    }

    /// Get server info, uptime, app uptime, virt mem, and rss memory
    #[allow(clippy::unused_async)]
    async fn memory_get(
        State(state): State<ApplicationState>,
    ) -> Result<StatusOJ<oj::AdminMemory>, ApiError> {
        let sysinfo = SysInfo::new(state.start_time).await;
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(oj::AdminMemory {
                uptime: sysinfo.uptime,
                uptime_app: sysinfo.uptime_app,
                virt: sysinfo.virt,
                rss: sysinfo.rss,
            }),
        ))
    }

    /// Get information on all users
    async fn users_get(
        State(state): State<ApplicationState>,
    ) -> Result<StatusOJ<Vec<AdminUserAndSession>>, ApiError> {
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(AdminModelUser::get_all(&state.postgres, &state.redis).await?),
        ))
    }

    /// Delete a given user session, will not allow to delete self session
    async fn session_delete(
        State(state): State<ApplicationState>,
        jar: PrivateCookieJar,
        ij::Path(ij::UserSession { session }): ij::Path<ij::UserSession>,
    ) -> Result<StatusCode, ApiError> {
        if let Some(data) = jar.get(&state.cookie_name) {
            if let Ok(ulid) = Ulid::from_string(data.value()) {
                if session == ulid {
                    return Err(ApiError::InvalidValue(String::from(
                        "Can't delete current session",
                    )));
                }
            }
            RedisSession::delete(&state.redis, &session).await?;
        } else {
            error!("Unable to parse session_delete user session");
        }
        Ok(StatusCode::OK)
    }

    /// Delete a given users login attempts
    async fn attempt_delete(
        State(state): State<ApplicationState>,
        ij::Path(ij::Reset { email }): ij::Path<ij::Reset>,
    ) -> Result<StatusCode, ApiError> {
        ModelLogin::admin_delete_attempt(&state.postgres, email).await?;
        Ok(StatusCode::OK)
    }

    /// Toggle a users active status
    /// If setting active to false, also delete all sessions
    /// TODO require password token
    async fn active_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        ij::Path(ij::Reset { email }): ij::Path<ij::Reset>,
    ) -> Result<StatusCode, ApiError> {
        if let Some(model_user) = ModelUser::admin_get(&state.postgres, &email).await? {
            if model_user.registered_user_id == user.registered_user_id {
                Err(ApiError::InvalidValue("Can't de-activate self".to_owned()))
            } else {
                if model_user.active {
                    RedisSession::delete_all(&state.redis, model_user.registered_user_id).await?;
                }
                model_user.admin_toggle_active(&state.postgres).await?;
                Ok(StatusCode::OK)
            }
        } else {
            Err(ApiError::InvalidValue(String::from("unknown user")))
        }
    }

    async fn invite_get(
        State(state): State<ApplicationState>,
    ) -> Result<StatusOJ<Vec<ModelInvite>>, ApiError> {
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(ModelInvite::get_all(&state.postgres).await?),
        ))
    }

    async fn invite_delete(
        State(state): State<ApplicationState>,
        ij::IncomingJson(body): ij::IncomingJson<ij::AdminInvitePatch>,
    ) -> Result<StatusCode, ApiError> {
        ModelInvite::delete(&state.postgres, body.invite).await?;
        Ok(StatusCode::OK)
    }

    async fn invite_post(
        State(state): State<ApplicationState>,
        user: ModelUser,
        req: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::AdminInvite>,
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
        ModelInvite::insert(&state.postgres, req, body.count, &user, &body.invite).await?;
        Ok(StatusCode::OK)
    }

    /// Delete a device, by setting it to non-active
    async fn device_delete(
        State(state): State<ApplicationState>,
        user: ModelUser,
        ij::Path(ij::AdminDevice { email, device_name }): ij::Path<ij::AdminDevice>,
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
        if let Some(model_user) = ModelUser::admin_get(&state.postgres, &email).await? {
            if let Some(device_id) =
                ModelDevice::delete_by_name(&state.postgres, &model_user, &device_name).await?
            {
                state
                    .connections
                    .lock()
                    .await
                    .close_by_single_device_id(device_id)
                    .await;

                MessageCache::delete(&state.redis, device_id).await?;
            }
            Ok(StatusCode::OK)
        } else {
            Err(ApiError::InvalidValue(String::from("unknown user")))
        }
    }

    /// Pause a device, by setting it to non-active
    async fn device_pause(
        State(state): State<ApplicationState>,
        user: ModelUser,
        ij::Path(ij::AdminDevice { email, device_name }): ij::Path<ij::AdminDevice>,
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
        if let Some(model_user) = ModelUser::admin_get(&state.postgres, &email).await? {
            if let Some(mut device) =
                ModelDevice::get_by_name(&state.postgres, &model_user, &device_name).await?
            {
                state
                    .connections
                    .lock()
                    .await
                    .close_by_single_device_id(device.device_id)
                    .await;
                device
                    .update_paused(&state.postgres, !device.paused)
                    .await?;
                Ok(StatusCode::OK)
            } else {
                Err(ApiError::InvalidValue(String::from("unknown device")))
            }
        } else {
            Err(ApiError::InvalidValue(String::from("unknown user")))
        }
    }

    /// Get device, and the connection info of each device, for a given user
    async fn user_delete(
        State(state): State<ApplicationState>,
        admin_user: ModelUser,
        ij::Path(ij::Reset { email }): ij::Path<ij::Reset>,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusCode, ApiError> {
        if !authentication::check_password_op_token(
            &admin_user,
            &body.password,
            body.token,
            &state.postgres,
        )
        .await?
        {
            return Err(ApiError::Authorization);
        }
        if let Some(model_user) = ModelUser::admin_get(&state.postgres, &email).await? {
            if model_user == admin_user {
                return Err(ApiError::InvalidValue(String::from(
                    "Admin users can't delete their own accounts",
                )));
            }
            model_user.delete(&state.postgres, &state.redis).await?;
            Ok(StatusCode::OK)
        } else {
            Err(ApiError::InvalidValue(String::from("unknown user")))
        }
    }

    /// Get device, and the connection info of each device, for a given user
    async fn user_connections_get(
        State(state): State<ApplicationState>,
        user: ModelUser,
        ij::Path(ij::Reset { email }): ij::Path<ij::Reset>,
    ) -> Result<StatusOJ<Vec<AdminDevice>>, ApiError> {
        if let Some(model_user) = ModelUser::admin_get(&state.postgres, &email).await? {
            let devices = ModelDevice::get_all(&state.postgres, &model_user).await?;
            let mut output = vec![];
            for i in devices {
                let connections = state
                    .connections
                    .lock()
                    .await
                    .get_admin_info_device(&user, i.device_id)?;

                output.push(AdminDevice {
                    connections,
                    device: i,
                });
            }
            Ok((StatusCode::OK, oj::OutgoingJson::new(output)))
        } else {
            Err(ApiError::InvalidValue(String::from("unknown user")))
        }
    }

    /// remove a connection
    async fn connection_remove(
        State(state): State<ApplicationState>,
        ij::IncomingJson(body): ij::IncomingJson<ij::AdminConnectionRemove>,
    ) -> Result<StatusCode, ApiError> {
        state
            .connections
            .lock()
            .await
            .close(body.device_id, body.connection_ulid, body.device_type)
            .await;
        Ok(StatusCode::OK)
    }

    /// Get counts of emails sent
    async fn connections_get(
        State(state): State<ApplicationState>,
        user: ModelUser,
    ) -> Result<StatusOJ<oj::AdminConnectionCounts>, ApiError> {
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(state.connections.lock().await.get_admin_info(&user)?),
        ))
    }

    /// Get the email sent counts
    async fn emails_get(
        State(state): State<ApplicationState>,
    ) -> Result<StatusOJ<oj::AdminEmailsCounts>, ApiError> {
        let (hour, total) = tokio::try_join!(
            ModelEmailLog::get_count_hour(&state.postgres),
            ModelEmailLog::get_count_total(&state.postgres)
        )?;
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(AdminEmailsCounts {
                hour: hour.count,
                total: total.count,
            }),
        ))
    }
}

/// Use reqwest to test against real server
// cargo watch -q -c -w src/ -x 'test admin_router -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {

    use super::AdminRoutes;
    use crate::connections::ConnectionType;
    use crate::database::user_level::UserLevel;
    use crate::helpers::gen_random_hex;
    use crate::servers::test_setup::{
        api_base_url, start_servers, Response, TestSetup, ANON_EMAIL, ANON_FULL_NAME, TEST_EMAIL,
        TEST_FULL_NAME, TEST_PASSWORD, TEST_USER_AGENT,
    };
    use crate::sleep;
    use crate::user_io::incoming_json::ij::{AdminInvite, DevicePost};

    use futures::{SinkExt, StreamExt};
    use redis::AsyncCommands;
    use reqwest::{Client, StatusCode, Url};
    use std::collections::HashMap;
    use time::OffsetDateTime;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;
    use ulid::Ulid;

    /// Send a request to /authenticated/user route to test that the user logged in
    async fn test_is_authenticated(test_setup: &TestSetup, client: &Client, cookie: &str) {
        let user_url = format!("{}/authenticated/user", api_base_url(&test_setup.app_env));
        let result = client
            .get(&user_url)
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
    }

    /// Send a request to /authenticated/user route to test that the user is not logged in
    async fn test_is_not_authenticated(test_setup: &TestSetup, client: &Client, cookie: &str) {
        let user_url = format!("{}/authenticated/user", api_base_url(&test_setup.app_env));
        let result = client
            .get(&user_url)
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    //***************
    // * Base Route *
    // **************

    #[tokio::test]
    // Unauthenticated user unable to access [GET] /admin route
    async fn admin_router_user_get_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!("{}/authenticated/admin", api_base_url(&test_setup.app_env));

        let client = TestSetup::get_client();

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [ GET ] /admin route
    async fn admin_router_user_get_user_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!("{}/authenticated/admin", api_base_url(&test_setup.app_env));

        let client = TestSetup::get_client();
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        test_setup.change_anon_user_level(UserLevel::Pro).await;
        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

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
    /// Admin user return 200 with empty body
    async fn admin_router_user_get_user_admin_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        let url = format!("{}/authenticated/admin", api_base_url(&test_setup.app_env));

        let client = TestSetup::get_client();

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.text().await.unwrap();
        assert!(result.is_empty())
    }

    // ****************
    // * Memory Route *
    // ****************

    #[tokio::test]
    // Unauthenticated user unable to [GET] "/memory" route
    async fn admin_router_memory_get_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Memory.addr()
        );

        let client = TestSetup::get_client();

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [GET] /memory route
    async fn admin_router_memory_get_memory_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Memory.addr()
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

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
    /// Admin user able to get memory details
    async fn admin_router_memory_get_user_admin_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Memory.addr()
        );

        let client = TestSetup::get_client();
        sleep!(1000);

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let result = result.json::<Response>().await.unwrap().response;

        assert!(result["rss"].is_number());
        assert!(result["virt"].is_number());
        assert!(result["uptime_app"].is_number());
        assert!(result["uptime"].is_number());

        // Assume the app has been alive for 1..10 seconds, in reality should be 1 or 2
        assert!((1..=10).contains(&result["uptime_app"].as_u64().unwrap()));
        // Assume the comptuer has been on for longer than 15 seconds
        assert!(result["uptime"].as_u64().unwrap() > 15);

        assert!(result["virt"].as_u64().unwrap() > result["rss"].as_u64().unwrap());
    }

    // ***************
    // * Limit Route *
    // ***************

    #[tokio::test]
    // Unauthenticated user unable to [DELETE, GET] "/limit" route
    async fn admin_router_limit_get_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Limit.addr()
        );

        let client = TestSetup::get_client();

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [DELETE, GET] /limit route
    async fn admin_router_limit_get_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Limit.addr()
        );

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Limit.addr()
        );

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

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
    /// Admin user able to get all current rate limit values
    async fn admin_router_limit_get_user_admin_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Limit.addr()
        );

        test_setup.insert_device(&authed_cookie, None).await;
        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());
        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let msg_text = "some_text";
        let msg = Message::from(msg_text);
        ws_pi.unwrap().0.send(msg).await.unwrap();
        let ws_base_url = format!("ws://127.0.0.1:{}", test_setup.app_env.ws_port);

        let _ratelimit_key = "ratelimit::ip::127.0.0.1";
        let ws_url = Url::parse(&format!("{ws_base_url}/online")).unwrap();
        for _ in 1..=181 {
            connect_async(&ws_url).await.ok();
        }

        let client = TestSetup::get_client();
        sleep!(1000);

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_array());
        let result = result.as_array().unwrap();

        let api_index = result.iter().position(|i| {
            i.as_object()
                .unwrap()
                .get("key")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("ratelimit::api_key")
        });
        assert!(api_index.is_some());
        let api_index = api_index.unwrap();
        assert_eq!(
            result
                .get(api_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("points")
                .unwrap()
                .as_i64()
                .unwrap(),
            2
        );
        assert_eq!(
            result
                .get(api_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("max")
                .unwrap()
                .as_i64()
                .unwrap(),
            60
        );
        assert!((58..60).contains(
            &result
                .get(api_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("ttl")
                .unwrap()
                .as_i64()
                .unwrap()
        ));
        assert!(!result
            .get(api_index)
            .unwrap()
            .as_object()
            .unwrap()
            .get("blocked")
            .unwrap()
            .as_bool()
            .unwrap());

        let user_index = result.iter().position(|i| {
            i.as_object()
                .unwrap()
                .get("key")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("ratelimit::user")
        });
        assert!(user_index.is_some());
        let user_index = user_index.unwrap();
        assert_eq!(
            result
                .get(user_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("points")
                .unwrap()
                .as_i64()
                .unwrap(),
            2
        );

        assert_eq!(
            result
                .get(user_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("max")
                .unwrap()
                .as_i64()
                .unwrap(),
            150
        );

        // should be 58 or 59
        assert!((55..60).contains(
            &result
                .get(user_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("ttl")
                .unwrap()
                .as_i64()
                .unwrap()
        ));
        assert!(!result
            .get(user_index)
            .unwrap()
            .as_object()
            .unwrap()
            .get("blocked")
            .unwrap()
            .as_bool()
            .unwrap());

        let ws_pro_index = result.iter().position(|i| {
            i.as_object()
                .unwrap()
                .get("key")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("ratelimit::ws_pro")
        });
        assert!(ws_pro_index.is_some());
        let ws_pro_index = ws_pro_index.unwrap();
        assert_eq!(
            result
                .get(ws_pro_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("points")
                .unwrap()
                .as_i64()
                .unwrap(),
            1
        );

        assert_eq!(
            result
                .get(ws_pro_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("max")
                .unwrap()
                .as_i64()
                .unwrap(),
            300
        );
        assert!((58..60).contains(
            &result
                .get(ws_pro_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("ttl")
                .unwrap()
                .as_i64()
                .unwrap()
        ));
        assert!(!result
            .get(ws_pro_index)
            .unwrap()
            .as_object()
            .unwrap()
            .get("blocked")
            .unwrap()
            .as_bool()
            .unwrap());

        let ip_index = result.iter().position(|i| {
            i.as_object()
                .unwrap()
                .get("key")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("ratelimit::ip")
        });
        assert!(ip_index.is_some());
        let ip_index = ip_index.unwrap();
        assert_eq!(
            result
                .get(ip_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("points")
                .unwrap()
                .as_i64()
                .unwrap(),
            186
        );
        assert_eq!(
            result
                .get(ip_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("max")
                .unwrap()
                .as_i64()
                .unwrap(),
            45
        );
        assert_eq!(
            result
                .get(ip_index)
                .unwrap()
                .as_object()
                .unwrap()
                .get("ttl")
                .unwrap()
                .as_i64()
                .unwrap(),
            299
        );
        assert!(result
            .get(ip_index)
            .unwrap()
            .as_object()
            .unwrap()
            .get("blocked")
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[tokio::test]
    /// Admin user able to delete a selected rate limit values
    async fn admin_router_limit_delete_user_admin_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let _device_name = test_setup.insert_device(&authed_cookie, None).await;
        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());
        let msg_text = "some_text";
        let msg = Message::from(msg_text);
        ws_pi.unwrap().0.send(msg).await.unwrap();

        let client = TestSetup::get_client();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Limit.addr()
        );

        sleep!(1000);

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_array());
        let result = result.as_array().unwrap();

        let ws_pro_index = result.iter().position(|i| {
            i.as_object()
                .unwrap()
                .get("key")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("ratelimit::ws_pro")
        });
        assert!(ws_pro_index.is_some());
        let _key = result.get(ws_pro_index.unwrap());
        let ws_rate_limit_key = result
            .get(ws_pro_index.unwrap())
            .unwrap()
            .as_object()
            .unwrap()
            .get("key")
            .unwrap()
            .as_str()
            .unwrap();

        let exists_in_redis: bool = test_setup
            .redis
            .lock()
            .await
            .exists(ws_rate_limit_key)
            .await
            .unwrap();
        assert!(exists_in_redis);

        let body = HashMap::from([("key", ws_rate_limit_key)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        let result = result.as_array().unwrap();
        let ws_pro_index = result.iter().position(|i| {
            i.as_object()
                .unwrap()
                .get("key")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("ratelimit::ws_pro")
        });
        assert!(ws_pro_index.is_none());
        let exists_in_redis: bool = test_setup
            .redis
            .lock()
            .await
            .exists(ws_rate_limit_key)
            .await
            .unwrap();
        assert!(!exists_in_redis);
    }

    //**********************
    // * Connections route *
    // *********************

    #[tokio::test]
    // Unauthenticated user unable to access [DELETE, GET] /connections/count route
    async fn admin_router_user_get_connections_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Connection.addr()
        );

        let client = TestSetup::get_client();

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [ DELETE, GET ] /connections/count route
    async fn admin_router_user_get_connections_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Connection.addr()
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

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
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

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
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// get the count of number of connections, when 1 pi and 2 clients connected
    async fn admin_router_user_connections_user_admin_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 4,
                    client_password: None,
                    device_password: None,
                    structured_data: false,
                    name: None,
                }),
            )
            .await;
        let pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let pi_ws = connect_async(&pi_url).await;
        assert!(pi_ws.is_ok());

        let client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let client_ws = connect_async(&client_url).await;
        assert!(client_ws.is_ok());

        let client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let client_ws = connect_async(&client_url).await;
        assert!(client_ws.is_ok());

        let client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let client_ws = connect_async(&client_url).await;
        assert!(client_ws.is_ok());

        let client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let client_ws = connect_async(&client_url).await;
        assert!(client_ws.is_ok());

        let client = TestSetup::get_client();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Connection.addr()
        );

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;

        assert!(result.is_object());
        let result = result.as_object().unwrap();
        assert_eq!(result.get("pi").unwrap().as_i64().unwrap(), 1);
        assert_eq!(result.get("client").unwrap().as_i64().unwrap(), 4);
    }

    #[derive(serde::Serialize, Debug)]
    struct TmpBody {
        device_type: String,
        device_id: i64,
        connection_ulid: String,
    }

    /// Admin user able to disconnect a client connection
    #[tokio::test]
    async fn admin_router_connections_remove_client_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        test_setup.insert_device(&authed_cookie, None).await;

        let client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&client_url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let url = format!(
            "{}/authenticated/admin/user/{}/devices",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        let client_ulid = result.as_array().unwrap()[0]
            .get("connections")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()
            .get("ulid")
            .unwrap()
            .as_str()
            .unwrap();

        let pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&pi_url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Connection.addr()
        );

        let body = TmpBody {
            device_type: String::from("Client"),
            device_id: test_setup.query_user_active_devices().await[0]
                .device_id
                .get(),
            connection_ulid: client_ulid.to_owned(),
        };

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        assert!(ws_client.next().await.unwrap().unwrap().is_close());
        ws_pi.close(None).await.unwrap();
    }

    /// Admin user able to disconnect a client connection
    #[tokio::test]
    async fn admin_router_connections_remove_pi_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        test_setup.insert_device(&authed_cookie, None).await;

        let pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&pi_url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = format!(
            "{}/authenticated/admin/user/{}/devices",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        let pi_ulid = result.as_array().unwrap()[0]
            .get("connections")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_object()
            .unwrap()
            .get("ulid")
            .unwrap()
            .as_str()
            .unwrap();

        let client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&client_url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Connection.addr()
        );

        let body = TmpBody {
            device_type: String::from("Pi"),
            device_id: test_setup.query_user_active_devices().await[0]
                .device_id
                .get(),
            connection_ulid: pi_ulid.to_owned(),
        };

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);

        assert!(ws_pi.next().await.unwrap().unwrap().is_close());
        ws_client.close(None).await.unwrap();
    }

    // *******************
    // * All Users Route *
    // *******************

    #[tokio::test]
    // Unauthenticated user unable to [GET] "/users" route
    async fn admin_router_allusers_get_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::AllUsers.addr()
        );

        let client = TestSetup::get_client();

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [GET] /users route
    async fn admin_router_allusers_get_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::AllUsers.addr()
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

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
    /// Admin user able to get list of all users, and current sessions of each user
    async fn admin_router_allusers_get_ok() {
        let mut test_setup = start_servers().await;

        test_setup.insert_anon_user().await;
        // sign in test user, so that we can check that sessions work
        // and insert device, again to check that we can get this information back
        let anon_user_cookie = test_setup.anon_user_cookie().await;
        test_setup
            .insert_device(&anon_user_cookie.unwrap(), None)
            .await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::AllUsers.addr()
        );

        let client = TestSetup::get_client();

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let result = result.json::<Response>().await.unwrap().response;

        assert!(result.is_array());

        let result = result.as_array().unwrap();
        assert!(result.len() >= 2);

        let result = result
            .iter()
            .map(|i| i.as_object().unwrap())
            .collect::<Vec<_>>();

        let test_index = result.iter().position(|i| {
            i.get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("email")
                .unwrap()
                .as_str()
                .unwrap()
                == TEST_EMAIL
        });
        assert!(test_index.is_some());

        let anon_index = result.iter().position(|i| {
            i.get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("email")
                .unwrap()
                .as_str()
                .unwrap()
                == ANON_EMAIL
        });

        assert!(anon_index.is_some());

        let test_user = result.get(test_index.unwrap()).unwrap();

        assert!(test_user.get("sessions").unwrap().is_array());
        assert!(test_user.get("sessions").unwrap().as_array().unwrap()[0]
            .get("key")
            .unwrap()
            .is_string());
        assert!(test_user.get("sessions").unwrap().as_array().unwrap()[0]
            .get("timestamp")
            .unwrap()
            .is_number());
        assert!((21595..=21600).contains(
            &test_user.get("sessions").unwrap().as_array().unwrap()[0]
                .get("ttl")
                .unwrap()
                .as_i64()
                .unwrap()
        ));

        assert!(test_user.get("user").unwrap().is_object());
        assert!(!test_user
            .get("user")
            .unwrap()
            .as_object()
            .unwrap()
            .get("two_fa_enabled")
            .unwrap()
            .as_bool()
            .unwrap());
        assert_eq!(
            test_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("full_name")
                .unwrap()
                .as_str()
                .unwrap(),
            TEST_FULL_NAME
        );
        assert_eq!(
            test_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("user_level")
                .unwrap()
                .as_str()
                .unwrap(),
            "admin"
        );
        assert_eq!(
            test_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("device_count")
                .unwrap()
                .as_i64()
                .unwrap(),
            0
        );
        assert_eq!(
            test_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("registered_user_id")
                .unwrap()
                .as_i64()
                .unwrap(),
            test_setup.get_user_id().get()
        );

        let anon_user = result.get(anon_index.unwrap()).unwrap();
        assert!(anon_user.get("sessions").unwrap().is_array());
        assert!(anon_user.get("sessions").unwrap().as_array().unwrap()[0]
            .get("key")
            .unwrap()
            .is_string());
        assert!(anon_user.get("sessions").unwrap().as_array().unwrap()[0]
            .get("timestamp")
            .unwrap()
            .is_number());
        assert!((21595..=21600).contains(
            &anon_user.get("sessions").unwrap().as_array().unwrap()[0]
                .get("ttl")
                .unwrap()
                .as_i64()
                .unwrap(),
        ));

        assert!(anon_user.get("user").unwrap().is_object());
        assert!(anon_user
            .get("user")
            .unwrap()
            .as_object()
            .unwrap()
            .get("two_fa_enabled")
            .unwrap()
            .as_bool()
            .unwrap());
        assert_eq!(
            anon_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("full_name")
                .unwrap()
                .as_str()
                .unwrap(),
            ANON_FULL_NAME
        );
        assert_eq!(
            anon_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("user_level")
                .unwrap()
                .as_str()
                .unwrap(),
            "free"
        );
        assert_eq!(
            anon_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("device_count")
                .unwrap()
                .as_i64()
                .unwrap(),
            1
        );

        assert_eq!(
            anon_user
                .get("user")
                .unwrap()
                .as_object()
                .unwrap()
                .get("registered_user_id")
                .unwrap()
                .as_i64()
                .unwrap(),
            test_setup
                .get_anon_user()
                .await
                .unwrap()
                .registered_user_id
                .get()
        );
    }

    // ******************
    // * Sessions Route *
    // ******************

    /// Generate a random session key - very small chance that it could clash with the real sessions, but close to zero
    fn random_session() -> String {
        format!("session::{}", Ulid::new())
    }

    #[tokio::test]
    // Unauthenticated user unable to [DELETE] "/session/:session" route
    async fn admin_router_session_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated/admin/session/{}",
            api_base_url(&test_setup.app_env),
            random_session()
        );

        let client = TestSetup::get_client();

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [DELETE] /session/:session route
    async fn admin_router_sessions_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated/admin/session/{}",
            api_base_url(&test_setup.app_env),
            random_session()
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user delete random session, just returns 200 empty body
    async fn admin_router_sessions_admin_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        let url = format!(
            "{}/authenticated/admin/session/{}",
            api_base_url(&test_setup.app_env),
            random_session()
        );

        let client = TestSetup::get_client();

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.text().await.unwrap(), "");
    }

    #[tokio::test]
    /// Admin user unable to delete self session
    async fn admin_router_session_self_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let current_session = test_setup
            .get_session(test_setup.get_user_id())
            .await
            .unwrap();
        let url = format!(
            "{}/authenticated/admin/session/{}",
            api_base_url(&test_setup.app_env),
            current_session
        );
        let client = TestSetup::get_client();
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Can't delete current session");
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;
    }

    #[tokio::test]
    /// Admin user able to delete anon_sessions, and anon_session is now no longer valid
    async fn admin_router_session_anon_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        // sign in test user, so that we can check that sessions work
        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await.unwrap();

        let anon_id = test_setup.get_anon_user().await.unwrap().registered_user_id;
        let anon_session = test_setup.get_session(anon_id).await.unwrap();
        let url = format!(
            "{}/authenticated/admin/session/{}",
            api_base_url(&test_setup.app_env),
            anon_session
        );
        let client = TestSetup::get_client();
        test_is_authenticated(&test_setup, &client, &anon_user_cookie).await;

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.text().await.unwrap(), "");

        let session_set: bool = test_setup
            .redis
            .lock()
            .await
            .exists(format!("session_set::user::{}", anon_id.get()))
            .await
            .unwrap();
        let session: bool = test_setup
            .redis
            .lock()
            .await
            .exists(anon_session)
            .await
            .unwrap();
        assert!(!session_set);
        assert!(!session);

        // Anon user now unable to access the user route
        test_is_not_authenticated(&test_setup, &client, &anon_user_cookie).await
    }

    // ******************
    // * Attempts Route *
    // ******************

    #[tokio::test]
    // Unauthenticated user unable to [DELETE] "/user/:email/attempt" route
    async fn admin_router_attempt_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated/admin/user/{}/attempt",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [DELETE] "/user/:email/attempt" route
    async fn admin_router_attempt_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated/admin/user/{}/attempt",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user able to delete a login attempt, just returns 200 empty body
    async fn admin_router_attempt_admin_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_anon_user().await;

        test_setup.invalid_signin(TEST_EMAIL).await;
        test_setup.change_user_level(UserLevel::Admin).await;

        assert_eq!(
            test_setup
                .get_model_user()
                .await
                .unwrap()
                .login_attempt_number,
            1
        );
        let url = format!(
            "{}/authenticated/admin/user/{}/attempt",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.text().await.unwrap(), "");
        assert_eq!(
            test_setup
                .get_model_user()
                .await
                .unwrap()
                .login_attempt_number,
            0
        );

        // Same test, with with another user
        test_setup.invalid_signin(ANON_EMAIL).await;
        test_setup.invalid_signin(ANON_EMAIL).await;
        test_setup.invalid_signin(ANON_EMAIL).await;
        assert_eq!(
            test_setup
                .get_anon_user()
                .await
                .unwrap()
                .login_attempt_number,
            3
        );
        let url = format!(
            "{}/authenticated/admin/user/{}/attempt",
            api_base_url(&test_setup.app_env),
            ANON_EMAIL
        );
        let client = TestSetup::get_client();
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.text().await.unwrap(), "");
        assert_eq!(
            test_setup
                .get_anon_user()
                .await
                .unwrap()
                .login_attempt_number,
            0
        );
    }

    // ****************
    // * Active Route *
    // ****************

    #[tokio::test]
    // Unauthenticated user unable to [PATCH] "/user/:email/attempt" route
    async fn admin_router_active_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated/admin/user/{}/active",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        let resp = client.patch(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [PATCH] "/user/:email/attempt" route
    async fn admin_router_active_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated/admin/user/{}/active",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user unable to patch active on self
    async fn admin_router_active_self_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let url = format!(
            "{}/authenticated/admin/user/{}/active",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();
        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            result.json::<Response>().await.unwrap().response,
            "Can't de-activate self"
        );
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;
    }

    #[tokio::test]
    /// Admin user able to de-activate the anon user, anon user session_set & sessions removed, unabled to log in,
    async fn admin_router_active_anon_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await.unwrap();

        test_setup.change_user_level(UserLevel::Admin).await;

        let url = format!(
            "{}/authenticated/admin/user/{}/active",
            api_base_url(&test_setup.app_env),
            ANON_EMAIL
        );

        let client = TestSetup::get_client();

        let anon_id = test_setup.get_anon_user().await.unwrap().registered_user_id;
        let anon_session = test_setup.get_session(anon_id).await.unwrap();

        // assert anon_user_cookie is valid
        test_is_authenticated(&test_setup, &client, &anon_user_cookie).await;

        let session_set: bool = test_setup
            .redis
            .lock()
            .await
            .exists(format!("session_set::user::{}", anon_id.get()))
            .await
            .unwrap();
        let session: bool = test_setup
            .redis
            .lock()
            .await
            .exists(&anon_session)
            .await
            .unwrap();
        assert!(session_set);
        assert!(session);

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.text().await.unwrap(), "");

        let session_set: bool = test_setup
            .redis
            .lock()
            .await
            .exists(format!("session_set::user::{}", anon_id.get()))
            .await
            .unwrap();
        let session: bool = test_setup
            .redis
            .lock()
            .await
            .exists(anon_session)
            .await
            .unwrap();
        assert!(!session_set);
        assert!(!session);

        // Anon user now unable to access the user route
        test_is_not_authenticated(&test_setup, &client, &anon_user_cookie).await;

        // user unable to signin
        assert!(test_setup.anon_user_cookie().await.is_none());
    }

    #[tokio::test]
    /// Admin user able to reactivate the anon user, able to login
    async fn admin_router_reactivate_anon_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await.unwrap();

        test_setup.change_user_level(UserLevel::Admin).await;

        let url = format!(
            "{}/authenticated/admin/user/{}/active",
            api_base_url(&test_setup.app_env),
            ANON_EMAIL
        );

        let client = TestSetup::get_client();

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.text().await.unwrap(), "");

        // Anon user now unable to access the user route
        test_is_not_authenticated(&test_setup, &client, &anon_user_cookie).await;
        // user unable to signin
        assert!(test_setup.anon_user_cookie().await.is_none());

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.text().await.unwrap(), "");

        let anon_user_cookie = test_setup.anon_user_cookie().await;
        assert!(anon_user_cookie.is_some());
        let anon_user_cookie = anon_user_cookie.unwrap();
        // Anon user is authenticated
        test_is_authenticated(&test_setup, &client, &anon_user_cookie).await;
    }

    // *****************
    // * Devices Route *
    // *****************

    #[tokio::test]
    // Unauthenticated user unable to [GET] "/user/:email/devices" route
    async fn admin_router_devices_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated/admin/user/{}/devices",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [GET] "/user/:email/devices" route
    async fn admin_router_devices_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated/admin/user/{}/devices",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user is able to [GET] "/user/:email/devices" information
    async fn admin_router_devices_get_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await.unwrap();
        test_setup.change_user_level(UserLevel::Admin).await;

        let device_name = test_setup.insert_device(&anon_user_cookie, None).await;
        let ws_pi_url = test_setup.get_anon_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());
        let ws_client_url = test_setup
            .get_anon_access_code(ConnectionType::Client, 0)
            .await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let url = format!(
            "{}/authenticated/admin/user/{}/devices",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL
        );

        let client = TestSetup::get_client();

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_array());
        let result = result.as_array().unwrap();
        assert!(result.is_empty());

        let url = format!(
            "{}/authenticated/admin/user/{}/devices",
            api_base_url(&test_setup.app_env),
            ANON_EMAIL
        );

        let client = TestSetup::get_client();

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_array());
        let result = result.as_array().unwrap();

        assert_eq!(result.len(), 1);

        assert!(result[0].is_object());
        let result = result[0].as_object().unwrap();
        let connections = result.get("connections");
        assert!(connections.is_some());
        assert!(connections.unwrap().is_array());

        assert!(connections.unwrap().as_array().unwrap()[0]
            .as_object()
            .unwrap()
            .get("connection_id")
            .unwrap()
            .is_i64());
        assert!(connections.unwrap().as_array().unwrap()[0]
            .as_object()
            .unwrap()
            .get("device_id")
            .unwrap()
            .is_i64());
        assert_eq!(
            connections.unwrap().as_array().unwrap()[0]
                .as_object()
                .unwrap()
                .get("device_type")
                .unwrap()
                .as_str()
                .unwrap(),
            "Pi"
        );
        assert_eq!(
            connections.unwrap().as_array().unwrap()[0]
                .as_object()
                .unwrap()
                .get("ip")
                .unwrap()
                .as_str()
                .unwrap(),
            "127.0.0.1"
        );
        assert!(connections.unwrap().as_array().unwrap()[0]
            .as_object()
            .unwrap()
            .get("timestamp")
            .unwrap()
            .is_i64());
        assert!(connections.unwrap().as_array().unwrap()[0]
            .as_object()
            .unwrap()
            .get("ulid")
            .unwrap()
            .is_string());

        assert!(connections.unwrap().as_array().unwrap()[1]
            .as_object()
            .unwrap()
            .get("connection_id")
            .unwrap()
            .is_i64());
        assert!(connections.unwrap().as_array().unwrap()[1]
            .as_object()
            .unwrap()
            .get("device_id")
            .unwrap()
            .is_i64());
        assert_eq!(
            connections.unwrap().as_array().unwrap()[1]
                .as_object()
                .unwrap()
                .get("device_type")
                .unwrap()
                .as_str()
                .unwrap(),
            "Client"
        );
        assert_eq!(
            connections.unwrap().as_array().unwrap()[1]
                .as_object()
                .unwrap()
                .get("ip")
                .unwrap()
                .as_str()
                .unwrap(),
            "127.0.0.1"
        );
        assert!(connections.unwrap().as_array().unwrap()[1]
            .as_object()
            .unwrap()
            .get("timestamp")
            .unwrap()
            .is_i64());
        assert!(connections.unwrap().as_array().unwrap()[1]
            .as_object()
            .unwrap()
            .get("ulid")
            .unwrap()
            .is_string());

        let device = result.get("device");
        assert!(device.is_some());
        assert!(device.unwrap().is_object());
        let device = device.unwrap().as_object().unwrap();

        assert_eq!(
            device
                .get("name_of_device")
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap(),
            device_name
        );

        // Check device information
        assert!(device.get("device_id").is_none());

        assert!(device.get("api_key").is_some());
        assert!(device.get("api_key").as_ref().unwrap().is_string());
        assert!(
            device
                .get("api_key")
                .unwrap()
                .as_str()
                .unwrap()
                .chars()
                .count()
                == 128
        );

        assert!(device.get("name_of_device").is_some());
        assert!(device.get("name_of_device").as_ref().unwrap().is_string());
        assert_eq!(
            device.get("name_of_device").unwrap().as_str().unwrap(),
            device_name
        );

        let counts = ["day", "month", "total"];
        let device_types = ["client", "pi"];
        let direction = ["in", "out"];

        for time_len in counts {
            for d in device_types {
                for x in direction {
                    let key_name = format!("{d}_bytes_{time_len}_{x}");
                    assert!(device.get(&key_name).is_some());
                    assert!(device.get(&key_name).as_ref().unwrap().is_i64());
                    assert!(device.get(&key_name).unwrap().as_i64().unwrap() == 0);
                }
            }
        }

        let false_bools = [
            "client_password_required",
            "device_password_required",
            "structured_data",
            "paused",
        ];
        for key in false_bools {
            assert!(device.get(key).is_some());
            assert!(device.get(key).as_ref().unwrap().is_boolean());
            assert!(!device.get(key).unwrap().as_bool().unwrap());
        }

        assert!(device.get("max_clients").is_some());
        assert!(device.get("max_clients").as_ref().unwrap().is_i64());
        assert_eq!(device.get("max_clients").unwrap().as_i64().unwrap(), 1);

        assert!(device.get("timestamp_offline").is_some());
        assert!(device.get("timestamp_offline").as_ref().unwrap().is_null());

        assert!(device.get("timestamp_online").is_some());
        assert!(device.get("timestamp_online").as_ref().unwrap().is_string());
        assert!(device
            .get("timestamp_online")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&format!("{}", OffsetDateTime::now_utc().date())));

        assert!(device.get("ip").is_some());
        assert!(device.get("ip").as_ref().unwrap().is_string());
        assert_eq!(device.get("ip").unwrap().as_str().unwrap(), "127.0.0.1");

        assert!(device.get("creation_date").is_some());
        assert!(device.get("creation_date").as_ref().unwrap().is_string());
        assert!(device
            .get("creation_date")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&format!("{}", OffsetDateTime::now_utc().date())));
    }

    // *********************
    // * Email Device Route *
    // **********************

    #[tokio::test]
    // Unauthenticated user unable to [DELETE, PATCH] "/user/:email/device/:device_name" route
    async fn admin_router_user_device_named_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated/admin/user/{}/device/{}",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL,
            gen_random_hex(10)
        );

        let client = TestSetup::get_client();

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.patch(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Non admin user unable to access [ DELETE, PATCH ] "/user/:email/device/:device_name" route
    async fn admin_router_user_device_named_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated/admin/user/{}/device/{}",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL,
            device_name
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let result = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user gets a bad device response when unknown device sent
    async fn admin_router_user_device_named_patch_unknown_device() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let url = format!(
            "{}/authenticated/admin/user/{}/device/{}",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL,
            gen_random_hex(12)
        );

        let client = TestSetup::get_client();
        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "unknown device");
    }

    #[tokio::test]
    /// Admin user gets a bad user response when unknown email sent
    async fn admin_router_user_device_named_patch_unknown_user() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let url = format!(
            "{}/authenticated/admin/user/{}/device/{}",
            api_base_url(&test_setup.app_env),
            ANON_EMAIL,
            gen_random_hex(12)
        );

        let client = TestSetup::get_client();
        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "unknown user");
    }

    #[tokio::test]
    /// Admin user is able to [ PATCH ] "/user/:email/devices", to toggle device paused status
    /// ws connections also get cut
    async fn admin_router_user_device_named_patch_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let url = format!(
            "{}/authenticated/admin/user/{}/device/{}",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL,
            device_name
        );

        let client = TestSetup::get_client();
        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // assert device is paused
        assert!(test_setup.query_user_active_devices().await[0].paused);

        // assert connections get cut
        assert!(ws_client
            .unwrap()
            .0
            .next()
            .await
            .unwrap()
            .unwrap()
            .is_close());
        assert!(ws_pi.unwrap().0.next().await.unwrap().unwrap().is_close());

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // assert device now not paused
        assert!(!test_setup.query_user_active_devices().await[0].paused);
    }

    #[tokio::test]
    /// Admin user is able to [ DELETE ] "/user/:email/devices", to "delete" the device (set active to false)
    /// ws connections also get cut
    async fn admin_router_user_device_named_delete_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let url = format!(
            "{}/authenticated/admin/user/{}/device/{}",
            api_base_url(&test_setup.app_env),
            TEST_EMAIL,
            device_name
        );

        let client = TestSetup::get_client();
        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // assert no active devices
        assert!(test_setup.query_user_active_devices().await.is_empty());

        // assert connections get cut
        assert!(ws_client
            .unwrap()
            .0
            .next()
            .await
            .unwrap()
            .unwrap()
            .is_close());
        assert!(ws_pi.unwrap().0.next().await.unwrap().unwrap().is_close());
    }

    // *****************
    // * Invite Route *
    // *****************

    #[tokio::test]
    // Unauthenticated user unable to [ DELETE, GET, POST] "/invite" route
    async fn admin_router_invite_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Invite.addr()
        );

        let client = TestSetup::get_client();

        let resp = client
            .delete(&url)
            .json(&HashMap::from([("invite", gen_random_hex(12))]))
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

        let resp = client
            .post(&url)
            .json(&AdminInvite {
                password: TEST_PASSWORD.to_owned(),
                token: None,
                invite: gen_random_hex(12),
                count: 1,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// FREE, then PRO, user unable to access [ DELETE, GET, POST ] "/invite" route
    async fn admin_router_invite_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Invite.addr()
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let resp = client
            .delete(&url)
            .json(&HashMap::from([("invite", gen_random_hex(12))]))
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client
            .post(&url)
            .json(&AdminInvite {
                password: TEST_PASSWORD.to_owned(),
                token: None,
                invite: gen_random_hex(12),
                count: 1,
            })
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let resp = client
            .delete(&url)
            .json(&HashMap::from([("invite", gen_random_hex(12))]))
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client
            .post(&url)
            .json(&AdminInvite {
                password: TEST_PASSWORD.to_owned(),
                token: None,
                invite: gen_random_hex(12),
                count: 1,
            })
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user is able to [ POST, GET, then DELETE ] "/invite" route
    async fn admin_router_invite_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Invite.addr()
        );

        let client = TestSetup::get_client();
        let invite = gen_random_hex(12);
        let resp = client
            .post(&url)
            .json(&AdminInvite {
                password: TEST_PASSWORD.to_owned(),
                token: None,
                invite: invite.clone(),
                count: 13,
            })
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;
        assert!(result.is_array());
        assert_eq!(
            result.as_array().unwrap()[0]
                .get("count")
                .unwrap()
                .as_i64()
                .unwrap(),
            13
        );
        assert_eq!(
            result.as_array().unwrap()[0]
                .get("invite")
                .unwrap()
                .as_str()
                .unwrap(),
            invite
        );

        let resp = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&HashMap::from([("invite", invite)]))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // send another get request, to make sure no invites now exist
        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;
        assert!(result.is_array());
        assert!(result.as_array().unwrap().is_empty());
    }

    // *****************
    // * Emails Route *
    // *****************

    #[tokio::test]
    // Unauthenticated user unable to [ GET ] "/emails" route
    async fn admin_router_emails_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Emails.addr()
        );

        let client = TestSetup::get_client();

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// FREE, then PRO, user unable to access [ GET ] "/emails" route
    async fn admin_router_emails_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Emails.addr()
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user is able to [ GET ] "/emails" route
    async fn admin_router_emails_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let client = TestSetup::get_client();
        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);
        client.post(url).json(&body).send().await.unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Emails.addr()
        );

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result.get("hour").unwrap().as_i64().unwrap(), 1);
        assert_eq!(result.get("total").unwrap().as_i64().unwrap(), 1);
    }

    // *****************
    // * Contact Route *
    // *****************

    #[tokio::test]
    // Unauthenticated user unable to [ DELETE, GET ] "/contact" route
    async fn admin_router_contact_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Connection.addr()
        );

        let client = TestSetup::get_client();

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// FREE, then PRO, user unable to access [ DELETE, GET ] "/contact" route
    async fn admin_router_contact_not_admin() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Emails.addr()
        );

        let client = TestSetup::get_client();

        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let resp = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        // Test as pro user
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        test_is_authenticated(&test_setup, &client, &authed_cookie).await;

        let resp = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    /// Admin user is able to [ GET ] "/contact" route
    async fn admin_router_contact_get_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let client = TestSetup::get_client();
        let contact_post_url = format!("{}/incognito/contact", api_base_url(&test_setup.app_env));

        let message_01 = gen_random_hex(80);
        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message_01)]);
        client
            .post(&contact_post_url)
            .json(&body)
            .send()
            .await
            .unwrap();

        let message_02 = gen_random_hex(80);
        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message_02)]);
        client
            .post(&contact_post_url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        // lazy rate limit removal!
        test_setup
            .redis
            .lock()
            .await
            .del::<&str, ()>("ratelimit::contact_ip::127.0.0.1")
            .await
            .unwrap();
        test_setup
            .redis
            .lock()
            .await
            .del::<&str, ()>(&format!("ratelimit::contact_ip::{TEST_EMAIL}"))
            .await
            .unwrap();

        let message_03 = gen_random_hex(80);
        let body = HashMap::from([("email", ANON_EMAIL), ("message", &message_03)]);
        client
            .post(&contact_post_url)
            .json(&body)
            .send()
            .await
            .unwrap();

        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);
        client.post(url).json(&body).send().await.unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Contact.addr()
        );

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;

        assert_eq!(result.as_array().unwrap().len(), 3);
        let result = result.as_array().unwrap();
        let c1 = result[0].as_object().unwrap();
        assert!(c1.get("contact_message_id").unwrap().is_i64());
        assert_eq!(c1.get("email").unwrap().as_str().unwrap(), TEST_EMAIL);
        assert_eq!(c1.get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
        assert_eq!(c1.get("message").unwrap().as_str().unwrap(), message_01);
        assert!(c1.get("timestamp").unwrap().is_string());
        assert_eq!(
            c1.get("user_agent").unwrap().as_str().unwrap(),
            TEST_USER_AGENT
        );
        assert!(c1.get("registered_user_id").unwrap().is_null());

        let c2 = result[1].as_object().unwrap();
        assert!(c2.get("contact_message_id").unwrap().is_i64());
        assert_eq!(c2.get("email").unwrap().as_str().unwrap(), TEST_EMAIL);
        assert_eq!(c2.get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
        assert_eq!(c2.get("message").unwrap().as_str().unwrap(), message_02);
        assert!(c2.get("timestamp").unwrap().is_string());
        assert_eq!(
            c1.get("user_agent").unwrap().as_str().unwrap(),
            TEST_USER_AGENT
        );
        assert_eq!(
            c2.get("registered_user_id").unwrap().as_i64().unwrap(),
            test_setup.get_user_id().get()
        );

        let c3 = result[2].as_object().unwrap();
        assert!(c3.get("contact_message_id").unwrap().is_i64());
        assert_eq!(c3.get("email").unwrap().as_str().unwrap(), ANON_EMAIL);
        assert_eq!(c3.get("ip").unwrap().as_str().unwrap(), "127.0.0.1");
        assert_eq!(c3.get("message").unwrap().as_str().unwrap(), message_03);
        assert!(c3.get("timestamp").unwrap().is_string());
        assert_eq!(
            c3.get("user_agent").unwrap().as_str().unwrap(),
            TEST_USER_AGENT
        );
        assert!(c3.get("registered_user_id").unwrap().is_null());
    }

    #[tokio::test]
    /// Admin user is able to delete a message via "/contact" route
    async fn admin_router_contact_delete_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;

        let client = TestSetup::get_client();
        let contact_post_url = format!("{}/incognito/contact", api_base_url(&test_setup.app_env));

        let message_01 = gen_random_hex(80);
        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message_01)]);
        client
            .post(&contact_post_url)
            .json(&body)
            .send()
            .await
            .unwrap();

        let message_02 = gen_random_hex(80);
        let body = HashMap::from([("email", TEST_EMAIL), ("message", &message_02)]);
        client
            .post(&contact_post_url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        let url = format!("{}/incognito/reset", api_base_url(&test_setup.app_env));
        let body = HashMap::from([("email", TEST_EMAIL)]);
        client.post(url).json(&body).send().await.unwrap();

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Contact.addr()
        );

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;

        assert_eq!(result.as_array().unwrap().len(), 2);
        let result = result.as_array().unwrap();
        let body = HashMap::from([(
            "contact_message_id",
            result[0]
                .as_object()
                .unwrap()
                .get("contact_message_id")
                .unwrap()
                .as_u64()
                .unwrap(),
        )]);

        let resp = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            AdminRoutes::Contact.addr()
        );

        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;

        assert_eq!(result.as_array().unwrap().len(), 1);
    }
}

use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    routing::{delete, patch},
    Router,
};
use std::fmt;

use crate::{
    api_error::ApiError,
    database::{
        connection::ModelConnection,
        device::{ModelApiKey, ModelDevice},
        ip_user_agent::ModelUserAgentIp,
        message_cache::MessageCache,
        rate_limit::RateLimit,
        user::ModelUser,
    },
    define_routes,
    servers::{api::authentication, ApiRouter, ApplicationState, StatusOJ},
    user_io::{
        incoming_json::ij,
        outgoing_json::oj::{self, AllDevices},
    },
};

define_routes! {
    DeviceRoutes,
    "/device",
    Base => "",
    Named => "/:name",
    NamedApiKey => "/:name/api_key",
    NamedMaxClients => "/:name/max_clients",
    NamedPassword => "/:name/password",
    NamedPause => "/:name/pause",
    NamedRename => "/:name/rename",
    NamedStructured => "/:name/structured_data"
}

// This is shared, should put elsewhere
enum DeviceResponse {
    AtMax,
    FreeName,
    FreeMaxClients,
    FreePassword,
    FreeStructured,
    Unknown,
    MaxClients,
    NameInUse,
}

impl fmt::Display for DeviceResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let disp = match self {
            Self::AtMax => "Max number devices reached",
            Self::FreeMaxClients => "Free users are unable to change max clients",
            Self::FreeName => "Free users are unable to set name",
            Self::FreePassword => "Free users are unable to set device password",
            Self::FreeStructured => "Free users are unable to set structured data",
            Self::MaxClients => "Max clients invalid",
            Self::NameInUse => "Device with given name already exists",
            Self::Unknown => "Unknown device",
        };
        write!(f, "{disp}")
    }
}

pub struct DeviceRouter;

impl ApiRouter for DeviceRouter {
    fn create_router(state: &ApplicationState) -> Router<ApplicationState> {
        Router::new()
            .route(
                &DeviceRoutes::Base.addr(),
                delete(Self::device_all_delete)
                    .get(Self::device_all_get)
                    .post(Self::device_all_post),
            )
            .route(
                &DeviceRoutes::NamedPause.addr(),
                patch(Self::named_pause_patch),
            )
            .route(
                &DeviceRoutes::NamedApiKey.addr(),
                patch(Self::named_api_key_patch),
            )
            .route(
                &DeviceRoutes::NamedRename.addr(),
                patch(Self::named_rename_patch),
            )
            .route(
                &DeviceRoutes::NamedMaxClients.addr(),
                patch(Self::named_max_clients_patch),
            )
            .route(
                &DeviceRoutes::NamedStructured.addr(),
                patch(Self::named_structured_patch),
            )
            .route(
                &DeviceRoutes::NamedPassword.addr(),
                delete(Self::named_password_delete).patch(Self::named_password_patch),
            )
            .route(
                &DeviceRoutes::Named.addr(),
                delete(Self::named_delete).get(Self::named_get),
            )
            .layer(middleware::from_fn_with_state(
                state.clone(),
                authentication::is_authenticated,
            ))
    }
}

impl DeviceRouter {
    /// delete all devices
    async fn device_all_delete(
        user: ModelUser,
        State(state): State<ApplicationState>,
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
        ModelDevice::delete_all_device_cache_connections(
            &state.postgres,
            &mut state.redis(),
            &state.connections,
            &user,
        )
        .await?;

        Ok(StatusCode::OK)
    }

    /// Get information on all devices, and include rate limits
    async fn device_all_get(
        State(state): State<ApplicationState>,
        user: ModelUser,
    ) -> Result<StatusOJ<AllDevices>, ApiError> {
        let devices = ModelDevice::get_all(&state.postgres, &user).await?;
        let mut limits = vec![];

        for device in &devices {
            let limiter = RateLimit::from((device, &user));
            limits.push(oj::AllLimits {
                name_of_device: device.name_of_device.clone(),
                ttl: limiter.limited_ttl(&mut state.redis()).await?,
            });
        }
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(oj::AllDevices { devices, limits }),
        ))
    }

    /// Insert a new device, check body against settings in the user object
    async fn device_all_post(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        ij::IncomingJson(body): ij::IncomingJson<ij::DevicePost>,
    ) -> Result<StatusOJ<String>, ApiError> {
        if !user.structured_data && body.structured_data {
            return Err(ApiError::InvalidValue(
                DeviceResponse::FreeStructured.to_string(),
            ));
        }

        if !user.device_password
            && (body.client_password.is_some() || body.device_password.is_some())
        {
            return Err(ApiError::InvalidValue(
                DeviceResponse::FreePassword.to_string(),
            ));
        }
        if !user.custom_device_name && body.name.is_some() {
            return Err(ApiError::InvalidValue(DeviceResponse::FreeName.to_string()));
        }

        // Check to see if max number of devices already hit
        let device_count = ModelDevice::count(&state.postgres, &user).await?;
        if device_count >= i64::from(user.max_number_of_devices) {
            return Err(ApiError::Conflict(DeviceResponse::AtMax.to_string()));
        }

        // Check max_clients setting is valid
        if body.max_clients > user.max_clients_per_device {
            return Err(ApiError::InvalidValue(
                DeviceResponse::MaxClients.to_string(),
            ));
        }

        // Check if a given device name is already in user by the user
        if let Some(device_name) = body.name.as_ref() {
            if ModelDevice::get_by_name(&state.postgres, &user, device_name)
                .await?
                .is_some()
            {
                return Err(ApiError::Conflict(DeviceResponse::NameInUse.to_string()));
            }
        }

        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(
                ModelDevice::insert(&state.postgres, useragent_ip, &user, body).await?,
            ),
        ))
    }

    /// Delete a named device
    async fn named_delete(
        State(state): State<ApplicationState>,
        Path(device_name): Path<String>,
        user: ModelUser,
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

        if let Some(device_id) =
            ModelDevice::delete_by_name(&state.postgres, &user, &device_name).await?
        {
            state
                .connections
                .lock()
                .await
                .close_by_single_device_id(device_id)
                .await;

            MessageCache::delete(&mut state.redis(), device_id).await?;

            Ok(StatusCode::OK)
        } else {
            Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
        }
    }

    /// get client connection details for given a named device
    async fn named_get(
        State(state): State<ApplicationState>,
        user: ModelUser,
        Path(device_name): Path<String>,
    ) -> Result<StatusOJ<Vec<ModelConnection>>, ApiError> {
        if ModelDevice::get_by_name(&state.postgres, &user, &device_name)
            .await?
            .is_some()
        {
            Ok((
                StatusCode::OK,
                oj::OutgoingJson::new(
                    ModelConnection::get_client_online(&state.postgres, &user, &device_name)
                        .await?,
                ),
            ))
        } else {
            Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
        }
    }

    /// (un)pause a named device
    async fn named_pause_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        Path(device_name): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::DevicePause>,
    ) -> Result<StatusCode, ApiError> {
        // Get device, then operate on device::update etc!
        if let Some(mut device) =
            ModelDevice::get_by_name(&state.postgres, &user, &device_name).await?
        {
            device.update_paused(&state.postgres, body.pause).await?;
            if body.pause {
                state
                    .connections
                    .lock()
                    .await
                    .close_by_single_device_id(device.device_id)
                    .await;
            }
            Ok(StatusCode::OK)
        } else {
            Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
        }
    }

    /// Rename a device, only if none free user
    async fn named_structured_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        Path(device_name): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::DeviceStructured>,
    ) -> Result<StatusCode, ApiError> {
        // Get device, then operate on device::update etc!
        if user.structured_data {
            if let Some(mut device) =
                ModelDevice::get_by_name(&state.postgres, &user, &device_name).await?
            {
                device
                    .update_structured_data(&state.postgres, body.structured_data)
                    .await?;

                // kill all connections
                state
                    .connections
                    .lock()
                    .await
                    .close_by_single_device_id(device.device_id)
                    .await;

                MessageCache::delete(&mut state.redis(), device.device_id).await?;
                Ok(StatusCode::OK)
            } else {
                Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
            }
        } else {
            Err(ApiError::InvalidValue(DeviceResponse::FreeName.to_string()))
        }
    }

    /// Remove a device password
    async fn named_password_delete(
        State(state): State<ApplicationState>,
        user: ModelUser,
        Path(device_name): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusCode, ApiError> {
        if user.device_password {
            // Get device, then operate on device::update etc!
            if let Some(mut device) =
                ModelDevice::get_by_name(&state.postgres, &user, &device_name).await?
            {
                if authentication::check_password_op_token(
                    &user,
                    &body.password,
                    body.token,
                    &state.postgres,
                )
                .await?
                {
                    device.remove_password(&state.postgres).await?;
                    Ok(StatusCode::OK)
                } else {
                    Err(ApiError::Authorization)
                }
            } else {
                Err(ApiError::InvalidValue(DeviceResponse::FreeName.to_string()))
            }
        } else {
            Err(ApiError::InvalidValue(
                DeviceResponse::FreePassword.to_string(),
            ))
        }
    }

    ///Add a device password
    async fn named_password_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        Path(device_name): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::ClientDevicePassword>,
    ) -> Result<StatusCode, ApiError> {
        if user.device_password {
            if let Some(mut device) =
                ModelDevice::get_by_name(&state.postgres, &user, &device_name).await?
            {
                device.update_password(&state.postgres, body).await?;
                state
                    .connections
                    .lock()
                    .await
                    .close_by_single_device_id(device.device_id)
                    .await;
                Ok(StatusCode::OK)
            } else {
                Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
            }
        } else {
            Err(ApiError::InvalidValue(
                DeviceResponse::FreePassword.to_string(),
            ))
        }
    }

    /// Rename a device, only if none free user
    /// Could apply a middleware to this, and other, routes, to make sure that free users can't access?
    async fn named_rename_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        Path(device_name): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::DeviceRename>,
    ) -> Result<StatusCode, ApiError> {
        if user.custom_device_name {
            if let Some(mut device) =
                ModelDevice::get_by_name(&state.postgres, &user, &device_name).await?
            {
                if ModelDevice::get_by_name(&state.postgres, &user, &body.new_name)
                    .await?
                    .is_some()
                {
                    return Err(ApiError::Conflict(DeviceResponse::NameInUse.to_string()));
                }

                device.update_name(&state.postgres, body.new_name).await?;
                Ok(StatusCode::OK)
            } else {
                Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
            }
        } else {
            Err(ApiError::InvalidValue(DeviceResponse::FreeName.to_string()))
        }
    }

    /// Update device max clients, only available to none free users
    async fn named_max_clients_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        Path(device_name): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::DeviceMaxClients>,
    ) -> Result<StatusCode, ApiError> {
        // This isn't great
        if user.max_clients_per_device > 1 {
            if (1..=user.max_clients_per_device).contains(&body.max_clients) {
                if let Some(mut device) =
                    ModelDevice::get_by_name(&state.postgres, &user, &device_name).await?
                {
                    device
                        .update_max_client(&state.postgres, body.max_clients)
                        .await?;
                    state
                        .connections
                        .lock()
                        .await
                        .close_max_clients(device.device_id, body.max_clients)
                        .await;
                    Ok(StatusCode::OK)
                } else {
                    Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
                }
            } else {
                Err(ApiError::InvalidValue(
                    DeviceResponse::MaxClients.to_string(),
                ))
            }
        } else {
            Err(ApiError::InvalidValue(
                DeviceResponse::FreeMaxClients.to_string(),
            ))
        }
    }

    /// refresh a devices api key
    async fn named_api_key_patch(
        State(state): State<ApplicationState>,
        user: ModelUser,
        useragent_ip: ModelUserAgentIp,
        Path(device_name): Path<String>,
        ij::IncomingJson(body): ij::IncomingJson<ij::PasswordToken>,
    ) -> Result<StatusCode, ApiError> {
        if let Some(device) = ModelDevice::get_by_name(&state.postgres, &user, &device_name).await?
        {
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

            state
                .connections
                .lock()
                .await
                .close_by_single_device_id(device.device_id)
                .await;

            ModelApiKey::update(&state.postgres, &user, useragent_ip, &device).await?;
            Ok(StatusCode::OK)
        } else {
            Err(ApiError::InvalidValue(DeviceResponse::Unknown.to_string()))
        }
    }
}

/// Use reqwest to test against real server
/// cargo watch -q -c -w src/ -x 'test device_router_user -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {

    use super::DeviceRoutes;
    use crate::connections::ConnectionType;
    use crate::database::user_level::UserLevel;
    use crate::helpers::gen_random_hex;
    use crate::servers::test_setup::{
        api_base_url, start_servers, Response, TestSetup, ANON_PASSWORD, TEST_PASSWORD,
    };
    use crate::sleep;
    use crate::user_io::incoming_json::ij::DevicePost;

    use futures::{SinkExt, StreamExt};
    use redis::AsyncCommands;
    use reqwest::StatusCode;
    use std::collections::HashMap;
    use time::OffsetDateTime;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    //***************
    // * Base Route *
    // **************

    #[tokio::test]
    // Unauthenticated user unable to access [DELETE, GET, POST] /device/ route
    async fn device_router_user_get_user_unauthenticated() {
        let test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
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

        let resp = client.post(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    /// POST requests

    #[tokio::test]
    /// Free user unable to create device if each k/v is invalid
    async fn device_router_post_free_user_invalid() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;

        // Invalid max clients : 0
        let body = TestSetup::gen_device_post(0, None, None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "max_clients");

        // Invalid max clients > 1
        let body = TestSetup::gen_device_post(10, None, None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Max clients invalid");

        // Structured data
        let body = TestSetup::gen_device_post(1, None, None, true, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to set structured data");

        // Name set to anything
        let body = TestSetup::gen_device_post(1, None, None, false, Some("some name"));
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to set name");

        // client password set to anything
        let body = TestSetup::gen_device_post(1, Some("random_password"), None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to set device password");

        let body = TestSetup::gen_device_post(1, None, Some("random_password"), false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to set device password");
    }

    #[tokio::test]
    /// Pro user unable to create device if each k/v is invalid
    async fn device_router_post_pro_user_invalid() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        // Invalid max clients : 0
        let body = TestSetup::gen_device_post(0, None, None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "max_clients");

        // Invalid max clients > 100
        let body = TestSetup::gen_device_post(101, None, None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Max clients invalid");

        // Invalid name, empty
        let body = TestSetup::gen_device_post(1, None, None, false, Some(""));
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "device_name");

        // Invalid name, empty (after trim)
        let body = TestSetup::gen_device_post(1, None, None, false, Some("                  "));
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "device_name");

        // Name too long
        let name = (0..=66).map(|_| "a").collect::<String>();
        let body = TestSetup::gen_device_post(1, None, None, false, Some(name.as_str()));
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "device_name");

        // client password too_long
        let password = (0..=65).map(|_| "a").collect::<String>();

        let body = TestSetup::gen_device_post(1, Some(password.as_str()), None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "device_password");

        // device password too long
        let body = TestSetup::gen_device_post(1, None, Some(password.as_str()), false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "device_password");
    }

    #[tokio::test]
    /// Free user able to insert device
    async fn device_router_post_free_user_valid() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;

        let body = TestSetup::gen_device_post(1, None, None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_string());

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
    }

    #[tokio::test]
    /// Free user unable to insert more than 1 device
    async fn device_router_post_free_user_max_devices() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        let body = TestSetup::gen_device_post(1, None, None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Max number devices reached");
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
    }

    #[tokio::test]
    /// Pro user able to create devices, with each, and every, setting
    async fn device_router_pro_user_valid() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        // With max clients
        let body = TestSetup::gen_device_post(100, None, None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_string());
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
        assert!(list_devices[0].max_clients == 100);
        test_setup.delete_devices().await;

        // With client password
        let password = (0..=16).map(|_| "a").collect::<String>();
        let body = TestSetup::gen_device_post(1, Some(password.as_str()), None, false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_string());
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
        assert!(list_devices[0].client_password_id.is_some());
        test_setup.delete_devices().await;

        // With device password
        let body = TestSetup::gen_device_post(1, None, Some(password.as_str()), false, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_string());
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
        assert!(list_devices[0].device_password_id.is_some());
        test_setup.delete_devices().await;

        // With both password, assert 2 hashes in db
        let body = TestSetup::gen_device_post(
            1,
            Some(password.as_str()),
            Some(password.as_str()),
            false,
            None,
        );
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_string());
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
        assert!(list_devices[0].client_password_id.is_some());
        assert!(list_devices[0].device_password_id.is_some());
        assert!(
            list_devices[0].device_password_id.unwrap()
                != list_devices[0].client_password_id.unwrap()
        );
        test_setup.delete_devices().await;

        // With structured data
        let body = TestSetup::gen_device_post(1, None, None, true, None);
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.is_string());
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
        assert!(list_devices[0].structured_data);
        test_setup.delete_devices().await;

        // With name
        let name = gen_random_hex(12);
        let body = TestSetup::gen_device_post(1, None, None, true, Some(name.as_str()));
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, name);
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
        test_setup.delete_devices().await;

        // With every setting
        let name = gen_random_hex(12);
        let client_password = gen_random_hex(12);
        let device_password = gen_random_hex(12);
        let body = TestSetup::gen_device_post(
            10,
            Some(client_password.as_str()),
            Some(device_password.as_str()),
            true,
            Some(name.as_str()),
        );
        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, name);
        test_setup.delete_devices().await;
    }

    #[tokio::test]
    /// Pro user unable to insert more than 20 devices
    /// TODO work out why this test can fail
    async fn device_router_post_pro_user_max_devices() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let body = TestSetup::gen_device_post(1, None, None, false, None);

        for _ in 0..=19 {
            test_setup.insert_device(&authed_cookie, None).await;
        }

        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Max number devices reached");
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 20);
    }

    #[tokio::test]
    /// Pro user unable to insert two devices with same name
    async fn device_router_post_pro_user_same_name() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let name = gen_random_hex(10);

        let body = TestSetup::gen_device_post(1, None, None, false, Some(name.as_str()));

        client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        let result = client
            .post(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::CONFLICT);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Device with given name already exists");
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
    }

    /// GET requests

    #[tokio::test]
    /// Free user get device info
    async fn device_router_get_free_user_valid() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        let result = result.json::<Response>().await.unwrap().response;

        assert!(result.as_object().unwrap().contains_key("devices"));
        assert!(result.as_object().unwrap().contains_key("limits"));

        let data = result.as_object().unwrap();

        // Check device limits
        let result = data.get("limits").unwrap();
        assert!(result.is_array());
        let result = result.as_array().unwrap();
        assert!(result.len() == 1);
        let result = result[0].as_object().unwrap();
        assert_eq!(
            result
                .get("name_of_device")
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap(),
            device_name
        );
        assert_eq!(result.get("ttl").as_ref().unwrap().as_i64().unwrap(), 0);

        // Check device information
        let result = data.get("devices").unwrap();

        assert!(result.is_array());
        let result = result.as_array().unwrap();

        assert!(result.len() == 1);
        let result = result[0].as_object().unwrap();
        assert!(result.get("device_id").is_none());

        assert!(result.get("api_key").is_some());
        assert!(result.get("api_key").as_ref().unwrap().is_string());
        assert!(
            result
                .get("api_key")
                .unwrap()
                .as_str()
                .unwrap()
                .chars()
                .count()
                == 128
        );

        assert!(result.get("name_of_device").is_some());
        assert!(result.get("name_of_device").as_ref().unwrap().is_string());
        assert_eq!(
            result.get("name_of_device").unwrap().as_str().unwrap(),
            device_name
        );

        let counts = ["day", "month", "total"];
        let device_types = ["client", "pi"];
        let direction = ["in", "out"];

        for time_len in counts {
            for device in device_types {
                for x in direction {
                    let key_name = format!("{device}_bytes_{time_len}_{x}");
                    assert!(result.get(&key_name).is_some());
                    assert!(result.get(&key_name).as_ref().unwrap().is_i64());
                    assert!(result.get(&key_name).unwrap().as_i64().unwrap() == 0);
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
            assert!(result.get(key).is_some());
            assert!(result.get(key).as_ref().unwrap().is_boolean());
            assert!(!result.get(key).unwrap().as_bool().unwrap());
        }

        assert!(result.get("max_clients").is_some());
        assert!(result.get("max_clients").as_ref().unwrap().is_i64());
        assert_eq!(result.get("max_clients").unwrap().as_i64().unwrap(), 1);

        let nulls = ["timestamp_offline", "timestamp_online", "ip"];
        for key in nulls {
            assert!(result.get(key).is_some());
            assert!(result.get(key).as_ref().unwrap().is_null());
        }

        assert!(result.get("creation_date").is_some());
        assert!(result.get("creation_date").as_ref().unwrap().is_string());
        assert!(result
            .get("creation_date")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&format!("{}", OffsetDateTime::now_utc().date())));
    }

    #[tokio::test]
    /// Anon user can't access free user device info
    async fn device_router_get_anon_user_invalid() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .get(&url)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        let result = result.json::<Response>().await.unwrap().response;

        assert!(result.as_object().unwrap().contains_key("devices"));
        assert!(result.as_object().unwrap().contains_key("limits"));

        assert!(result
            .as_object()
            .unwrap()
            .get("devices")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        assert!(result
            .as_object()
            .unwrap()
            .get("limits")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    /// Pro user get device info, when 2 distinct devices inserted
    async fn device_router_get_pro_user_valid() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let device_1 = test_setup.insert_device(&authed_cookie, None).await;

        let hex_device_name = gen_random_hex(10);
        test_setup
            .insert_device(
                &authed_cookie,
                Some(TestSetup::gen_device_post(
                    10,
                    Some(&gen_random_hex(13)),
                    Some(&gen_random_hex(13)),
                    true,
                    Some(&hex_device_name),
                )),
            )
            .await;

        let result = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();

        // This is an error, also has limits as well!
        // let result = result.json::<Response>().await.unwrap().response;
        let result = result.json::<Response>().await.unwrap().response;
        assert!(result.as_object().unwrap().contains_key("devices"));
        assert!(result.as_object().unwrap().contains_key("limits"));

        let data = result.as_object().unwrap();

        // Check device limits
        let result = data.get("limits").unwrap();
        assert!(result.is_array());
        let limits = result.as_array().unwrap();
        assert!(limits.len() == 2);
        let result = limits[0].as_object().unwrap();
        assert_eq!(
            result
                .get("name_of_device")
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap(),
            device_1
        );
        assert_eq!(result.get("ttl").as_ref().unwrap().as_i64().unwrap(), 0);

        let result = limits[1].as_object().unwrap();
        assert_eq!(
            result
                .get("name_of_device")
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap(),
            hex_device_name
        );
        assert_eq!(result.get("ttl").as_ref().unwrap().as_i64().unwrap(), 0);

        // Check device information
        let result = data.get("devices").unwrap();

        assert!(result.is_array());
        let result = result.as_array().unwrap();
        assert!(result.len() == 2);
        let result_01 = result[0].as_object().unwrap();
        assert!(result_01.get("device_id").is_none());

        assert!(result_01.get("api_key").is_some());
        assert!(result_01.get("api_key").as_ref().unwrap().is_string());
        assert!(
            result_01
                .get("api_key")
                .unwrap()
                .as_str()
                .unwrap()
                .chars()
                .count()
                == 128
        );

        assert!(result_01.get("name_of_device").is_some());
        assert!(result_01
            .get("name_of_device")
            .as_ref()
            .unwrap()
            .is_string());
        assert_eq!(
            result_01.get("name_of_device").unwrap().as_str().unwrap(),
            device_1
        );

        let counts = ["day", "month", "total"];
        let device_types = ["client", "pi"];
        let direction = ["in", "out"];

        for time_len in counts {
            for device in device_types {
                for x in direction {
                    let key_name = format!("{device}_bytes_{time_len}_{x}");
                    assert!(result_01.get(&key_name).is_some());
                    assert!(result_01.get(&key_name).as_ref().unwrap().is_i64());
                    assert!(result_01.get(&key_name).unwrap().as_i64().unwrap() == 0);
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
            assert!(result_01.get(key).is_some());
            assert!(result_01.get(key).as_ref().unwrap().is_boolean());
            assert!(!result_01.get(key).unwrap().as_bool().unwrap());
        }

        assert!(result_01.get("max_clients").is_some());
        assert!(result_01.get("max_clients").as_ref().unwrap().is_i64());
        assert_eq!(result_01.get("max_clients").unwrap().as_i64().unwrap(), 1);

        let nulls = ["timestamp_offline", "timestamp_online", "ip"];
        for key in nulls {
            assert!(result_01.get(key).is_some());
            assert!(result_01.get(key).as_ref().unwrap().is_null());
        }

        assert!(result_01.get("creation_date").is_some());
        assert!(result_01.get("creation_date").as_ref().unwrap().is_string());
        assert!(result_01
            .get("creation_date")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&format!("{}", OffsetDateTime::now_utc().date())));

        let result_02 = result[1].as_object().unwrap();
        assert!(result_02.get("device_id").is_none());

        assert!(result_02.get("api_key").is_some());
        assert!(result_02.get("api_key").as_ref().unwrap().is_string());
        assert!(
            result_02
                .get("api_key")
                .unwrap()
                .as_str()
                .unwrap()
                .chars()
                .count()
                == 128
        );

        assert!(result_02.get("name_of_device").is_some());
        assert!(result_02
            .get("name_of_device")
            .as_ref()
            .unwrap()
            .is_string());
        assert_eq!(
            result_02.get("name_of_device").unwrap().as_str().unwrap(),
            hex_device_name
        );

        let counts = ["day", "month", "total"];
        let device_types = ["client", "pi"];
        let direction = ["in", "out"];

        for time_len in counts {
            for device in device_types {
                for x in direction {
                    let key_name = format!("{device}_bytes_{time_len}_{x}");
                    assert!(result_02.get(&key_name).is_some());
                    assert!(result_02.get(&key_name).as_ref().unwrap().is_i64());
                    assert!(result_02.get(&key_name).unwrap().as_i64().unwrap() == 0);
                }
            }
        }

        let true_bools = [
            "client_password_required",
            "device_password_required",
            "structured_data",
        ];
        for key in true_bools {
            assert!(result_02.get(key).is_some());
            assert!(result_02.get(key).as_ref().unwrap().is_boolean());
            assert!(result_02.get(key).unwrap().as_bool().unwrap());
        }

        assert!(result_02.get("paused").is_some());
        assert!(result_02.get("paused").as_ref().unwrap().is_boolean());
        assert!(!result_02.get("paused").unwrap().as_bool().unwrap());

        assert!(result_02.get("max_clients").is_some());
        assert!(result_02.get("max_clients").as_ref().unwrap().is_i64());
        assert_eq!(result_02.get("max_clients").unwrap().as_i64().unwrap(), 10);

        let nulls = ["timestamp_offline", "timestamp_online", "ip"];
        for key in nulls {
            assert!(result_02.get(key).is_some());
            assert!(result_02.get(key).as_ref().unwrap().is_null());
        }

        assert!(result_02.get("creation_date").is_some());
        assert!(result_02.get("creation_date").as_ref().unwrap().is_string());
        assert!(result_02
            .get("creation_date")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&format!("{}", OffsetDateTime::now_utc().date())));

        assert_ne!(
            result_01.get("api_key").unwrap().as_str().unwrap(),
            result_02.get("api_key").unwrap().as_str().unwrap()
        );
    }

    #[tokio::test]
    // Unable to delete all device, with wrong password, no password, wrong token, no token
    async fn device_router_delete_all_invalid_body() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;

        // No password sent
        let body: HashMap<String, String> = HashMap::new();
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        // let result = result.text().await.unwrap();
        assert_eq!(result, "missing password");

        // Invalid password sent
        let body = HashMap::from([("password", "password")]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        test_setup.insert_two_fa().await;
        test_setup.two_fa_always_required(true).await;

        // Missing token
        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        // invalid token
        let token = test_setup.get_invalid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &token)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");
    }

    #[tokio::test]
    /// All devices deleted with password, and then again when twoFA always required is enabled
    async fn device_router_delete_all_ok_free_user() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_device(&authed_cookie, None).await;

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);

        // Valid password sent
        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.is_empty());

        test_setup.insert_two_fa().await;
        test_setup.two_fa_always_required(true).await;

        test_setup.insert_device(&authed_cookie, None).await;
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);

        let token = test_setup.get_valid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &token)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.is_empty());
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    /// All devices deleted with password, and then again when twoFA always required is enabled
    async fn device_router_delete_all_ok_pro_user() {
        let mut test_setup = start_servers().await;
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        for _ in 0..10 {
            test_setup.insert_device(&authed_cookie, None).await;
        }

        // need to work out why this is needed?
        sleep!();
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 10);

        // Valid password sent
        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::OK);
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.is_empty());

        test_setup.insert_two_fa().await;
        test_setup.two_fa_always_required(true).await;

        for _ in 0..10 {
            test_setup.insert_device(&authed_cookie, None).await;
            sleep!(10);
        }
        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 10);

        let token = test_setup.get_valid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &token)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.is_empty());
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    /// Device message caches removed when all devices deleted
    async fn device_router_delete_pro_user_message_cache_removed() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 2,
                    client_password: None,
                    device_password: None,
                    structured_data: true,
                    name: None,
                }),
            )
            .await;
        test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 2,
                    client_password: None,
                    device_password: None,
                    structured_data: true,
                    name: None,
                }),
            )
            .await;

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi_01 = connect_async(&url).await;
        assert!(ws_pi_01.is_ok());
        let (mut ws_pi_01, _) = ws_pi_01.unwrap();
        let msg_text = r#"{"data":"ws_pi_01", "cache": true}"#;
        let msg = Message::from(msg_text);
        ws_pi_01.send(msg).await.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Pi, 1).await;

        let ws_pi_02 = connect_async(&url).await;
        assert!(ws_pi_02.is_ok());
        let (mut ws_pi_02, _) = ws_pi_02.unwrap();
        let msg_text = r#"{"data":"ws_pi_02", "cache": true}"#;
        let msg = Message::from(msg_text);
        ws_pi_02.send(msg).await.unwrap();

        // Sleep as inserted on own thread
        sleep!(100);
        let message_caches: Vec<String> = test_setup.redis.keys("cache::message::*").await.unwrap();

        assert_eq!(message_caches.len(), 2);

        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let url = format!(
            "{}/authenticated{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr()
        );
        client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        let message_caches: Vec<String> = test_setup.redis.keys("cache::message::*").await.unwrap();
        assert!(message_caches.is_empty());
    }

    //*******************
    //* Name device route
    //*******************

    #[tokio::test]
    // Unauthenticated user unable to access [DELETE, GET, PATCH] /device/:device_name route
    async fn device_router_user_name_device_user_unauthenticated() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body: HashMap<String, String> = HashMap::new();

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.post(url).json(&body).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    //***********
    // * DELETE *
    //***********

    #[tokio::test]
    /// Return 401 unauthorized if invalid password (+ token) invalid
    async fn device_router_user_named_device_delete_invalid_body() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        // No password sent
        let body: HashMap<String, String> = HashMap::new();
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "missing password");

        // Invalid password sent
        let body = HashMap::from([("password", "password")]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        test_setup.insert_two_fa().await;
        test_setup.two_fa_always_required(true).await;

        // Missing token
        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        // invalid token
        let token = test_setup.get_invalid_token();
        let body = HashMap::from([("password", TEST_PASSWORD), ("token", &token)]);
        let result = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid email address and/or password and/or token");

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
    }

    #[tokio::test]
    /// Return 400 if device not known
    async fn device_router_user_named_device_delete_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let random_name = gen_random_hex(12);

        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let resp = client
            .delete(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Anon user can't delete a device of another user
    async fn device_router_user_named_device_delete_anon_invalid() {
        let mut test_setup = start_servers().await;

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("password", ANON_PASSWORD)]);
        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .delete(&url)
            .json(&body)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");

        let list_devices = test_setup.query_user_active_devices().await;
        assert_eq!(list_devices.len(), 1);
    }

    #[tokio::test]
    /// Free user, delete device, return 200
    async fn device_router_user_named_device_delete_free_ok() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .delete(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.is_empty());
    }

    #[tokio::test]
    /// Pro use, delete device, return 200
    async fn device_router_user_named_device_delete_ok() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .delete(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.len() == 1);
    }

    #[tokio::test]
    /// Free user, delete device, return 200, no email sent
    async fn device_router_user_named_device_delete_free_email() {
        let mut test_setup = start_servers().await;
        // test_setup.em
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Free).await;

        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let resp = client
            .delete(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let list_devices = test_setup.query_user_active_devices().await;
        assert!(list_devices.is_empty());
    }

    #[tokio::test]
    /// Single device delete, 1 (of 2) message caches removed
    async fn device_router_user_named_device_delete_cache_removed() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let device_01_name = test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 2,
                    client_password: None,
                    device_password: None,
                    structured_data: true,
                    name: None,
                }),
            )
            .await;
        test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 2,
                    client_password: None,
                    device_password: None,
                    structured_data: true,
                    name: None,
                }),
            )
            .await;

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi_01 = connect_async(&url).await;
        assert!(ws_pi_01.is_ok());
        let (mut ws_pi_01, _) = ws_pi_01.unwrap();
        let msg_text = r#"{"data":"ws_pi_01", "cache": true}"#;
        let msg = Message::from(msg_text);
        ws_pi_01.send(msg).await.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Pi, 1).await;

        let ws_pi_02 = connect_async(&url).await;
        assert!(ws_pi_02.is_ok());
        let (mut ws_pi_02, _) = ws_pi_02.unwrap();
        let msg_text = r#"{"data":"ws_pi_02", "cache": true}"#;
        let msg = Message::from(msg_text);
        ws_pi_02.send(msg).await.unwrap();

        // Sleep as inserted on own thread
        sleep!(100);
        let message_caches: Vec<String> = test_setup.redis.keys("cache::message::*").await.unwrap();

        assert_eq!(message_caches.len(), 2);

        let body = HashMap::from([("password", TEST_PASSWORD)]);
        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_01_name
        );
        client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        let message_caches: Vec<String> = test_setup.redis.keys("cache::message::*").await.unwrap();
        assert_eq!(message_caches.len(), 1);
    }

    // *******
    // * GET *
    // *******

    #[tokio::test]
    /// Get list of currently connected clients, timestamp connected & ip_address
    /// Need to test by connecting via websocket!
    async fn device_router_user_named_device_get_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .get(&url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;
        assert!(result.is_array());
    }

    #[tokio::test]
    /// Get list of currently connected clients, timestamp connected & ip_address
    async fn device_router_user_named_device_get_ok() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        let resp = client
            .get(&url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;
        let result = result.as_array().unwrap()[0].as_object().unwrap();
        assert_eq!(result.get("ip").unwrap(), "127.0.0.1");

        let ts = OffsetDateTime::now_utc()
            .to_string()
            .chars()
            .take(10)
            .collect::<String>();
        assert!(result
            .get("timestamp_online")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&ts));
    }

    #[tokio::test]
    /// Get list of currently connected clients, timestamp connected & ip_address
    async fn device_router_user_named_device_get_ok_multiple_connections() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 3,
                    client_password: None,
                    device_password: None,
                    structured_data: false,
                    name: None,
                }),
            )
            .await;

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url_01 = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client_01 = connect_async(&ws_client_url_01).await;
        assert!(ws_client_01.is_ok());
        let ws_client_url_02 = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client_02 = connect_async(&ws_client_url_02).await;
        assert!(ws_client_02.is_ok());
        let ws_client_url_03 = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client_03 = connect_async(&ws_client_url_03).await;
        assert!(ws_client_03.is_ok());

        let resp = client
            .get(&url)
            .header("cookie", authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let result = resp.json::<Response>().await.unwrap().response;
        let resp = result.as_array().unwrap();
        assert_eq!(resp.len(), 3);

        let ts = OffsetDateTime::now_utc()
            .to_string()
            .chars()
            .take(10)
            .collect::<String>();

        let result = resp[0].as_object().unwrap();
        assert_eq!(result.get("ip").unwrap(), "127.0.0.1");

        assert!(result
            .get("timestamp_online")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&ts));

        let result = resp[1].as_object().unwrap();
        assert_eq!(result.get("ip").unwrap(), "127.0.0.1");

        assert!(result
            .get("timestamp_online")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&ts));

        let result = resp[2].as_object().unwrap();
        assert_eq!(result.get("ip").unwrap(), "127.0.0.1");

        assert!(result
            .get("timestamp_online")
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with(&ts));
    }

    #[tokio::test]
    /// Anon user unable to get list of connected clients for test_user device
    async fn device_router_user_named_device_anon_invalid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let ws_pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&ws_pi_url).await;
        assert!(ws_pi.is_ok());

        let ws_client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&ws_client_url).await;
        assert!(ws_client.is_ok());

        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .get(&url)
            .header("cookie", anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    // ****************
    // * PATCH - Pause*
    // ****************

    #[tokio::test]
    // Unauthenticated user unable to access [PATCH] /device/:some_name/pause route
    async fn device_router_user_get_user_patch_pause_unauthenticated() {
        let test_setup = start_servers().await;
        let random_name = gen_random_hex(12);

        let url = format!(
            "{}/authenticated{}/{}/pause",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let client = TestSetup::get_client();

        let resp = client.patch(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Return 400 if device not know
    async fn device_router_user_named_device_patch_pause_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let random_name = gen_random_hex(12);

        let body = HashMap::from([("pause", true)]);

        let url = format!(
            "{}/authenticated{}/{}/pause",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Anon user can't pause the device of another user
    async fn device_router_user_named_device_patch_pause_anon_invalid() {
        let mut test_setup = start_servers().await;

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}/pause",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("pause", true)]);
        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");

        let list_devices = test_setup.query_user_active_devices().await;
        assert_eq!(list_devices.len(), 1);
    }

    #[tokio::test]
    /// Pause device connection valid - need to test it's actually paused, by trying to connect via ws?
    async fn device_router_user_named_device_patch_pause_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        let paused = test_setup.query_user_active_devices().await[0].paused;

        let url = format!(
            "{}/authenticated{}/{}/pause",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("pause", true)]);
        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_ne!(
            test_setup.query_user_active_devices().await[0].paused,
            paused
        );

        let body = HashMap::from([("pause", false)]);
        let resp = client
            .patch(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!test_setup.query_user_active_devices().await[0].paused);
    }

    // ******************
    // * PATCH - Apikey *
    // ******************

    #[tokio::test]
    // Unauthenticated user unable to access [PATCH] /device/:some_name/apikey route
    async fn device_router_user_get_user_patch_api_key_unauthenticated() {
        let test_setup = start_servers().await;
        let random_name = gen_random_hex(12);

        let url = format!(
            "{}/authenticated{}/{}/api_key",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let client = TestSetup::get_client();

        let resp = client.patch(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Return 400 if device not known
    async fn device_router_user_named_device_patch_apikey_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let random_name = gen_random_hex(12);

        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let url = format!(
            "{}/authenticated{}/{}/api_key",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Anon user can't patch the api key of the device of another user
    async fn device_router_user_named_device_patch_api_key_anon_invalid() {
        let mut test_setup = start_servers().await;

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}/api_key",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("password", ANON_PASSWORD)]);
        test_setup.insert_anon_user().await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Refresh a devices api key
    async fn device_router_user_named_device_patch_api_key_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let url = format!(
            "{}/authenticated{}/{}/api_key",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let pre_api_key = test_setup.query_user_active_devices().await[0].clone();

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_ne!(
            test_setup.query_user_active_devices().await[0].api_key_id,
            pre_api_key.api_key_id
        );

        assert_ne!(
            test_setup.query_user_active_devices().await[0].api_key_string,
            pre_api_key.api_key_string
        );
    }

    #[tokio::test]
    // On api key refresh, pi & client connections killed
    async fn device_router_user_get_user_patch_api_key_unauthenticated_connection_killed() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;

        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let url = format!(
            "{}/authenticated{}/{}/api_key",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );
        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(ws_pi.next().await.unwrap().unwrap().is_close());
        assert!(ws_client.next().await.unwrap().unwrap().is_close());
    }

    // ******************
    // * PATCH - Rename *
    // ******************

    #[tokio::test]
    // Unauthenticated user unable to access [PATCH] /device/:some_name/rename route
    async fn device_router_user_get_user_patch_rename_unauthenticated() {
        let test_setup = start_servers().await;
        let random_name = gen_random_hex(12);

        let url = format!(
            "{}/authenticated{}/{}/rename",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let client = TestSetup::get_client();

        let resp = client.patch(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Return 400 if device not know
    async fn device_router_user_named_device_patch_rename_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let random_name = gen_random_hex(12);

        let body = HashMap::from([("new_name", gen_random_hex(12))]);

        let url = format!(
            "{}/authenticated{}/{}/rename",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Free user unable to change device name
    async fn device_router_user_named_device_patch_rename_free_user() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("new_name", gen_random_hex(10))]);

        let url = format!(
            "{}/authenticated{}/{}/rename",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to set name");
    }

    #[tokio::test]
    /// Anon user can't rename the device of another user
    async fn device_router_user_named_device_patch_rename_anon_invalid() {
        let mut test_setup = start_servers().await;

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}/rename",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("new_name", gen_random_hex(12))]);
        test_setup.insert_anon_user().await;
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Pro user unable to change device name to one already in use by same user
    async fn device_router_user_named_device_patch_rename_name_in_use() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name_01 = test_setup.insert_device(&authed_cookie, None).await;
        let device_name_02 = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("new_name", device_name_02)]);

        let url = format!(
            "{}/authenticated{}/{}/rename",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name_01
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Device with given name already exists");
    }

    #[tokio::test]
    /// Pro user able to change name of device
    async fn device_router_user_named_device_patch_rename_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let new_name = gen_random_hex(10);
        let body = HashMap::from([("new_name", new_name)]);

        let pre_device = test_setup.query_user_active_devices().await[0].clone();

        let url = format!(
            "{}/authenticated{}/{}/rename",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let post_device = test_setup.query_user_active_devices().await[0].clone();
        assert_ne!(post_device.device_name_id, pre_device.device_name_id)
    }

    // ***************************
    // * PATCH - Structured data *
    // ***************************

    #[tokio::test]
    // Unauthenticated user unable to access [PATCH] /device/:some_name/structured_data route
    async fn device_router_user_get_user_patch_structured_unauthenticated() {
        let test_setup = start_servers().await;
        let random_name = gen_random_hex(12);

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let client = TestSetup::get_client();

        let resp = client.patch(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Return 400 if device not know
    async fn device_router_user_named_device_patch_structured_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let random_name = gen_random_hex(12);

        let body = HashMap::from([("structured_data", false)]);

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Free user unable to set structured data
    async fn device_router_user_named_device_patch_structured_free_user() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("structured_data", true)]);

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to set name");
    }

    #[tokio::test]
    /// Anon user can't rename the device of another user
    async fn device_router_user_named_device_patch_structured_anon_invalid() {
        let mut test_setup = start_servers().await;

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("structured_data", true)]);
        test_setup.insert_anon_user().await;
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Pro user able to toggle structured data on and off
    async fn device_router_user_named_device_patch_structured_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("structured_data", true)]);

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(test_setup.query_user_active_devices().await[0].structured_data);

        let body = HashMap::from([("structured_data", false)]);

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!test_setup.query_user_active_devices().await[0].structured_data);
    }

    #[tokio::test]
    /// On structured data toggled off, all connected clients and pi are disconnected, message cache removed
    async fn device_router_user_named_device_patch_structured_off_connections_killed() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 2,
                    client_password: None,
                    device_password: None,
                    structured_data: true,
                    name: None,
                }),
            )
            .await;

        let body = HashMap::from([("structured_data", false)]);

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        // Seed the message cache, before clients connect!
        let msg_text = r#"{"data":"ws_pi_01", "cache": true}"#;
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client_01 = connect_async(&url).await;
        assert!(ws_client_01.is_ok());
        let (mut ws_client_01, _) = ws_client_01.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client_02 = connect_async(&url).await;
        assert!(ws_client_02.is_ok());
        let (mut ws_client_02, _) = ws_client_02.unwrap();

        // Sleep as inserted on own thread
        sleep!(100);
        let message_caches: Vec<String> = test_setup.redis.keys("cache::message::*").await.unwrap();

        assert_eq!(message_caches.len(), 1);

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        assert!(ws_pi.next().await.unwrap().unwrap().is_close());
        assert!(ws_client_01.next().await.unwrap().unwrap().is_close());
        assert!(ws_client_02.next().await.unwrap().unwrap().is_close());

        let message_caches: Vec<String> = test_setup.redis.keys("cache::message::*").await.unwrap();

        assert!(message_caches.is_empty());
    }

    #[tokio::test]
    /// On structured data toggled on, all connected clients and pi are disconnected
    async fn device_router_user_named_device_patch_structured_on_connections_killed() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 2,
                    client_password: None,
                    device_password: None,
                    structured_data: false,
                    name: None,
                }),
            )
            .await;

        let body = HashMap::from([("structured_data", true)]);

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client_01 = connect_async(&url).await;
        assert!(ws_client_01.is_ok());
        let (mut ws_client_01, _) = ws_client_01.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client_02 = connect_async(&url).await;
        assert!(ws_client_02.is_ok());
        let (mut ws_client_02, _) = ws_client_02.unwrap();

        let url = format!(
            "{}/authenticated{}/{}/structured_data",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        assert!(ws_pi.next().await.unwrap().unwrap().is_close());
        assert!(ws_client_01.next().await.unwrap().unwrap().is_close());
        assert!(ws_client_02.next().await.unwrap().unwrap().is_close());
    }

    // *********************
    // * PATCH - Max client *
    // **********************

    #[tokio::test]
    // Unauthenticated user unable to access [PATCH] /device/:some_name/max_clients route
    async fn device_router_user_get_user_patch_max_clients_unauthenticated() {
        let test_setup = start_servers().await;
        let random_name = gen_random_hex(12);

        let url = format!(
            "{}/authenticated{}/{}/max_clients",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let client = TestSetup::get_client();

        let resp = client.patch(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Return 400 if device not know
    async fn device_router_user_named_device_patch_max_clients_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let random_name = gen_random_hex(12);

        let body = HashMap::from([("max_clients", 10)]);

        let url = format!(
            "{}/authenticated{}/{}/max_clients",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Free user unable to change max_clients
    async fn device_router_user_named_device_patch_max_clients_free_user() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("max_clients", 1)]);

        let url = format!(
            "{}/authenticated{}/{}/max_clients",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to change max clients");
    }

    #[tokio::test]
    /// Anon user can't change the max_clients of the device of another user
    async fn device_router_user_named_device_patch_max_clients_anon_invalid() {
        let mut test_setup = start_servers().await;

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}/max_clients",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([("max_clients", 12)]);
        test_setup.insert_anon_user().await;
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Pro user able to change max_clients
    async fn device_router_user_named_device_patch_max_clients_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([("max_clients", 12)]);

        let url = format!(
            "{}/authenticated{}/{}/max_clients",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            test_setup.query_user_active_devices().await[0].max_clients,
            12
        );
    }

    // *******************
    // * PATCH - Password *
    // ********************

    #[tokio::test]
    // Unauthenticated user unable to access [DELETE, POST] /device/:some_name/max_clients route
    async fn device_router_user_get_user_patch_password_unauthenticated() {
        let test_setup = start_servers().await;
        let random_name = gen_random_hex(12);

        let url = format!(
            "{}/authenticated{}/{}/password",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let client = TestSetup::get_client();

        let resp = client.delete(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");

        let resp = client.post(url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Invalid Authentication");
    }

    #[tokio::test]
    // Return 400 if device not know
    async fn device_router_user_named_device_patch_password_unknown_device() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let random_name = gen_random_hex(12);

        let body = HashMap::from([
            ("device_password", gen_random_hex(12)),
            ("client_password", gen_random_hex(12)),
        ]);

        let url = format!(
            "{}/authenticated{}/{}/password",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            random_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Free user unable to set device passwords
    async fn device_router_user_named_device_patch_password_free_user() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([
            ("device_password", gen_random_hex(12)),
            ("client_password", gen_random_hex(12)),
        ]);

        let url = format!(
            "{}/authenticated{}/{}/password",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Free users are unable to set device password");
    }

    #[tokio::test]
    /// Anon user can't change the passwords of the device of another user
    async fn device_router_user_named_device_patch_password_anon_invalid() {
        let mut test_setup = start_servers().await;

        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let url = format!(
            "{}/authenticated{}/{}/password",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let body = HashMap::from([
            ("device_password", gen_random_hex(12)),
            ("client_password", gen_random_hex(12)),
        ]);
        test_setup.insert_anon_user().await;
        test_setup.change_anon_user_level(UserLevel::Pro).await;
        let anon_user_cookie = test_setup.anon_user_cookie().await;

        let result = client
            .patch(&url)
            .json(&body)
            .header("cookie", &anon_user_cookie.unwrap())
            .send()
            .await
            .unwrap();

        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result, "Unknown device");
    }

    #[tokio::test]
    /// Pro user able to change device & client password
    async fn device_router_user_named_device_patch_password_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;

        let body = HashMap::from([
            ("device_password", gen_random_hex(12)),
            ("client_password", gen_random_hex(12)),
        ]);

        let url = format!(
            "{}/authenticated{}/{}/password",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .patch(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(test_setup.query_user_active_devices().await[0]
            .device_password_id
            .is_some(),);
        assert!(test_setup.query_user_active_devices().await[0]
            .client_password_id
            .is_some(),);
    }

    #[tokio::test]
    /// Pro user able to toggle structured data on and off
    async fn device_router_user_named_device_delete_password_valid() {
        let mut test_setup = start_servers().await;
        let client = TestSetup::get_client();
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        let device_name = test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 1,
                    client_password: Some("this_is_a_password".to_owned()),
                    device_password: Some("This_is_another_password".to_owned()),
                    structured_data: false,
                    name: None,
                }),
            )
            .await;

        let body = HashMap::from([("password", TEST_PASSWORD)]);

        let url = format!(
            "{}/authenticated{}/{}/password",
            api_base_url(&test_setup.app_env),
            DeviceRoutes::Base.addr(),
            device_name
        );

        let resp = client
            .delete(&url)
            .header("cookie", &authed_cookie)
            .json(&body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(test_setup.query_user_active_devices().await[0]
            .device_password_id
            .is_none(),);
        assert!(test_setup.query_user_active_devices().await[0]
            .client_password_id
            .is_none(),);
    }
}

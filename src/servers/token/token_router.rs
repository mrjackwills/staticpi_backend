use axum::{
    body::Bytes,
    extract::{OriginalUri, State},
    http::{StatusCode, Uri},
    routing::{get, post},
    Router,
};

use redis::aio::ConnectionManager;
use ulid::Ulid;

use crate::{
    api_error::ApiError,
    argon,
    connections::ConnectionType,
    database::{
        access_token::AccessToken,
        device::{ModelDevicePasswordHash, ModelWsDevice},
        ip_user_agent::ModelUserAgentIp,
        new_types::{ApiKey, DeviceId},
        rate_limit::RateLimit,
    },
    define_routes,
    helpers::calc_uptime,
    servers::{check_monthly_bandwidth, ApiRouter, ApplicationState, StatusOJ},
    user_io::{incoming_json::ij, outgoing_json::oj},
};

define_routes! {
    TokenRoutes,
    "/",
    Online => "online",
    Client => "client",
    Pi => "pi"
}

pub struct TokenRouter;

impl ApiRouter for TokenRouter {
    fn create_router(_state: &ApplicationState) -> Router<ApplicationState> {
        Router::new()
            .route(&TokenRoutes::Online.addr(), get(Self::online_get))
            .route(&TokenRoutes::Client.addr(), post(Self::auth_post))
            .route(&TokenRoutes::Pi.addr(), post(Self::auth_post))
    }
}

impl TokenRouter {
    #[allow(clippy::unused_async)]
    async fn online_get(
        State(state): State<ApplicationState>,
    ) -> Result<StatusOJ<oj::Online>, ApiError> {
        Ok((
            StatusCode::OK,
            oj::OutgoingJson::new(oj::Online {
                uptime: calc_uptime(state.start_time),
                api_version: env!("CARGO_PKG_VERSION").into(),
            }),
        ))
    }

    /// Insert an access token into redis
    async fn create_access_token(
        redis: &mut ConnectionManager,
        device_id: DeviceId,
        device_type: ConnectionType,
        req: &ModelUserAgentIp,
    ) -> Result<Ulid, ApiError> {
        let ulid = Ulid::new();
        AccessToken::new(device_id, req, device_type)
            .insert(redis, ulid)
            .await?;
        Ok(ulid)
    }

    /// Check if device has a password, validate password, insert token into redis, return ulid
    async fn validate_key_password(
        api_key: ApiKey,
        password: Option<&str>,
        useragent_ip: ModelUserAgentIp,
        device_type: ConnectionType,
        state: &ApplicationState,
    ) -> Result<Option<Ulid>, ApiError> {
        let mut output = None;

        let mut redis = state.redis();
        // if is Err, return empty response?
        RateLimit::from(&api_key).check(&mut redis).await?;
        if let Some(device) = ModelWsDevice::get_by_api_key(&state.postgres, &api_key).await? {
            let password_id = match device_type {
                ConnectionType::Client => device.client_password_id,
                ConnectionType::Pi => device.device_password_id,
            };

            if state
                .connections
                .lock()
                .await
                .max_connected(&device, device_type)
                || RateLimit::from(&device).limited_ttl(&mut redis).await? > 0
                || RateLimit::from(&api_key).limited_ttl(&mut redis).await? > 0
                || check_monthly_bandwidth(&state.postgres, &mut redis, &device)
                    .await
                    .is_err()
            {
                return Ok(None);
            }

            if let Some(id) = password_id {
                if let Some(device_hash) = ModelDevicePasswordHash::get(&state.postgres, id).await?
                {
                    if argon::verify_password(password.map_or("", |f| f), device_hash.password_hash)
                        .await?
                    {
                        output = Some(
                            Self::create_access_token(
                                &mut redis,
                                device.device_id,
                                device_type,
                                &useragent_ip,
                            )
                            .await?,
                        );
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            } else {
                output = Some(
                    Self::create_access_token(
                        &mut redis,
                        device.device_id,
                        device_type,
                        &useragent_ip,
                    )
                    .await?,
                );
            }
        }
        Ok(output)
    }

    /// Handle the rate limiting, body verification, key & password checking
    async fn _auth_post(
        useragent_ip: ModelUserAgentIp,
        uri: Uri,
        state: &ApplicationState,
        body: Bytes,
    ) -> Result<StatusOJ<Ulid>, ApiError> {
        let body = serde_json::from_slice::<ij::AuthKeyPassword>(&body)?;
        let device_type = ConnectionType::try_from(uri)?;
        let api_key = ApiKey::from(body.key.as_str());
        (Self::validate_key_password(
            api_key,
            body.password.as_deref(),
            useragent_ip,
            device_type,
            state,
        )
        .await?)
            .map_or(Err(ApiError::AccessToken), |ulid| {
                Ok((StatusCode::OK, oj::OutgoingJson::new(ulid)))
            })
    }

    /// Catch all errors, so that the only error that the user sees is an AccessToken error or a Ratelimit error
    async fn auth_post(
        useragent_ip: ModelUserAgentIp,
        OriginalUri(uri): OriginalUri,
        State(state): State<ApplicationState>,
        body: Bytes,
    ) -> Result<StatusOJ<Ulid>, ApiError> {
        match Self::_auth_post(useragent_ip, uri, &state, body).await {
            Ok(response) => Ok(response),
            Err(e) => match e {
                ApiError::RateLimited(ttl) => Err(ApiError::RateLimited(ttl)),
                _ => Err(ApiError::AccessToken),
            },
        }
    }
}

/// Use reqwest to test against real server
// cargo watch -q -c -w src/ -x 'test token_server -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {
    use crate::{
        connections::ConnectionType,
        database::{access_token::AccessToken, user_level::UserLevel, RedisKey},
        helpers::gen_random_hex,
        servers::test_setup::{start_servers, token_base_url, Response, TestSetup},
        sleep,
        user_io::incoming_json::ij::DevicePost,
    };
    use redis::AsyncCommands;
    use reqwest::StatusCode;
    use std::collections::HashMap;
    use ulid::Ulid;

    #[tokio::test]
    /// base route returns basic server stats
    async fn token_server_online() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();
        sleep!(1000);
        let result = client
            .get(&format!("{}/online", token_base_url(&test_setup.app_env)))
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(result["uptime"], 1);
    }

    #[tokio::test]
    /// small ban rate limit when using ip as a key
    async fn token_server_rate_limit_small_ip() {
        let test_setup = start_servers().await;

        let url = format!("{}/online", token_base_url(&test_setup.app_env));
        for _ in 1..=44 {
            reqwest::get(&url).await.unwrap();
            // Can delete key each loop when testing api_key rate limit
        }

        // 45th request is fine
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert!(result.get("uptime").is_some());

        // 45+ request is rate limited
        let resp = reqwest::get(url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        let messages = ["rate limited for 60 seconds", "rate limited for 59 seconds"];
        assert!(messages.contains(&result.as_str().unwrap()));
    }

    #[tokio::test]
    /// small ban rate limit when using api_key as a key
    async fn token_server_rate_limit_small_api_key() {
        let mut test_setup = start_servers().await;

        let url = format!("{}/online", token_base_url(&test_setup.app_env));
        for _ in 1..=44 {
            reqwest::get(&url).await.unwrap();
            test_setup
                .redis
                .del::<&str, ()>("ratelimit::ip::*")
                .await
                .unwrap();
        }

        // 45 request is fine
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert!(result.get("uptime").is_some());

        // 45+ request is rate limited
        let resp = reqwest::get(url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        let messages = ["rate limited for 60 seconds", "rate limited for 59 seconds"];
        assert!(messages.contains(&result.as_str().unwrap()));
    }

    #[tokio::test]
    /// big ban rate limit when using ip as a key
    async fn token_server_rate_limit_big() {
        let test_setup = start_servers().await;

        let url = format!("{}/online", token_base_url(&test_setup.app_env));
        for _ in 1..=89 {
            reqwest::get(&url).await.unwrap();
        }

        // 90th request is rate limited
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        let messages = ["rate limited for 60 seconds", "rate limited for 59 seconds"];
        assert!(messages.contains(&result.as_str().unwrap()));

        // 90+ request is rate limited for 300 seconds
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "rate limited for 300 seconds");

        // any further requests resets the ban to 300 again
        sleep!(1000);
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result, "rate limited for 300 seconds");
    }

    #[tokio::test]
    /// Random api_keys return 400 bad requests
    async fn token_server_random_hex() {
        let test_setup = start_servers().await;
        let client = TestSetup::get_client();

        // Client
        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", gen_random_hex(128))]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        // pi
        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", gen_random_hex(128))]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    /// Return ulid token for free user, check
    async fn token_server_free_client_ok() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        let device = test_setup.query_user_active_devices().await[0].clone();

        let client = TestSetup::get_client();

        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        let ulid = Ulid::from_string(result.as_str().unwrap()).unwrap();

        let access_token: Option<AccessToken> = test_setup
            .redis
            .hget(RedisKey::AccessToken(&ulid).to_string(), "data")
            .await
            .unwrap();
        assert!(access_token.is_some());
        let access_token = access_token.unwrap();
        assert_eq!(access_token.device_id, device.device_id);
        assert_eq!(access_token.device_type, ConnectionType::Client);

        let ttl: usize = test_setup
            .redis
            .ttl(RedisKey::AccessToken(&ulid).to_string())
            .await
            .unwrap();
        assert_eq!(ttl, 20);
    }

    #[tokio::test]
    /// Return ulid token for free user, check
    async fn token_server_free_pi_ok() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        let device = test_setup.query_user_active_devices().await[0].clone();

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        let ulid = Ulid::from_string(result.as_str().unwrap()).unwrap();

        let access_token: Option<AccessToken> = test_setup
            .redis
            .hget(RedisKey::AccessToken(&ulid).to_string(), "data")
            .await
            .unwrap();
        assert!(access_token.is_some());
        let access_token = access_token.unwrap();

        assert_eq!(access_token.device_id, device.device_id);
        assert_eq!(access_token.device_type, ConnectionType::Pi);

        let ttl: usize = test_setup
            .redis
            .ttl(RedisKey::AccessToken(&ulid).to_string())
            .await
            .unwrap();
        assert_eq!(ttl, 20);
    }

    #[tokio::test]
    /// If no password provided, return error
    async fn token_server_pro_password_client_invalid_no_password() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let password = gen_random_hex(20);
        let device = DevicePost {
            max_clients: 1,
            client_password: Some(password.clone()),
            device_password: Some(password),
            structured_data: false,
            name: None,
        };
        test_setup.insert_device(&authed_cookie, Some(device)).await;

        let device = test_setup.query_user_active_devices().await[0].clone();

        let client = TestSetup::get_client();

        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// If no password provided, return error
    async fn token_server_pro_password_pi_invalid_no_password() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let password = gen_random_hex(20);
        let device = DevicePost {
            max_clients: 1,
            client_password: Some(password.clone()),
            device_password: Some(password),
            structured_data: false,
            name: None,
        };
        test_setup.insert_device(&authed_cookie, Some(device)).await;

        let device = test_setup.query_user_active_devices().await[0].clone();

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Use device password in client route
    async fn token_server_pro_password_client_invalid_wrong_password() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let client_password = gen_random_hex(20);
        let device_password = gen_random_hex(20);
        let device = DevicePost {
            max_clients: 1,
            client_password: Some(client_password.clone()),
            device_password: Some(device_password.clone()),
            structured_data: false,
            name: None,
        };
        test_setup.insert_device(&authed_cookie, Some(device)).await;

        let device = test_setup.query_user_active_devices().await[0].clone();

        let client = TestSetup::get_client();

        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([
            ("key", device.api_key_string),
            ("password", device_password),
        ]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Use client password in pi route
    async fn token_server_pro_password_pi_invalid_wrong_password() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let client_password = gen_random_hex(20);
        let device_password = gen_random_hex(20);
        let device = DevicePost {
            max_clients: 1,
            client_password: Some(client_password.clone()),
            device_password: Some(device_password.clone()),
            structured_data: false,
            name: None,
        };
        test_setup.insert_device(&authed_cookie, Some(device)).await;

        let device = test_setup.query_user_active_devices().await[0].clone();

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([
            ("key", device.api_key_string),
            ("password", client_password),
        ]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Free user pi unable to get auth access token if monthly bandwidth limit reached
    async fn token_server_free_pi_max_bandwidth() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .insert_bandwidth(device.device_id, 5_000_000, ConnectionType::Pi, true)
            .await;
        // ModelHourlyBandwidth::insert(
        //     DeviceType::Pi,
        //     &test_setup.postgres,
        //     &mut test_setup.redis,
        //     device.device_id,
        //     5_000_000,
        //     true,
        // );

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Free user client unable to get auth access token if monthly bandwidth limit reached
    async fn token_server_free_client_max_bandwidth() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .insert_bandwidth(device.device_id, 5_000_000, ConnectionType::Client, true)
            .await;

        // ModelHourlyBandwidth::insert(
        //     DeviceType::Client,
        //     &test_setup.postgres,
        //     &mut test_setup.redis,
        //     device.device_id,
        //     5_000_000,
        //     true,
        // );

        let client = TestSetup::get_client();

        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Pro user pi unable to get auth access token if monthly bandwidth limit reached
    async fn token_server_pro_pi_max_bandwidth() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .insert_bandwidth(device.device_id, 10_000_000_000, ConnectionType::Pi, true)
            .await;

        // ModelHourlyBandwidth::insert(
        //     DeviceType::Pi,
        //     &test_setup.postgres,
        //     &mut test_setup.redis,
        //     device.device_id,
        //     10_000_000_000,
        //     true,
        // );

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Pro user client unable to get auth access token if monthly bandwidth limit reached
    async fn token_server_pro_client_max_bandwidth() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .insert_bandwidth(
                device.device_id,
                10_000_000_000,
                ConnectionType::Client,
                true,
            )
            .await;

        // ModelHourlyBandwidth::insert(
        //     DeviceType::Client,
        //     &test_setup.postgres,
        //     &mut test_setup.redis,
        //     device.device_id,
        //     10_000_000_000,
        //     true,
        // );

        let client = TestSetup::get_client();

        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Free user pi unable to get auth access token if currently rate limited
    async fn token_server_free_pi_rate_limited() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .redis
            .set::<String, usize, ()>(
                format!("ratelimit::ws_free::{}", test_setup.get_user_id().get()),
                30,
            )
            .await
            .unwrap();

        test_setup
            .redis
            .expire::<String, ()>(
                format!("ratelimit::ws_free::{}", test_setup.get_user_id().get()),
                60,
            )
            .await
            .unwrap();

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Free user client unable to get auth access token if currently rate limited
    async fn token_server_free_client_rate_limited() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .redis
            .set::<String, usize, ()>(
                format!("ratelimit::ws_free::{}", test_setup.get_user_id().get()),
                30,
            )
            .await
            .unwrap();

        test_setup
            .redis
            .expire::<String, ()>(
                format!("ratelimit::ws_free::{}", test_setup.get_user_id().get()),
                60,
            )
            .await
            .unwrap();

        let client = TestSetup::get_client();

        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Pro user pi unable to get auth access token if currently rate limited
    async fn token_server_pro_pi_rate_limited() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .redis
            .set::<String, usize, ()>(
                format!("ratelimit::ws_pro::{}", device.device_id.get()),
                300,
            )
            .await
            .unwrap();

        test_setup
            .redis
            .expire::<String, ()>(format!("ratelimit::ws_pro::{}", device.device_id.get()), 60)
            .await
            .unwrap();

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    /// Pro user client unable to get auth access token if currently rate limited
    async fn token_server_pro_client_rate_limited() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = test_setup.query_user_active_devices().await[0].clone();

        test_setup
            .redis
            .set::<String, usize, ()>(
                format!("ratelimit::ws_pro::{}", device.device_id.get()),
                300,
            )
            .await
            .unwrap();

        test_setup
            .redis
            .expire::<String, ()>(format!("ratelimit::ws_pro::{}", device.device_id.get()), 60)
            .await
            .unwrap();

        let client = TestSetup::get_client();

        let url = format!("{}/client", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);

        let keys: Vec<String> = test_setup.redis.keys("access_token::*").await.unwrap();
        assert!(keys.is_empty());
    }
}

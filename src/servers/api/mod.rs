pub mod authentication;
mod routers;

use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

use axum::{Extension, Router, http::HeaderValue, middleware};
use std::net::SocketAddr;

use crate::{
    C, S,
    api_error::ApiError,
    parse_env::RunMode,
    servers::{ApplicationState, fallback, get_api_version, parse_addr, rate_limiting},
};

use super::{ApiRouter, Serve, ServeData, shutdown_signal};

pub struct ApiServer;

impl Serve for ApiServer {
    /// Serve the `api_application`
    async fn serve(serve_data: ServeData) -> Result<(), ApiError> {
        let prefix = get_api_version();
        let auth_prefix = format!("{prefix}/authenticated");

        let cors_url = match serve_data.app_env.run_mode {
            RunMode::Development => S!("http://127.0.0.1:8002"),
            RunMode::Production => format!("https://www.{}", serve_data.app_env.domain),
        };

        let cors = CorsLayer::new()
            .allow_methods([
                axum::http::Method::DELETE,
                axum::http::Method::GET,
                axum::http::Method::OPTIONS,
                axum::http::Method::PATCH,
                axum::http::Method::POST,
                axum::http::Method::PUT,
            ])
            .allow_credentials(true)
            .allow_headers(vec![
                axum::http::header::ACCEPT,
                axum::http::header::ACCEPT_LANGUAGE,
                axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                axum::http::header::AUTHORIZATION,
                axum::http::header::CACHE_CONTROL,
                axum::http::header::CONTENT_LANGUAGE,
                axum::http::header::CONTENT_TYPE,
            ])
            .allow_origin(
                cors_url
                    .parse::<HeaderValue>()
                    .map_err(|i| ApiError::Internal(i.to_string()))?,
            );

        let addr = parse_addr(&serve_data.app_env.api_host, serve_data.app_env.api_port)?;
        let server_name = serve_data.server_name;
        server_name.show_name(&addr);

        let application_state = ApplicationState::new(serve_data);

        let router_authenticated = routers::admin::AdminRouter::create_router(&application_state)
            .merge(routers::device::DeviceRouter::create_router(
                &application_state,
            ))
            .merge(routers::user::UserRouter::create_router(&application_state));

        let router_incognito =
            routers::incognito::IncognitoRouter::create_router(&application_state);

        let app = Router::new()
            .nest(&prefix, router_incognito)
            .nest(&auth_prefix, router_authenticated)
            .fallback(fallback)
            .layer(
                ServiceBuilder::new()
                    .layer(cors)
                    .layer(Extension(C!(application_state.cookie_key)))
                    .layer(middleware::from_fn_with_state(
                        C!(application_state),
                        rate_limiting,
                    )),
            )
            .with_state(application_state);

        match axum::serve(
            tokio::net::TcpListener::bind(&addr).await?,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal(server_name))
        .await
        {
            Ok(()) => Ok(()),
            Err(_) => Err(ApiError::Internal(S!("api_server"))),
        }
    }
}

// http tests - ran via actual requests to a (local) server
// cargo watch -q -c -w src/ -x 'test http_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used)]
pub mod api_tests {

    use fred::interfaces::KeysInterface;
    use rand::{Rng, distributions::Alphanumeric};
    use reqwest::StatusCode;

    use crate::S;
    use crate::servers::get_api_version;
    use crate::servers::test_setup::{
        RATELIMIT_REGEX, RATELIMIT_REGEX_BIG, Response, TestSetup, api_base_url, start_servers,
    };

    pub const EMAIL_BODY_LOCATION: &str = "/ramdrive/staticpi/email_body.txt";
    pub const EMAIL_HEADERS_LOCATION: &str = "/ramdrive/staticpi/email_headers.txt";

    #[test]
    fn http_mod_get_api_version() {
        assert_eq!(get_api_version(), S!("/v0"));
    }

    #[tokio::test]
    async fn http_mod_get_unknown() {
        let test_setup = start_servers().await;

        let version = get_api_version();

        let random_route: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        let url = format!("{}/{}", api_base_url(&test_setup.app_env), random_route);
        let resp = reqwest::get(url).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let result = resp.json::<Response>().await.unwrap().response;

        assert_eq!(
            result,
            format!("unknown endpoint: {version}/{random_route}")
        );
    }

    #[tokio::test]
    /// request not rate limited, but points == number request, and ttl 60
    async fn http_mod_rate_limit() {
        let test_setup = start_servers().await;

        let url = format!("{}/incognito/online", api_base_url(&test_setup.app_env));
        for _ in 1..=20 {
            reqwest::get(&url).await.unwrap();
        }

        let count: u64 = test_setup
            .redis
            .get("ratelimit::ip::127.0.0.1")
            .await
            .unwrap();
        let ttl: u64 = test_setup
            .redis
            .ttl("ratelimit::ip::127.0.0.1")
            .await
            .unwrap();
        assert_eq!(count, 20);
        assert!([59, 60].contains(&ttl));
    }

    #[tokio::test]
    /// rate limit when using ip as a key
    async fn http_mod_rate_limit_small_unauthenticated() {
        let test_setup = start_servers().await;

        let url = format!("{}/incognito/online", api_base_url(&test_setup.app_env));
        for _ in 1..=44 {
            reqwest::get(&url).await.unwrap();
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
        assert!(RATELIMIT_REGEX.is_match(result.as_str().unwrap()));
    }

    #[tokio::test]
    /// rate limit when using user email address as a key
    async fn http_mod_rate_limit_small_authenticated() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        let client = TestSetup::get_client();

        let url = format!("{}/incognito/online", api_base_url(&test_setup.app_env));
        for _ in 1..=149 {
            client
                .get(&url)
                .header("cookie", &authed_cookie)
                .send()
                .await
                .unwrap();
        }

        let points: u64 = test_setup
            .redis
            .get(format!(
                "ratelimit::user::{}",
                test_setup.get_user_id().get()
            ))
            .await
            .unwrap();
        assert_eq!(points, 149);

        // 150 request is fine
        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let result = resp.json::<Response>().await.unwrap().response;
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert!(result.get("uptime").is_some());

        // 150+ request is rate limited
        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;

        assert!(RATELIMIT_REGEX.is_match(result.as_str().unwrap()));
    }

    #[tokio::test]
    async fn http_mod_rate_limit_big_unauthenticated() {
        let test_setup = start_servers().await;

        let url = format!("{}/incognito/online", api_base_url(&test_setup.app_env));
        for _ in 1..=89 {
            reqwest::get(&url).await.unwrap();
        }

        // 90th request is rate limited
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        assert!(RATELIMIT_REGEX.is_match(result.as_str().unwrap()));

        // 90+ request is rate limited for 300 seconds
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        assert!(RATELIMIT_REGEX_BIG.is_match(result.as_str().unwrap()));
    }

    #[tokio::test]
    async fn http_mod_rate_limit_big_authenticated() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        let client = TestSetup::get_client();

        let url = format!("{}/incognito/online", api_base_url(&test_setup.app_env));

        for _ in 1..=299 {
            client
                .get(&url)
                .header("cookie", &authed_cookie)
                .send()
                .await
                .unwrap();
        }

        let points: u64 = test_setup
            .redis
            .get(format!(
                "ratelimit::user::{}",
                test_setup.get_user_id().get()
            ))
            .await
            .unwrap();
        assert_eq!(points, 299);

        // 300th request is rate limited for ~ ONE MINUTE
        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        assert!(RATELIMIT_REGEX.is_match(result.as_str().unwrap()));

        // 300+ request is rate limited for 300 seconds
        let resp = client
            .get(&url)
            .header("cookie", &authed_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let result = resp.json::<Response>().await.unwrap().response;
        assert!(RATELIMIT_REGEX_BIG.is_match(result.as_str().unwrap()));
    }
}

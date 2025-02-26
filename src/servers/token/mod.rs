use tower_http::cors::{Any, CorsLayer};

use axum::{Router, http::Method, middleware};
use std::net::SocketAddr;
use tower::ServiceBuilder;

use crate::{
    C, ServeData,
    api_error::ApiError,
    servers::{ApplicationState, parse_addr, rate_limiting},
};

use self::token_router::TokenRouter;

use super::{ApiRouter, Serve, shutdown_signal};
mod token_router;

pub struct TokenServer;

async fn token_fallback() -> Result<(), ApiError> {
    Err(ApiError::AccessToken)
}

impl Serve for TokenServer {
    async fn serve(serve_data: ServeData) -> Result<(), ApiError> {
        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any)
            .allow_origin(Any);

        let addr = parse_addr(&serve_data.app_env.api_host, serve_data.app_env.auth_port)?;
        let server_name = serve_data.server_name;
        server_name.show_name(&addr);

        let application_state = ApplicationState::new(serve_data);

        let routes = TokenRouter::create_router(&application_state);

        let app = Router::new()
            .merge(routes)
            .fallback(token_fallback)
            .layer(
                ServiceBuilder::new()
                    .layer(cors)
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
            Err(_) => Err(ApiError::Internal(format!("bind server::{server_name}"))),
        }
    }
}

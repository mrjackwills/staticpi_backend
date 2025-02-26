use tower_http::cors::{Any, CorsLayer};

use axum::{Router, http::Method, middleware};
use std::net::SocketAddr;
use tower::ServiceBuilder;

use crate::{
    C, ServeData,
    api_error::ApiError,
    servers::{ApplicationState, fallback, parse_addr, rate_limiting},
};

use self::ws_router::WsRouter;

pub use self::ws_router::HandlerData;

use super::{ApiRouter, Serve, shutdown_signal};
mod ws_router;

pub struct WsServer;

impl Serve for WsServer {
    /// Serve the `ws_application`
    async fn serve(serve_data: ServeData) -> Result<(), ApiError> {
        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any)
            .allow_origin(Any);

        let addr = parse_addr(&serve_data.app_env.api_host, serve_data.app_env.ws_port)?;
        let server_name = serve_data.server_name;
        server_name.show_name(&addr);

        let application_state = ApplicationState::new(serve_data);

        let app = Router::new()
            .merge(WsRouter::create_router(&application_state))
            .fallback(fallback)
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

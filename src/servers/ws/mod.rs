use tower_http::cors::{Any, CorsLayer};

use axum::{async_trait, middleware, Router, http::Method};
use std::net::SocketAddr;
use tower::ServiceBuilder;

use crate::{
    api_error::ApiError,
    servers::{fallback, parse_addr, rate_limiting, ApplicationState},
    ServeData,
};

use self::ws_router::WsRouter;

pub use self::ws_router::HandlerData;

use super::{ApiRouter, Serve};
mod ws_router;

pub struct WsServer;

#[async_trait]
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
                        application_state.clone(),
                        rate_limiting,
                    )),
            )
            .with_state(application_state);

			match axum::serve(
				tokio::net::TcpListener::bind(&addr).await?,
				app.into_make_service_with_connect_info::<SocketAddr>(),
			)
			.await
			{
				Ok(()) => Ok(()),
				Err(_) => Err(ApiError::Internal(format!("bind server::{server_name}")))
			}


        // if let Err(e) = axum::Server::bind(&addr)
        //     .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        //     .with_graceful_shutdown(shutdown_signal(&server_name))
        //     .await
        // {
        //     error!("{e:?}");
        //     return Err(ApiError::Internal(format!("bind server::{server_name}")));
        // }
        // Ok(())
    }
}

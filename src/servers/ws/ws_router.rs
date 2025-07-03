use std::net::IpAddr;

use axum::{
    Router,
    extract::{
        OriginalUri, State, WebSocketUpgrade,
        ws::{Message, Utf8Bytes, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use fred::clients::Pool;
use futures::{SinkExt, StreamExt, TryStreamExt};

use sqlx::PgPool;
use ulid::Ulid;

use crate::{
    C, S,
    api_error::ApiError,
    connections::{AMConnections, ConnectionType, SendMessage, WsSender},
    database::{
        access_token::AccessToken,
        connection::ModelConnection,
        device::ModelWsDevice,
        hourly_bandwidth::ModelHourlyBandwidth,
        ip_user_agent::ModelUserAgentIp,
        message_cache::MessageCache,
        new_types::{ConnectionId, DeviceId},
        rate_limit::RateLimit,
    },
    define_routes,
    helpers::calc_uptime,
    servers::{ApiRouter, ApplicationState, check_monthly_bandwidth},
    user_io::{
        incoming_json::ij,
        outgoing_json::oj,
        ws_message::wm::{self, ClientBody, PiBody},
    },
};

const DEFAULT_BUFFER: usize = 1024 * 1024;

define_routes! {
    WsRoutes,
    "/",
    Online => "online",
    Client => "client/{access_token}",
    Pi => "pi/{access_token}"
}

// Measure message size in bytes
/// TODO check for this with next clippy version
#[allow(clippy::missing_const_for_fn)]
pub fn get_message_size(msg: &Message) -> usize {
    match msg {
        Message::Text(data) => data.len(),
        Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.len(),
        Message::Close(_) => 0,
    }
}

pub struct HandlerData<'a> {
    pub connection_id: ConnectionId,
    pub connections: &'a AMConnections,
    pub device_type: ConnectionType,
    pub device: &'a ModelWsDevice,
    pub limiter: &'a RateLimit,
    pub msg_size: usize,
    pub postgres: &'a PgPool,
    pub redis: &'a Pool,
    pub ulid: Ulid,
}
impl<'a> HandlerData<'a> {
    /// TODO check for this with next clippy version
    #[allow(clippy::missing_const_for_fn)]
    fn new(
        connection_id: ConnectionId,
        device_type: ConnectionType,
        device: &'a ModelWsDevice,
        limiter: &'a RateLimit,
        state: &'a ApplicationState,
        ulid: Ulid,
    ) -> Self {
        Self {
            connection_id,
            connections: &state.connections,
            device_type,
            device,
            limiter,
            msg_size: 0,
            postgres: &state.postgres,
            redis: &state.redis,
            ulid,
        }
    }
}

pub struct WsRouter;

impl ApiRouter for WsRouter {
    fn create_router(_state: &ApplicationState) -> Router<ApplicationState> {
        Router::new()
            .route(&WsRoutes::Online.addr(), get(Self::online_get))
            .route(&WsRoutes::Pi.addr(), get(Self::ws_handler))
            .route(&WsRoutes::Client.addr(), get(Self::ws_handler))
    }
}

impl WsRouter {
    /// Close the connection
    async fn close_connection(
        connections: &AMConnections,
        device_id: DeviceId,
        ulid: Ulid,
        device_type: ConnectionType,
    ) {
        connections
            .lock()
            .await
            .close(device_id, ulid, device_type)
            .await;
    }

    /// Close connection from inside either message_handler or structured_message_handler
    async fn handler_close(input: &HandlerData<'_>) {
        Self::close_connection(
            input.connections,
            input.device.device_id,
            input.ulid,
            input.device_type,
        )
        .await;
    }

    /// Send a message to self, when cache or error
    async fn send_self<T: ToString + Send>(input: &HandlerData<'_>, msg: T) {
        let msg = msg.to_string();
        input
            .connections
            .lock()
            .await
            .send_self(input, SendMessage::from(msg))
            .await;
    }

    /// Check if the rate limit is ok, skip if a Close message, or a PONG message with a msg_length of 0
    async fn rate_limit_ok(input: &HandlerData<'_>, msg: &Message) -> bool {
        match msg {
            Message::Close(_) => true,
            Message::Pong(data) => {
                if data.is_empty() {
                    true
                } else {
                    input.limiter.check(input.redis).await.is_ok()
                }
            }
            _ => input.limiter.check(input.redis).await.is_ok(),
        }
    }

    /// Validate rate limit, if structured data
    /// If structured data, return error to sender
    async fn valid_rate_limit(input: &HandlerData<'_>, msg: &Message) -> Result<(), ()> {
        if !Self::rate_limit_ok(input, msg).await {
            if input.limiter.exceeded(input.redis).await.unwrap_or(true) {
                Self::handler_close(input).await;
            }

            if input.device.structured_data {
                let ttl = input.limiter.ttl(input.redis).await.unwrap_or(60);
                Self::send_self(input, wm::Error::RateLimit(ttl)).await;
            }
            return Err(());
        }
        Ok(())
    }

    /// Validate that a users monthly bandwidth limit hasn't been hit
    /// If structured data, return error to sender
    async fn valid_bandwidth(input: &HandlerData<'_>) -> Result<(), ()> {
        if check_monthly_bandwidth(input.postgres, input.redis, input.device)
            .await
            .is_err()
        {
            if input.device.structured_data {
                Self::send_self(input, wm::Error::MonthlyBandwidth).await;
            }
            return Err(());
        }
        Ok(())
    }

    /// Check that a given message is smaller than the devices max message size
    /// If structured data, return error to sender
    async fn valid_message_size(input: &HandlerData<'_>) -> Result<(), ()> {
        if input.msg_size > usize::try_from(input.device.max_message_size_in_bytes).unwrap_or(1000)
        {
            if input.device.structured_data {
                Self::send_self(input, wm::Error::MessageSize).await;
            }
            return Err(());
        }
        Ok(())
    }

    /// Handle each received websocket message
    /// Sender is split and pushed into hashmap
    async fn message_looper(
        connection_id: ConnectionId,
        device_type: ConnectionType,
        device: ModelWsDevice,
        ip: IpAddr,
        socket: WebSocket,
        state: ApplicationState,
    ) {
        // Generate random ulid for each connection, currently am NOT storing this in postgres connection table
        let ulid = Ulid::new();

        let (sender, mut receiver) = socket.split();

        let inserted = state.connections.lock().await.insert(
            WsSender::new(connection_id, device_type, &device, ip, sender, ulid),
            &device,
        );
        if inserted.is_err() {
            Self::close_connection(&state.connections, device.device_id, ulid, device_type).await;
            return;
        }

        let limiter = RateLimit::from(&device);
        let mut handler_data =
            HandlerData::new(connection_id, device_type, &device, &limiter, &state, ulid);

        while let Ok(Some(msg)) = receiver.try_next().await {
            handler_data.msg_size = get_message_size(&msg);
            Self::message_handler(&handler_data, msg).await;
        }
        Self::close_connection(&state.connections, device.device_id, ulid, device_type).await;

        if let Err(e) = ModelConnection::update_offline(&state.postgres, connection_id).await {
            tracing::error!("{e:?}");
            tracing::error!("unable to update connection details");
        }
    }

    /// Deal with text messages when structured data is enabled
	#[allow(clippy::cognitive_complexity)]
    async fn structured_text_handler(input: &HandlerData<'_>, data: Utf8Bytes) {
        match input.device_type {
            ConnectionType::Client => match serde_json::from_str::<wm::ClientBody>(&data) {
                Ok(body) => {
                    let pi_online = input.connections.lock().await.is_alive(
                        input.device.device_id,
                        input.ulid,
                        ConnectionType::Pi,
                    );

                    if pi_online {
                        let to_send = if body.unique.is_some() {
                            PiBody::from_client(body, Some(input.ulid))
                        } else {
                            PiBody::from_client(body, None)
                        };

                        input
                            .connections
                            .lock()
                            .await
                            .send_all(input, SendMessage::from(to_send))
                            .await;
                    } else {
                        match MessageCache::get(input.redis, input.device.device_id).await {
                            Ok(Some(cache_msg)) => {
                                Self::send_self(input, cache_msg).await;
                            }
                            Ok(None) => (),
                            Err(e) => tracing::error!("{:?}", e),
                        }
                    }
                }
                Err(_) => Self::send_self(input, wm::Error::InvalidStructure).await,
            },
            ConnectionType::Pi => match serde_json::from_str::<wm::PiBody>(&data) {
                Ok(body) => {
                    if let Some(cache) = body.cache {
                        if cache {
                            MessageCache::new(&body)
                                .insert(&C!(input.redis), input.device.device_id);
                        // Don't like this syntax?
                        } else if let Err(e) =
                            MessageCache::delete(input.redis, input.device.device_id).await
                        {
                            tracing::error!("{e:?}");
                        }
                    }

                    let unique = body.unique;
                    let to_send = ClientBody::from_pi(body);
                    if let Some(unique_ulid) = unique {
                        input
                            .connections
                            .lock()
                            .await
                            .send_unique(input, SendMessage::from(to_send), unique_ulid)
                            .await;
                    } else {
                        input
                            .connections
                            .lock()
                            .await
                            .send_all(input, SendMessage::from(to_send))
                            .await;
                    }
                }
                Err(_) => Self::send_self(input, wm::Error::InvalidStructure).await,
            },
        }
    }

    /// This needs to be better!
    async fn message_handler(input: &HandlerData<'_>, msg: Message) {
        if Self::valid_rate_limit(input, &msg).await.is_err() {
            return;
        }

        if Self::valid_bandwidth(input).await.is_err() {
            return;
        }

        if Self::valid_message_size(input).await.is_err() {
            return;
        }

        ModelHourlyBandwidth::insert(
            input.device.device_id,
            input.device_type,
            false,
            input.msg_size,
            input.postgres,
            input.redis,
        );

        match msg {
            Message::Text(data) => {
                if input.device.structured_data {
                    Self::structured_text_handler(input, data).await;
                } else {
                    input
                        .connections
                        .lock()
                        .await
                        .send_all(input, SendMessage::from(data))
                        .await;
                }
            }
            Message::Binary(data) => {
                if input.device.structured_data {
                    Self::send_self(input, wm::Error::InvalidStructure).await;
                } else {
                    input
                        .connections
                        .lock()
                        .await
                        .send_all(input, SendMessage::from(data))
                        .await;
                }
            }
            Message::Ping(_) => (),
            Message::Pong(_) => input.connections.lock().await.update_auto_close(input),
            Message::Close(_) => Self::handler_close(input).await,
        }
    }

    /// Send an api_version & uptime response, then close socket
    #[expect(clippy::unused_async)]
    async fn online_get(
        State(state): State<ApplicationState>,
        ws: WebSocketUpgrade,
    ) -> impl IntoResponse {
        ws.max_message_size(1)
            .max_write_buffer_size(1000 * 256)
            .on_upgrade(move |socket| Self::online_message_handler(socket, state))
    }

    /// Send an api_version & uptime response, then close socket
	#[allow(clippy::cognitive_complexity)]
    async fn online_message_handler(mut socket: WebSocket, state: ApplicationState) {
        if let Ok(response) = serde_json::to_string(&oj::Online {
            uptime: calc_uptime(state.start_time),
            api_version: S!(env!("CARGO_PKG_VERSION")),
        }) {
            if let Err(e) = socket.send(Message::Text(response.into())).await {
                tracing::debug!("online_ws::send::{:?}", e);
            }
        }

        match tokio::time::timeout(std::time::Duration::from_secs(2), socket.close()).await {
            Ok(close_result) => {
                if let Err(e) = close_result {
                    tracing::debug!("online_ws::close::{:?}", e);
                }
            }
            Err(e) => {
                tracing::debug!("online_ws::tokio_timeout::{}", e);
            }
        }
    }

    async fn ws_handler(
        useragent_ip: ModelUserAgentIp,
        ws: WebSocketUpgrade,
        OriginalUri(uri): OriginalUri,
        State(state): State<ApplicationState>,
        ij::Path(ij::AccessToken { access_token }): ij::Path<ij::AccessToken>,
    ) -> Result<impl IntoResponse, ApiError> {
        let device_type = ConnectionType::try_from(uri)?;

        if std::time::SystemTime::now()
            .duration_since(access_token.datetime())?
            .as_secs()
            > AccessToken::TTL_AS_SEC.into()
        {
            return Ok((StatusCode::BAD_REQUEST).into_response());
        }

        if let Some(token) =
            AccessToken::get(&state.redis, access_token, device_type, &useragent_ip).await?
        {
            token.delete(&state.redis, access_token).await?;
            if let Some(device) = ModelWsDevice::get_by_id(&state.postgres, token.device_id).await?
            {
                let max_connections = state
                    .connections
                    .lock()
                    .await
                    .max_connected(&device, device_type);

                if !max_connections
                    && check_monthly_bandwidth(&state.postgres, &state.redis, &device)
                        .await
                        .is_ok()
                    && RateLimit::from(&device).limited_ttl(&state.redis).await? == 0
                {
                    let connection_id = ModelConnection::insert(
                        &state.postgres,
                        &device,
                        &useragent_ip,
                        device_type,
                    )
                    .await?;

                    let max_buffer_size =
                        usize::try_from(device.max_message_size_in_bytes.saturating_mul(16))
                            .unwrap_or(DEFAULT_BUFFER);
                    return Ok(ws
                        .max_message_size(
                            usize::try_from(device.max_message_size_in_bytes * 2)
                                .unwrap_or(1000 * 11),
                        )
                        .max_write_buffer_size(max_buffer_size)
                        .on_upgrade(move |socket| {
                            Self::message_looper(
                                connection_id,
                                device_type,
                                device,
                                useragent_ip.ip,
                                socket,
                                state,
                            )
                        }));
                }
            }
        }
        Ok((StatusCode::BAD_REQUEST).into_response())
    }
}

/// cargo watch -q -c -w src/ -x 'test ws_server -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use crate::{
        C, S,
        connections::ConnectionType,
        database::{
            RedisKey, access_token::AccessToken, monthly_bandwidth::ModelMonthlyBandwidth,
            user_level::UserLevel,
        },
        helpers::gen_random_hex,
        servers::test_setup::{
            Response, TestSetup, get_keys, start_servers, token_base_url, ws_base_url,
        },
        sleep,
        user_io::incoming_json::ij::DevicePost,
    };
    use fred::interfaces::{HashesInterface, KeysInterface};
    use futures::{SinkExt, StreamExt};
    use reqwest::{StatusCode, Url};
    use serde_json::Value;
    use std::collections::HashMap;
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{Error, protocol::Message},
    };
    use ulid::Ulid;

    const INVALID_BODY: &str =
        r#"{"error":{"message":"received data is invalid structure","code":400}}"#;

    #[tokio::test]
    /// base ws route returns basic server stats, and then connection is closed
    async fn ws_server_online() {
        let test_setup = start_servers().await;
        sleep!(1000);
        let url = Url::parse(&format!("{}/online", ws_base_url(&test_setup.app_env))).unwrap();
        let (socket, _) = connect_async(url.as_str()).await.unwrap();
        let (_, mut rx) = socket.split();
        let result: Value =
            serde_json::from_str(&rx.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        let closed = rx.next().await.unwrap().unwrap().is_close();
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(result["uptime"], 1);
        assert!(closed)
    }

    #[tokio::test]
    /// small ban rate limit when using ip as a key, when connecting to /online route
    async fn ws_server_rate_limit_small() {
        let test_setup = start_servers().await;

        let url = Url::parse(&format!("{}/online", ws_base_url(&test_setup.app_env))).unwrap();
        for _ in 1..=44 {
            let (socket, _) = connect_async(url.as_str()).await.unwrap();
            let (_, mut rx) = socket.split();
            rx.next().await;
        }

        // 89 request is fine
        let (socket, _) = connect_async(url.as_str()).await.unwrap();
        let (_, mut rx) = socket.split();
        let result: Value =
            serde_json::from_str(&rx.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        let closed = rx.next().await.unwrap().unwrap().is_close();
        assert_eq!(result["api_version"], env!("CARGO_PKG_VERSION"));
        assert!(result["uptime"].is_u64());
        assert!(closed);

        // 90+ request is rate limited
        match connect_async(url.as_str()).await.unwrap_err() {
            Error::Http(response) => {
                assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS)
            }
            _ => unreachable!("connect_async test"),
        }
        let ratelimit_key = "ratelimit::ip::127.0.0.1";
        let ttl = test_setup
            .redis
            .ttl::<usize, &str>(ratelimit_key)
            .await
            .unwrap();
        assert_eq!(ttl, 60);
    }

    #[tokio::test]
    /// big ban rate limit when using ip as a key, ttl reset on extra request
    async fn ws_server_rate_limit_big() {
        let test_setup = start_servers().await;

        let url = Url::parse(&format!("{}/online", ws_base_url(&test_setup.app_env))).unwrap();

        let ratelimit_key = "ratelimit::ip::127.0.0.1";

        test_setup
            .redis
            .set::<(), &str, i64>(ratelimit_key, 90, None, None, false)
            .await
            .unwrap();

        match connect_async(url.as_str()).await.unwrap_err() {
            Error::Http(response) => {
                assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS)
            }
            _ => unreachable!("connect_async test"),
        };

        let ttl = test_setup
            .redis
            .ttl::<usize, &str>(ratelimit_key)
            .await
            .unwrap();

        assert_eq!(ttl, 300);

        sleep!(1000);
        assert!(connect_async(url.as_str()).await.is_err());
        let ttl = test_setup
            .redis
            .ttl::<usize, &str>(ratelimit_key)
            .await
            .unwrap();
        assert_eq!(ttl, 300);
    }

    #[tokio::test]
    /// Return ulid token for free user, check
    async fn ws_server_free_client_ok() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        let device = C!(test_setup.query_user_active_devices().await[0]);

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
    async fn ws_server_free_pi_ok() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        let device = C!(test_setup.query_user_active_devices().await[0]);

        let client = TestSetup::get_client();

        let url = format!("{}/pi", &token_base_url(&test_setup.app_env));
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = result.json::<Response>().await.unwrap().response;
        assert!(Ulid::from_string(result.as_str().unwrap()).is_ok());
    }

    #[tokio::test]
    /// Client able to connect and send a message, connection in db
    async fn ws_server_free_client_connect_ok() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;

        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());
        let connections = test_setup
            .get_connections(ConnectionType::Client, &device_name)
            .await;
        // this is a connection_id issue again!
        assert!(connections.len() == 1);
        assert!(connections[0].timestamp_offline.is_none());
    }

    #[tokio::test]
    /// Client unable to use an access token twice
    async fn ws_server_free_client_connect_err() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());
        ws.close(None).await.unwrap();
        let ws = connect_async(&url).await;
        assert!(ws.is_err());
    }

    #[tokio::test]
    /// Client disconnect inserted into db
    async fn ws_server_free_client_connections_in_db() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;

        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());

        assert!(ws.close(None).await.is_ok());

        // Need to sleep here, as connection_offline is executed on it's own thread,
        sleep!(100);

        let connections = test_setup
            .get_connections(ConnectionType::Client, &device_name)
            .await;
        assert!(connections.len() == 1);
        assert!(connections[0].timestamp_offline.is_some());
    }

    #[tokio::test]
    /// Pi able to connect and send a message, connection in db
    async fn ws_server_free_pi_connect_ok() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;

        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());
        let connections = test_setup
            .get_connections(ConnectionType::Pi, &device_name)
            .await;
        assert!(connections.len() == 1);
        assert!(connections[0].timestamp_offline.is_none());
    }

    #[tokio::test]
    /// Pi unable to use an access token twice
    async fn ws_server_free_pi_connect_err() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());
        ws.close(None).await.unwrap();
        let ws = connect_async(&url).await;
        assert!(ws.is_err());
    }

    #[tokio::test]
    /// Pi disconnect inserted into db
    async fn ws_server_free_pi_connections_in_db() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        let device_name = test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());

        assert!(ws.close(None).await.is_ok());

        // Need to sleep here, as connection_offline is executed in it's own thread,
        sleep!(100);

        let connections = test_setup
            .get_connections(ConnectionType::Pi, &device_name)
            .await;
        assert!(connections.len() == 1);
        assert!(connections[0].timestamp_offline.is_some());
    }

    #[tokio::test]
    /// Pi unable to get access code if already connected
    async fn ws_server_free_client_connect_twice_error() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());

        let device = C!(test_setup.query_user_active_devices().await[0]);
        let client = TestSetup::get_client();
        let url = format!(
            "{}/{}",
            &token_base_url(&test_setup.app_env),
            ConnectionType::Client
        );
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    /// Pi unable to get access code if already connected
    async fn ws_server_free_pi_connect_twice_error() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws = connect_async(&url).await;
        assert!(ws.is_ok());

        let msg = Message::from("hello world");
        let (mut ws, _) = ws.unwrap();
        assert!(ws.send(msg).await.is_ok());

        let device = C!(test_setup.query_user_active_devices().await[0]);
        let client = TestSetup::get_client();
        let url = format!(
            "{}/{}",
            &token_base_url(&test_setup.app_env),
            ConnectionType::Pi
        );
        let body = HashMap::from([("key", device.api_key_string)]);
        let result = client.post(&url).json(&body).send().await.unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    /// Client & Pi able to connect and send a message
    async fn ws_server_free_client_and_pi_connect_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let pi_url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let client_url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let pi_ws = connect_async(&pi_url).await;
        assert!(pi_ws.is_ok());

        let client_ws = connect_async(&client_url).await;
        assert!(client_ws.is_ok());

        let msg = Message::from("hello world");
        let (mut pi_ws, _) = pi_ws.unwrap();
        assert!(pi_ws.send(C!(msg)).await.is_ok());

        let (mut client_ws, _) = client_ws.unwrap();
        assert!(client_ws.send(msg).await.is_ok());
    }

    #[tokio::test]
    /// Pro user unable connect multiple clients to device when using single access token
    async fn ws_server_pro_client_multiple_connections_err() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let device = DevicePost {
            max_clients: 2,
            client_password: None,
            device_password: None,
            structured_data: false,
            name: None,
        };
        let device_name = test_setup.insert_device(&authed_cookie, Some(device)).await;
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws_01 = connect_async(&url).await;
        assert!(ws_01.is_ok());

        let ws_02 = connect_async(&url).await;
        assert!(ws_02.is_err());

        let msg = Message::from("hello world");
        let (mut ws_01, _) = ws_01.unwrap();
        assert!(ws_01.send(C!(msg)).await.is_ok());

        let connections = test_setup
            .get_connections(ConnectionType::Client, &device_name)
            .await;
        assert!(connections.len() == 1);
    }

    #[tokio::test]
    /// Pro user able to connect multiple clients to device
    async fn ws_server_pro_client_multiple_connections_ok() {
        let mut test_setup = start_servers().await;

        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let device = DevicePost {
            max_clients: 2,
            client_password: None,
            device_password: None,
            structured_data: false,
            name: None,
        };
        let device_name = test_setup.insert_device(&authed_cookie, Some(device)).await;
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws_01 = connect_async(&url).await;
        assert!(ws_01.is_ok());

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_02 = connect_async(&url).await;
        assert!(ws_02.is_ok());

        let msg = Message::from("hello world");
        let (mut ws_01, _) = ws_01.unwrap();
        let (mut ws_02, _) = ws_02.unwrap();
        assert!(ws_01.send(C!(msg)).await.is_ok());
        assert!(ws_02.send(msg).await.is_ok());

        let connections = test_setup
            .get_connections(ConnectionType::Client, &device_name)
            .await;
        assert!(connections.len() == 2);
    }

    #[tokio::test]
    /// Free user able to send message from pi to client, rate limit exists, monthly bandwidth exists
    async fn ws_server_free_send_pi_to_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));

        ws_pi.send(msg).await.unwrap();

        let (_, mut rx) = ws_client.split();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let key = format!("ratelimit::ws_free::{}", test_setup.get_user_id().get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);

        // have to sleep as bandwidth inserted on own thread
        sleep!();
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 12);
    }

    #[tokio::test]
    /// Free user able to send message from client to pi, rate limit exists, monthly bandwidth exists
    async fn ws_server_free_send_client_to_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));

        ws_client.send(msg).await.unwrap();

        let (_, mut rx) = ws_pi.split();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let key = format!("ratelimit::ws_free::{}", test_setup.get_user_id().get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);

        // Need to wait as bandwidth inserted on own thread
        sleep!();
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 12);
    }

    #[tokio::test]
    /// Pro user able to send message from pi to client, rate limit exists, monthly bandwidth exists
    async fn ws_server_pro_send_pi_to_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));

        ws_pi.send(msg).await.unwrap();

        let (_, mut rx) = ws_client.split();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let key = format!("ratelimit::ws_pro::{}", device.device_id.get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);

        // have to sleep as bandwidth inserted on own thread
        sleep!();
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 12);
    }

    #[tokio::test]
    /// Pro user able to send message from client to pi, rate limit exists, monthly bandwidth exists
    async fn ws_server_pro_send_client_to_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));

        ws_client.send(msg).await.unwrap();

        let (_, mut rx) = ws_pi.split();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let key = format!("ratelimit::ws_pro::{}", device.device_id.get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);

        // Need to wait as bandwidth inserted on own thread
        sleep!();
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 12);
    }

    //*******************
    //* Structured data *
    //*******************

    #[tokio::test]
    /// Pro user, structured data, pi sends invalid ws messages
    async fn ws_server_free_structured_data_pi_invalid_body() {
        let mut test_setup = start_servers().await;
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

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        // Random message
        let msg_text = gen_random_hex(12);
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // structured error
        let msg_text = r#"{"error":{"message":"received data is invalid structure", "code":400}}"#;
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // structured additional field
        let msg_text = r#"{"data":{"message":"received data is invalid structure", "code":400}, "another":"one:}"#;
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // cache not bool
        let msg_text = r#"{"data":"something", "cache":1}"#;
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // unique not ulid
        let msg_text = r#"{"data":"something", "unique":1}"#;
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // unique invalid ulid
        let ulid = Ulid::new();
        let msg_text = format!("{{\"data\":\"something\", \"unique\":\"{ulid}I\"}}");
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);
    }

    #[tokio::test]
    /// Pro user, structured data, client sends invalid ws messages
    async fn ws_server_free_structured_data_client_invalid_body() {
        let mut test_setup = start_servers().await;
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

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        // Random message
        let msg_text = gen_random_hex(12);
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // structured error
        let msg_text = r#"{"error":{"message":"received data is invalid structure", "code":400}}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // structured additional field
        let msg_text = r#"{"data":{"message":"received data is invalid structure", "code":400}, "another":"one:}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // cache anything
        let msg_text = r#"{"data":"something", "cache":1}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // unique not ulid
        let msg_text = r#"{"data":"something", "unique":1}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);

        // unique not true
        let msg_text = r#"{"data":"something", "unique":false}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), INVALID_BODY);
    }

    #[tokio::test]
    /// Pro user, structured data, client received valid structured data message
    async fn ws_server_free_structured_data_pi_to_client_message_received() {
        let mut test_setup = start_servers().await;
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

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = r#"{"data":"something"}"#;
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), msg_text);
    }

    #[tokio::test]
    /// Pro user, structured data,  multiple clients receive valid structured data message
    async fn ws_server_free_structured_data_pi_to_multiple_client_message_received() {
        let mut test_setup = start_servers().await;
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

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client_01, _) = ws_client.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client_02, _) = ws_client.unwrap();

        let msg_text = r#"{"data":"something"}"#;
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();
        let result = &ws_client_01
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), msg_text);

        let result = &ws_client_02
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(result.as_str(), msg_text);
    }

    #[tokio::test]
    /// Pro user, structured data, pi received valid structured data message sent from client
    async fn ws_server_free_structured_data_client_to_pi_message_received() {
        let mut test_setup = start_servers().await;
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

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = r#"{"data":"something"}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result.as_str(), msg_text);
    }

    #[tokio::test]
    /// Pro user, structured data, pi received valid structured data message sent from client, including a unique ulid, and unique is valid ulid
    async fn ws_server_free_structured_data_client_to_pi_unique_message_received() {
        let mut test_setup = start_servers().await;
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

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = r#"{"data":"something", "unique":true}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(result.contains("\"data\":\"something\""));
        assert!(result.contains("\"unique\":"));

        // Extract the unique value, and assert that it's a valid ulid
        let unique_value = result.chars().skip(30).take(26).collect::<String>();
        assert!(Ulid::from_string(&unique_value).is_ok());
    }

    #[tokio::test]
    /// Pro user, structured data, pi received valid structured data message sent from client, including a unique ulid, then returns to ONLY the sendee unique client
    async fn ws_server_free_structured_data_client_to_pi_to_client_unique_message_received() {
        let mut test_setup = start_servers().await;
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

        let msg_text = r#"{"data":"something", "unique":true}"#;
        let msg = Message::from(msg_text);
        ws_client_01.send(msg).await.unwrap();
        let result = &ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        let unique_value = result.chars().skip(30).take(26).collect::<String>();

        let random_hex = gen_random_hex(10);

        let msg_text = format!("{{\"data\":\"{random_hex}\", \"unique\":\"{unique_value}\"}}");
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();

        let result = &ws_client_01
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();

        assert_eq!(result, &format!("{{\"data\":\"{random_hex}\"}}"));

        // Wait 1 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(1), &mut ws_client_02.next())
            .await
            .is_ok()
        {
            unreachable!("unique msg shouldn't be sent to his client")
        };
    }

    #[tokio::test]
    async fn ws_server_pro_structured_data_cache_ok() {
        let mut test_setup = start_servers().await;
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

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let random_msg = gen_random_hex(12);
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();
        let msg_text = format!(r#"{{"data":"{random_msg}", "cache": true}}"#);
        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();

        // Sleep as inserted on own thread
        sleep!();
        let message_cache = get_keys(&test_setup.redis, "cache::message::*").await;

        assert_eq!(message_cache.len(), 1);

        let cache: String = test_setup
            .redis
            .hget(&message_cache[0], "data")
            .await
            .unwrap();

        assert!(cache.contains(&random_msg));

        ws_pi.send(Message::Close(None)).await.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();
        let msg_text = r#"{"data":"doesn't matter"}"#;
        let msg = Message::from(msg_text);
        ws_client.send(msg).await.unwrap();

        let response = ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert!(response.contains("\"cache\":true"));
        assert!(response.contains(&random_msg));
    }

    //***************
    //* Rate Limits *
    //***************

    #[tokio::test]
    /// Free user rate limited after 15 message sent, from pi to client, ttl correct in redis, remove rate limit then able to send/recv mesg again
    async fn ws_server_free_rate_limit_hit_pi_to_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();
        for _ in 1..=15 {
            let msg_text = gen_random_hex(12);
            let msg = Message::from(C!(msg_text));
            ws_pi.send(C!(msg)).await.unwrap();

            let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(result, &msg_text);
        }

        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        // Wait 1 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(1), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("rate limit test error")
        };

        let key = format!("ratelimit::ws_free::{}", test_setup.get_user_id().get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 16);

        // Delete rate limit, and assert a message can be sent/received again!
        test_setup.redis.del::<(), &str>(&key).await.unwrap();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);
    }

    #[tokio::test]
    /// Free user rate limited after 15 message sent, from client to pi, ttl correct in redis, remove rate limit then able to send/recv mesg again
    async fn ws_server_free_rate_limit_hit_client_to_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        // 15 message fine
        for _ in 1..=15 {
            let msg_text = gen_random_hex(12);
            let msg = Message::from(C!(msg_text));
            ws_client.send(C!(msg)).await.unwrap();
            let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(result, &msg_text);
        }

        // 16th message rate limited
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        // Wait 1 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(1), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("rate limit test error")
        };

        let key = format!("ratelimit::ws_free::{}", test_setup.get_user_id().get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 16);

        // Delete rate limit, and assert a message can be sent/received again!
        test_setup.redis.del::<(), &str>(&key).await.unwrap();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);
    }

    #[tokio::test]
    /// Pro user with structured data, get rate limited structured response
    async fn ws_server_pro_rate_limit_structured_response_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 1,
                    client_password: None,
                    device_password: None,
                    structured_data: true,
                    name: None,
                }),
            )
            .await;

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let msg_text = r#"{"data":"some structured data"}"#;
        for _ in 0..300 {
            let msg = Message::from(msg_text);
            ws_pi.send(C!(msg)).await.unwrap();
        }

        let msg = Message::from(msg_text);
        ws_pi.send(C!(msg)).await.unwrap();
        let result = ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(
            result,
            r#"{"error":{"message":"rate limited for 60 seconds","code":429}}"#
        );
    }

    #[tokio::test]
    /// Pro user with structured data, get rate limited structured response
    async fn ws_server_pro_rate_limit_structured_response_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup
            .insert_device(
                &authed_cookie,
                Some(DevicePost {
                    max_clients: 1,
                    client_password: None,
                    device_password: None,
                    structured_data: true,
                    name: None,
                }),
            )
            .await;

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = r#"{"data":"some structured data"}"#;
        for _ in 0..300 {
            let msg = Message::from(msg_text);
            ws_client.send(C!(msg)).await.unwrap();
        }

        let msg = Message::from(msg_text);
        ws_client.send(C!(msg)).await.unwrap();
        let result = ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            result,
            r#"{"error":{"message":"rate limited for 60 seconds","code":429}}"#
        );
    }

    #[tokio::test]
    /// Free user rate limited after 60 message sent, from pi to client, connection gets closed
    async fn ws_server_free_rate_limit_closed_pi_to_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let msg_text = gen_random_hex(12);
        for _ in 0..59 {
            let msg = Message::from(C!(msg_text));
            ws_pi.send(C!(msg)).await.unwrap();
        }

        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        assert!(ws_pi.next().await.unwrap().unwrap().is_close());
    }

    #[tokio::test]
    /// Free user rate limited after 60 message sent, from client to pi, connection gets closed
    async fn ws_server_free_rate_limit_closed_client_to_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = gen_random_hex(12);
        for _ in 0..59 {
            let msg = Message::from(C!(msg_text));
            ws_client.send(C!(msg)).await.unwrap();
        }

        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        assert!(ws_client.next().await.unwrap().unwrap().is_close());
    }

    #[tokio::test]
    /// Pro user rate limited after 1200 message sent, from pi to client, connection gets closed
    async fn ws_server_pro_rate_limit_closed_pi_to_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let msg_text = gen_random_hex(12);
        for _ in 0..1199 {
            let msg = Message::from(C!(msg_text));
            ws_pi.send(C!(msg)).await.unwrap();
        }

        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        assert!(ws_pi.next().await.unwrap().unwrap().is_close());
    }

    #[tokio::test]
    /// Pro user rate limited after 1200 message sent, from client to pi, connection gets closed
    async fn ws_server_pro_rate_limit_closed_client_to_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        test_setup.change_user_level(UserLevel::Pro).await;

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let msg_text = gen_random_hex(12);
        for _ in 0..1199 {
            let msg = Message::from(C!(msg_text));
            ws_client.send(C!(msg)).await.unwrap();
        }

        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        assert!(ws_client.next().await.unwrap().unwrap().is_close());
    }

    #[tokio::test]
    /// Pro user rate limited after 300 message sent, from pi to client, ttl correct in redis, remove rate limit then able to send/recv mesg again
    async fn ws_server_pro_rate_limit_hit_pi_to_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();
        // 300 message are fine
        for _ in 1..=300 {
            let msg_text = gen_random_hex(12);
            let msg = Message::from(C!(msg_text));
            ws_pi.send(C!(msg)).await.unwrap();
            let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(result, &msg_text);
        }

        // 301 message is rate limited

        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        // Wait 1 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("rate limit test error")
        };

        let key = format!("ratelimit::ws_pro::{}", device.device_id.get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 301);

        // Delete rate limit, and assert a message can be sent/received again!
        test_setup.redis.del::<(), &str>(&key).await.unwrap();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);
    }

    #[tokio::test]
    /// Pro user rate limited after 300 message sent, from client to pi, ttl correct in redis, remove rate limit then able to send/recv mesg again
    async fn ws_server_pro_rate_limit_hit_client_to_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        // 300 message fine
        for _ in 1..=300 {
            let msg_text = gen_random_hex(12);
            let msg = Message::from(C!(msg_text));
            ws_client.send(C!(msg)).await.unwrap();
            let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(result, &msg_text);
        }

        // 301 message rate limited
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        // Wait 2 seconds to recevive a message, should never receive
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("rate limit test error")
        };

        let key = format!("ratelimit::ws_pro::{}", device.device_id.get());
        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 301);

        // Delete rate limit, and assert a message can be sent/received again!
        test_setup.redis.del::<(), &str>(&key).await.unwrap();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();
        let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(result, &msg_text);

        let rate_limit: usize = test_setup.redis.get(&key).await.unwrap();
        assert_eq!(rate_limit, 1);
    }

    //*********************
    //* Monthly Bandwidth *
    //*********************

    #[tokio::test]
    /// Free user, from pi to client, bandwidth inserted into postgres, and in redis cache
    async fn ws_server_free_monthly_bandwidth_inserted_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let user = C!(test_setup.get_model_user().await.as_ref().unwrap());

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();
        for _ in 1..=10 {
            let msg_text = gen_random_hex(12);
            let msg = Message::from(C!(msg_text));
            ws_pi.send(C!(msg)).await.unwrap();
            let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(result, &msg_text);
        }

        // have to sleep as bandwidth inserted on own thread
        sleep!();

        // flush cache!
        let key = format!(
            "cache::monthly_bandwidth::{}",
            user.registered_user_id.get()
        );
        test_setup.redis.del::<(), &str>(&key).await.unwrap();

        // This will now be from postgres
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 12 * 10);

        // Should also now be in redis
        let model: ModelMonthlyBandwidth = test_setup.redis.hget(&key, "data").await.unwrap();
        assert_eq!(model.size_in_bytes, 12 * 10);
    }

    #[tokio::test]
    /// Free user, from pi to client, bandwidth inserted into postgres, and in redis cache
    async fn ws_server_free_monthly_bandwidth_inserted_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        let user = C!(test_setup.get_model_user().await.as_ref().unwrap());

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        for _ in 1..=10 {
            let msg_text = gen_random_hex(12);
            let msg = Message::from(C!(msg_text));
            ws_client.send(C!(msg)).await.unwrap();
            let result = &rx.next().await.unwrap().unwrap().into_text().unwrap();
            assert_eq!(result, &msg_text);
        }

        // have to sleep as bandwidth inserted on own thread
        sleep!(500);

        // flush cache!
        let key = format!(
            "cache::monthly_bandwidth::{}",
            user.registered_user_id.get()
        );
        test_setup.redis.del::<(), &str>(&key).await.unwrap();

        // This will now be from postgres
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 12 * 10);

        // Should also now be in redis
        let model: ModelMonthlyBandwidth = test_setup.redis.hget(&key, "data").await.unwrap();
        assert_eq!(model.size_in_bytes, 12 * 10);
    }

    #[tokio::test]
    /// Free user, from pi to client, max bandwidth limit hit, unable to receive messages
    async fn ws_server_free_monthly_bandwidth_at_limit_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let device = C!(test_setup.query_user_active_devices().await[0]);
        test_setup
            .insert_bandwidth(device.device_id, 5_000_000_000, ConnectionType::Pi, true)
            .await;

        let (_, mut rx) = ws_client.split();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("Monthly bandwidth test error")
        };
    }

    #[tokio::test]
    /// Free user, from client to pi, max bandwidth limit hit, unable to receive messages
    async fn ws_server_free_monthly_bandwidth_at_limit_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let device = C!(test_setup.query_user_active_devices().await[0]);

        test_setup
            .insert_bandwidth(
                device.device_id,
                5_000_000_000,
                ConnectionType::Client,
                true,
            )
            .await;

        let (_, mut rx) = ws_pi.split();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("Monthly bandwidth test error")
        };
    }

    #[tokio::test]
    /// Free user, pi connection unable to connect if max bandwidth limit hit (but access code already supplied)
    async fn ws_server_free_monthly_bandwidth_at_limit_pi_connect() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;

        test_setup.insert_device(&authed_cookie, None).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        test_setup
            .insert_bandwidth(device.device_id, 5_000_000_000, ConnectionType::Pi, true)
            .await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_err());
    }

    #[tokio::test]
    /// Free user, client connection unable to connect if max bandwidth limit hit (but access code already supplied)
    async fn ws_server_free_monthly_bandwidth_at_limit_client_connect() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        test_setup
            .insert_bandwidth(
                device.device_id,
                5_000_000_000,
                ConnectionType::Client,
                true,
            )
            .await;

        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_err());
    }

    #[tokio::test]
    /// Pro user, from pi to client, max bandwidth limit hit, unable to receive messages
    async fn ws_server_pro_monthly_bandwidth_at_limit_pi() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;

        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let device = C!(test_setup.query_user_active_devices().await[0]);

        test_setup
            .insert_bandwidth(device.device_id, 10_000_000_000, ConnectionType::Pi, true)
            .await;

        let (_, mut rx) = ws_client.split();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("Monthly bandwidth test error")
        };
    }

    #[tokio::test]
    /// Pro user, from client to pi, max bandwidth limit hit, unable to receive messages
    async fn ws_server_pro_monthly_bandwidth_at_limit_client() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let device = C!(test_setup.query_user_active_devices().await[0]);

        test_setup
            .insert_bandwidth(
                device.device_id,
                10_000_000_000,
                ConnectionType::Client,
                true,
            )
            .await;

        let (_, mut rx) = ws_pi.split();
        let msg_text = gen_random_hex(12);
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("Monthly bandwidth test error")
        };
    }

    #[tokio::test]
    /// Pro user, pi connection unable to connect if max bandwidth limit hit (but access code already supplied)
    async fn ws_server_pro_monthly_bandwidth_at_limit_pi_connect() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);

        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;
        test_setup
            .insert_bandwidth(device.device_id, 10_000_000_000, ConnectionType::Pi, true)
            .await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_err());
    }

    #[tokio::test]
    /// Pro user, client connection unable to connect if max bandwidth limit hit (but access code already supplied)
    async fn ws_server_pro_monthly_bandwidth_at_limit_client_connect() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let device = C!(test_setup.query_user_active_devices().await[0]);

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        test_setup
            .insert_bandwidth(
                device.device_id,
                10_000_000_000,
                ConnectionType::Client,
                true,
            )
            .await;

        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_err());
    }

    //****************
    //* Message size *
    //****************

    #[tokio::test]
    /// Free user, from pi to client, msg size > 1kb
    async fn ws_server_free_pi_message_size_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();

        let msg_text = (0..=10_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("message size test error")
        };

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_none());
    }

    #[tokio::test]
    /// Free user, from client to pi, msg size > 1kb
    async fn ws_server_free_client_message_size_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        let msg_text = (0..=10_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("message size test error")
        };

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_none());
    }

    #[tokio::test]
    /// Pro user, from pi to client, msg size > 3mb < 5mb
    async fn ws_server_pro_pi_message_size_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();
        let msg_text = (0..=3_000_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        let response = rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(msg_text, response.as_str());

        // sleep as bandwidth inserted on own thread
        sleep!();

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 3_000_001);
    }

    #[tokio::test]
    /// Pro user, from client to pi,  msg size > 3mb < 5mb
    async fn ws_server_pro_client_message_size_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        let msg_text = (0..=3_000_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        let response = rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(msg_text, response.as_str());

        // sleep as bandwidth inserted on own thread
        sleep!();

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 3_000_001);
    }

    #[tokio::test]
    /// Pro user, from pi to client, msg size > 5mb
    async fn ws_server_pro_pi_message_size_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();
        let msg_text = (0..=5_000_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("message size test error")
        };

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_none());
    }

    #[tokio::test]
    /// Pro user, from client to pi, msg size > 5mb
    async fn ws_server_pro_client_message_size_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Pro).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        let msg_text = (0..=5_000_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("message size test error")
        };

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_none());
    }

    #[tokio::test]
    /// Pro user, from pi to client, msg size > 5mb, structured data
    async fn ws_server_pro_pi_message_size_err_structured() {
        let mut test_setup = start_servers().await;
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
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let long_msg = (0..=5_000_000).map(|_| S!("a")).collect::<String>();

        let msg_text = format!(r#"{{"data":{long_msg}}}"#);

        let msg = Message::from(msg_text);
        ws_pi.send(msg).await.unwrap();

        let result = ws_pi.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(
            result,
            r#"{"error":{"message":"message size too large","code":413}}"#
        );

        // Sleep due to bandwidth insertion on own thread
        sleep!();
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 57);
    }

    #[tokio::test]
    /// Pro user, from pi to client, msg size > 5mb, structured data
    async fn ws_server_pro_client_message_size_err_structured() {
        let mut test_setup = start_servers().await;
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
        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;

        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let long_msg = (0..=5_000_000).map(|_| S!("a")).collect::<String>();

        let msg_text = format!(r#"{{"data":{long_msg}}}"#);

        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        let result = ws_client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        assert_eq!(
            result,
            r#"{"error":{"message":"message size too large","code":413}}"#
        );

        // Sleep due to bandwidth insertion on own thread
        sleep!();
        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();
        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 57);
    }

    // Admin user 10mb msg size
    #[tokio::test]
    /// Admin user, from pi to client, msg size > 5mb < 10mb
    async fn ws_server_admin_pi_message_size_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();
        let msg_text = (0..=8_000_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        let response = rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(msg_text, response.as_str());

        // sleep as bandwidth inserted on own thread
        sleep!();

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 8_000_001);
    }

    #[tokio::test]
    /// Admin user, from client to pi,  msg size > 5mb < 10mb
    async fn ws_server_admin_client_message_size_ok() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        let msg_text = (0..=8_000_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        let response = rx.next().await.unwrap().unwrap().into_text().unwrap();
        assert_eq!(msg_text, response.as_str());

        // sleep as bandwidth inserted on own thread
        sleep!();

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_some());
        let bandwidth = bandwidth.unwrap();
        assert_eq!(bandwidth.size_in_bytes, 8_000_001);
    }

    #[tokio::test]
    /// Admin user, from pi to client, msg size > 10mb
    async fn ws_server_admin_pi_message_size_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (mut ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_client.split();
        let msg_text = (0..=10_000_000).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_pi.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("message size test error")
        };

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_none());
    }

    #[tokio::test]
    /// Admin user, from client to pi, msg size > 5mb
    async fn ws_server_admin_client_message_size_err() {
        let mut test_setup = start_servers().await;
        let authed_cookie = test_setup.authed_user_cookie().await;
        test_setup.change_user_level(UserLevel::Admin).await;
        test_setup.insert_device(&authed_cookie, None).await;
        let url = test_setup.get_access_code(ConnectionType::Pi, 0).await;

        let ws_pi = connect_async(&url).await;
        assert!(ws_pi.is_ok());
        let (ws_pi, _) = ws_pi.unwrap();

        let url = test_setup.get_access_code(ConnectionType::Client, 0).await;
        let ws_client = connect_async(&url).await;
        assert!(ws_client.is_ok());
        let (mut ws_client, _) = ws_client.unwrap();

        let (_, mut rx) = ws_pi.split();
        let msg_text = (0..=10_000_001).map(|_| S!("a")).collect::<String>();
        let msg = Message::from(C!(msg_text));
        ws_client.send(C!(msg)).await.unwrap();

        // Wait 2 second to recevive a message, should never occur
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut rx.next())
            .await
            .is_ok()
        {
            unreachable!("message size test error")
        };

        let bandwidth = ModelMonthlyBandwidth::get(
            &test_setup.postgres,
            &test_setup.redis,
            test_setup.get_user_id(),
        )
        .await
        .unwrap();

        assert!(bandwidth.is_none());
    }
}

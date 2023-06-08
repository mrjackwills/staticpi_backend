use crate::{
    api_error::ApiError,
    connections::{AMConnections, Connections},
    database::{
        self, device::ModelWsDevice, monthly_bandwidth::ModelMonthlyBandwidth,
        rate_limit::RateLimit, session::RedisSession,
    },
    emailer::EmailerEnv,
    parse_env::{AppEnv, RunMode},
    user_io::outgoing_json::oj::{AsJsonRes, OutgoingJson},
};
use axum::{
    async_trait,
    extract::{ConnectInfo, FromRef, FromRequestParts, OriginalUri, State},
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
    Router,
};
use axum_extra::extract::{cookie::Key, PrivateCookieJar};
use redis::aio::Connection;
use sqlx::PgPool;
use std::{
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::SystemTime,
};
use tokio::{signal, sync::Mutex};
use tracing::info;
use ulid::Ulid;

pub mod api;
pub mod token;
pub mod ws;

pub type AMRedis = Arc<Mutex<Connection>>;

pub trait ApiRouter {
    fn create_router(state: &ApplicationState) -> Router<ApplicationState>;
}

pub struct ServeData {
    pub app_env: AppEnv,
    pub connections: AMConnections,
    pub postgres: PgPool,
    pub redis: AMRedis,
    pub server_name: ServerName,
}

impl ServeData {
    pub async fn new(
        app_env: &AppEnv,
        connections: &AMConnections,
        server_name: ServerName,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            app_env: app_env.clone(),
            connections: Arc::clone(connections),
            postgres: database::db_postgres::db_pool(app_env).await?,
            redis: Arc::new(Mutex::new(
                database::DbRedis::get_connection(app_env).await?,
            )),
            server_name,
        })
    }
}

#[async_trait]
pub trait Serve {
    async fn serve(serve_data: ServeData) -> Result<(), ApiError>;
}

type StatusOJ<T> = (axum::http::StatusCode, AsJsonRes<T>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerName {
    Api,
    Token,
    Ws,
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Api => write!(f, "api"),
            Self::Token => write!(f, "token"),
            Self::Ws => write!(f, "ws"),
        }
    }
}

impl ServerName {
    pub fn show_name(self, addr: &SocketAddr) {
        info!("starting server::{self} @ {addr}");
    }
}

// should have a db struct, then can easily call both without?
#[derive(Clone)]
pub struct ApplicationState {
    pub connections: Arc<Mutex<Connections>>,
    pub cookie_name: String,
    pub domain: String,
    pub email_env: EmailerEnv,
    pub postgres: PgPool,
    pub redis: AMRedis,
    pub run_mode: RunMode,
    pub start_time: SystemTime,
    cookie_key: Key,
    invite: String,
}

impl ApplicationState {
    // Should take in serve_data!
    pub fn new(serve_data: ServeData) -> Self {
        Self {
            connections: Arc::clone(&serve_data.connections),
            cookie_key: Key::from(&serve_data.app_env.cookie_secret),
            cookie_name: serve_data.app_env.cookie_name.clone(),
            domain: serve_data.app_env.domain.clone(),
            email_env: EmailerEnv::new(&serve_data.app_env),
            invite: serve_data.app_env.invite.clone(),
            postgres: serve_data.postgres,
            redis: serve_data.redis,
            run_mode: serve_data.app_env.run_mode,
            start_time: serve_data.app_env.start_time,
        }
    }
}

impl FromRef<ApplicationState> for Key {
    fn from_ref(state: &ApplicationState) -> Self {
        state.cookie_key.clone()
    }
}

const X_REAL_IP: &str = "x-real-ip";
const X_FORWARDED_FOR: &str = "x-forwarded-for";
const USER_AGENT: &str = "user-agent";

/// extract `x-forwarded-for` header
fn x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_FORWARDED_FOR)
        .and_then(|x| x.to_str().ok())
        .and_then(|s| s.split(',').find_map(|s| s.trim().parse::<IpAddr>().ok()))
}

/// extract the `x-real-ip` header
fn x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(X_REAL_IP)
        .and_then(|x| x.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
}

/// Get a users ip address, application should always be behind an nginx reverse proxy
/// so header x-forwarded-for should always be valid, then try x-real-ip
/// if neither headers work, use the optional socket address from axum
/// but if for some nothing works, return ipv4 255.255.255.255
pub fn get_ip(headers: &HeaderMap, addr: ConnectInfo<SocketAddr>) -> IpAddr {
    x_forwarded_for(headers)
        .or_else(|| x_real_ip(headers))
        .map_or(addr.0.ip(), |ip_addr| ip_addr)
}

/// Check the current monthly bandwidth of user
/// Should take into account the incoming message size?
async fn check_monthly_bandwidth(
    postgres: &PgPool,
    redis: &AMRedis,
    device: &ModelWsDevice,
) -> Result<(), ApiError> {
    match ModelMonthlyBandwidth::get(postgres, redis, device.registered_user_id).await {
        Ok(Some(data)) => {
            if data.size_in_bytes >= device.max_monthly_bandwidth_in_bytes {
                return Err(ApiError::Internal("max monthly bandwidth".to_owned()));
            }
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Extract the user-agent string
pub fn get_user_agent_header(headers: &HeaderMap) -> String {
    headers
        .get(USER_AGENT)
        .and_then(|x| x.to_str().ok())
        .unwrap_or("UNKNOWN")
        .to_owned()
}

/// Parse a hostname + port number into a bind-able `SocketAddr`
fn parse_addr(host: &str, port: u16) -> Result<SocketAddr, ApiError> {
    match (host, port).to_socket_addrs() {
        Ok(i) => {
            let vec_i = i.take(1).collect::<Vec<SocketAddr>>();
            vec_i
                .get(0)
                .map_or(Err(ApiError::Internal("No addr".to_string())), |addr| {
                    Ok(*addr)
                })
        }
        Err(e) => Err(ApiError::Internal(e.to_string())),
    }
}

/// Create a /v[x] prefix for all api routes, where x is the current major version
fn get_api_version() -> String {
    format!(
        "/v{}",
        env!("CARGO_PKG_VERSION")
            .split('.')
            .take(1)
            .collect::<String>()
    )
}

#[allow(clippy::expect_used)]
async fn shutdown_signal(server_name: &ServerName) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!(
        "signal received, starting graceful shutdown - {}",
        server_name
    );
}

/// return a unknown endpoint response
#[allow(clippy::unused_async)]
pub async fn fallback(
    OriginalUri(original_uri): OriginalUri,
) -> (axum::http::StatusCode, AsJsonRes<String>) {
    (
        axum::http::StatusCode::NOT_FOUND,
        OutgoingJson::new(format!("unknown endpoint: {original_uri}")),
    )
}

// Limit the users request based on ip address, using redis as mem store
async fn rate_limiting<B: Send + Sync>(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let addr = ConnectInfo::<SocketAddr>::from_request_parts(&mut parts, &state).await?;
    let ip = get_ip(&parts.headers, addr);
    let mut key = RateLimit::Ip(ip);

    if let Some(data) = jar.get(&state.cookie_name) {
        if let Ok(ulid) = Ulid::from_string(data.value()) {
            if let Some(user) = RedisSession::exists(&state.redis, &ulid).await? {
                key = RateLimit::User(user.registered_user_id);
            }
        }
    }
    key.check(&state.redis).await?;
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// http tests - ran via actual requests to a (local) server
/// cargo watch -q -c -w src/ -x 'test http_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
pub mod test_setup {
    use redis::{aio::Connection, AsyncCommands};
    use reqwest::Url;

    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use sqlx::PgPool;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;

    use crate::connections::ConnectionType;
    use crate::connections::Connections;
    use crate::database::connection::ModelConnection;
    use crate::database::email_address::ModelEmailAddress;
    use crate::database::invite::ModelInvite;
    use crate::database::ip_user_agent::ModelUserAgentIp;
    use crate::database::ip_user_agent::ReqUserAgentIp;
    use crate::database::new_types::*;
    use crate::database::new_user::RedisNewUser;
    use crate::database::password_reset::ModelPasswordReset;
    use crate::database::two_fa_backup::ModelTwoFA;
    use crate::database::two_fa_setup::RedisTwoFASetup;
    use crate::database::user::ModelUser;
    use crate::database::user_level::ModelUserLevel;
    use crate::database::user_level::UserLevel;
    use crate::database::*;
    use crate::helpers::gen_random_hex;
    use crate::parse_env;
    use crate::parse_env::AppEnv;
    use crate::servers::api::authentication::totp_from_secret;
    use crate::sleep;
    use crate::user_io::incoming_json::ij;
    use crate::user_io::incoming_json::ij::DevicePost;
    use crate::ServeData;

    use super::api::ApiServer;
    use super::get_api_version;
    use super::token::TokenServer;
    use super::ws::WsServer;
    use super::Serve;
    use super::ServerName;

    pub const TEST_EMAIL: &str = "test_user@email.com";
    pub const TEST_PASSWORD: &str = "N}}2&zwhgUmfVup[g))EmCchQxcu%R~x";
    pub const TEST_PASSWORD_HASH: &str = "$argon2id$v=19$m=4096,t=1,p=1$D/DKFfvJbZOBICD6y/798w$ifr1qDS9aQLyRPT+57ZOKmfUnrju+fbkEpiK6w2ADuo";
    pub const TEST_FULL_NAME: &str = "Test user full name";

    pub const UNSAFE_PASSWORD: &str = "iloveyou1234";

    pub const TEST_USER_AGENT: &str = "test_user_agent";

    pub const ANON_EMAIL: &str = "anon_user@email.com";
    pub const ANON_PASSWORD: &str = "this_is_the_anon_test_user_password";
    pub const ANON_PASSWORD_HASH: &str = "$argon2id$v=19$m=4096,t=1,p=1$ODYzbGwydnl4YzAwMDAwMA$x0HG3MOFFlMEDQoVNNacku3lj7yx2Mniacytc+ULPxU8GPj+";
    pub const ANON_FULL_NAME: &str = "Anon user full name";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Response {
        pub response: Value,
    }

    #[derive(sqlx::FromRow, Debug, Clone)]
    pub struct DeviceQuery {
        pub device_id: DeviceId,
        pub registered_user_id: UserId,
        pub ip_id: IpId,
        pub user_agent_id: UserAgentId,
        pub api_key_id: ApiKeyId,
        pub api_key_string: String,
        pub device_name_id: DeviceNameId,
        pub structured_data: bool,
        pub paused: bool,
        pub client_password_id: Option<DevicePasswordId>,
        pub device_password_id: Option<DevicePasswordId>,
        pub max_clients: i16,
        pub active: bool,
    }

    pub struct TestSetup {
        pub token_handle: Option<JoinHandle<()>>,
        pub ws_handle: Option<JoinHandle<()>>,
        pub api_handle: Option<JoinHandle<()>>,
        pub app_env: AppEnv,
        pub redis: Arc<Mutex<Connection>>,
        pub postgres: PgPool,
        pub model_user: Option<ModelUser>,
        pub anon_user: Option<ModelUser>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct TestBodySignin {
        pub email: String,
        pub password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub token: Option<String>,
        pub remember: bool,
    }

    pub fn api_base_url(app_env: &AppEnv) -> String {
        format!("http://127.0.0.1:{}{}", app_env.api_port, get_api_version())
    }

    pub fn token_base_url(app_env: &AppEnv) -> String {
        format!("http://127.0.0.1:{}", app_env.auth_port)
    }

    pub fn ws_base_url(app_env: &AppEnv) -> String {
        format!("ws://127.0.0.1:{}", app_env.ws_port)
    }

    /// Cleanup the test environment, and close postgres connection
    impl TestSetup {
        async fn clean_up(&mut self) {
            self.delete_two_fa_secret().await;
            self.delete_invite().await;
            self.delete_devices().await;
            self.delete_email_log().await;
            self.delete_contact_message().await;
            self.delete_test_users().await;
            self.delete_useragent_ip().await;
            self.delete_login_attempts().await;
            Self::delete_emails();
            self.flush_redis().await;
        }

        /// Delete all redis keys
        pub async fn flush_redis(&self) {
            redis::cmd("FLUSHDB")
                .query_async::<_, ()>(&mut *self.redis.lock().await)
                .await
                .unwrap();
        }

        /// generate user ip address, user agent, normally done in middleware automatically by server
        pub fn gen_req() -> ReqUserAgentIp {
            ReqUserAgentIp {
                user_agent: String::from(TEST_USER_AGENT),
                ip: IpAddr::V4(Ipv4Addr::new(123, 123, 123, 123)),
            }
        }

        /// Delete all login_attempt from db
        pub async fn delete_login_attempts(&self) {
            let query = r"DELETE FROM login_attempt";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
        }

        /// Delete email_subjects & email logs
        /// Sleep issue, as emails and sent, and put onto db, in another thread, and not waited for!
        pub async fn delete_email_log(&self) {
            let query = r"DELETE FROM email_log";
            sqlx::query(query).execute(&self.postgres).await.unwrap();

            let query = r"DELETE FROM email_subject";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
        }

        /// Delete any invites
        pub async fn delete_invite(&self) {
            let query = r"DELETE FROM invite_code";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
        }

        /// Delete any invites
        pub async fn delete_contact_message(&self) {
            let query = r"DELETE FROM contact_message";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
        }

        /// Delete two fa secrets
        pub async fn delete_two_fa_secret(&self) {
            if let Some(user) = self.model_user.as_ref() {
                let query = r"DELETE FROM two_fa_secret WHERE registered_user_id = $1;";
                sqlx::query(query)
                    .bind(user.registered_user_id.get())
                    .execute(&self.postgres)
                    .await
                    .unwrap();
            }
        }

        /// Delete devices
        pub async fn delete_devices(&self) {
            let query = r"DELETE FROM api_key;";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
            let query = r"DELETE FROM device_password;";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
            let query = r"DELETE FROM device_name;";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
            let query = r"DELETE FROM connection;";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
            let query = r"DELETE FROM hourly_bandwidth;";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
            let query = r"DELETE FROM device;";
            sqlx::query(query).execute(&self.postgres).await.unwrap();
        }

        /// Remove test user from postgres
        pub async fn delete_test_users(&self) {
            let query = r"DELETE FROM registered_user WHERE full_name = $1 OR full_name = $2;";
            sqlx::query(query)
                .bind(ANON_FULL_NAME)
                .bind(TEST_FULL_NAME)
                .execute(&self.postgres)
                .await
                .unwrap();

            let query = r"DELETE FROM email_address WHERE email = $1 OR EMAIL = $2;";
            sqlx::query(query)
                .bind(TEST_EMAIL)
                .bind(ANON_EMAIL)
                .execute(&self.postgres)
                .await
                .unwrap();
        }

        /// Delete emails that were written to disk
        pub fn delete_emails() {
            std::fs::remove_file("/dev/shm/email_headers.txt").ok();
            std::fs::remove_file("/dev/shm/email_body.txt").ok();
        }

        // Insert bandwidth, same thread as caller, unlike the actual method
        pub async fn insert_bandwidth(
            &self,
            device_id: DeviceId,
            size_in_bytes: i64,
            device_type: ConnectionType,
            is_counted: bool,
        ) {
            let query = r"
			INSERT INTO hourly_bandwidth
				(device_id, size_in_bytes, is_pi, is_counted)
			VALUES
				($1, $2, $3, $4)
			ON CONFLICT (
					extract(year FROM (timestamp AT TIME ZONE 'UTC')),
					extract(month FROM (timestamp AT TIME ZONE 'UTC')),
					extract(day FROM (timestamp AT TIME ZONE 'UTC')),
					extract(hour FROM (timestamp AT TIME ZONE 'UTC')),
					device_id,
					is_pi,
					is_counted
				)
			DO UPDATE
			SET
				size_in_bytes = hourly_bandwidth.size_in_bytes + $2";
            sqlx::query(query)
                .bind(device_id.get())
                .bind(size_in_bytes)
                .bind(device_type.is_pi())
                .bind(is_counted)
                .execute(&self.postgres)
                .await
                .unwrap();
        }

        /// Delete the useragent and ip from database
        pub async fn delete_useragent_ip(&self) {
            let req = Self::gen_req();
            let query = r"DELETE FROM ip_address WHERE ip = $1::inet";
            sqlx::query(query)
                .bind(req.ip.to_string())
                .execute(&self.postgres)
                .await
                .unwrap();

            let query = r"DELETE FROM user_agent WHERE user_agent_string = $1";
            sqlx::query(query)
                .bind(req.user_agent)
                .execute(&self.postgres)
                .await
                .unwrap();
        }

        pub async fn get_model_user(&self) -> Option<ModelUser> {
            ModelUser::get(&self.postgres, TEST_EMAIL).await.unwrap()
        }

        pub async fn get_session(&self, user_id: UserId) -> Option<String> {
            let sessions: Vec<String> = self
                .redis
                .lock()
                .await
                .smembers(format!("session_set::user::{}", user_id.get()))
                .await
                .unwrap();
            sessions.get(0).map(|i| i.to_owned())
        }

        pub fn get_user_id(&self) -> UserId {
            self.model_user.as_ref().unwrap().registered_user_id
        }

        pub async fn get_anon_user(&self) -> Option<ModelUser> {
            ModelUser::get(&self.postgres, ANON_EMAIL).await.unwrap()
        }

        /// Somewhat diry way to insert an invite, this will fail if no user is registered!
        pub async fn insert_invite(&mut self) -> String {
            let user = self.model_user.as_ref().unwrap();

            let req = ModelUserAgentIp::get(&self.postgres, &self.redis, &Self::gen_req())
                .await
                .unwrap();
            let invite = gen_random_hex(12);
            ModelInvite::insert(&self.postgres, req, 1, user, &invite)
                .await
                .unwrap();
            invite
        }

        /// Somewhat diry way to insert a new user - uses server & json requests etc
        pub async fn insert_test_user(&mut self) {
            let req = ModelUserAgentIp::get(&self.postgres, &self.redis, &Self::gen_req())
                .await
                .unwrap();

            let email = ModelEmailAddress::insert(&self.postgres, TEST_EMAIL)
                .await
                .unwrap();

            let new_user = RedisNewUser {
                email: TEST_EMAIL.to_owned(),
                email_address_id: email.email_address_id,
                full_name: TEST_FULL_NAME.to_owned(),
                password_hash: TEST_PASSWORD_HASH.to_string(),
                ip_id: req.ip_id,
                user_agent_id: req.user_agent_id,
            };

            ModelUser::insert(&self.postgres, &new_user).await.unwrap();
            self.model_user = self.get_model_user().await;
        }

        /// Insert new anon user, also has twofa
        pub async fn insert_anon_user(&mut self) {
            let req = ModelUserAgentIp::get(&self.postgres, &self.redis, &Self::gen_req())
                .await
                .unwrap();

            let email = ModelEmailAddress::insert(&self.postgres, ANON_EMAIL)
                .await
                .unwrap();

            let new_user = RedisNewUser {
                email: ANON_EMAIL.to_owned(),
                email_address_id: email.email_address_id,
                full_name: ANON_FULL_NAME.to_owned(),
                password_hash: ANON_PASSWORD_HASH.to_string(),
                ip_id: req.ip_id,
                user_agent_id: req.user_agent_id,
            };

            ModelUser::insert(&self.postgres, &new_user).await.unwrap();

            let anon_user = self.get_anon_user().await;

            let secret = gen_random_hex(32);
            let two_fa_setup = RedisTwoFASetup::new(&secret);
            let req = ModelUserAgentIp::get(&self.postgres, &self.redis, &Self::gen_req())
                .await
                .unwrap();
            ModelTwoFA::insert(
                &self.postgres,
                two_fa_setup,
                &req,
                anon_user.as_ref().unwrap(),
            )
            .await
            .unwrap();
            self.anon_user = self.get_anon_user().await;
        }

        pub async fn two_fa_always_required(&mut self, setting: bool) {
            ModelTwoFA::update_always_required(
                &self.postgres,
                setting,
                self.model_user.as_ref().unwrap(),
            )
            .await
            .unwrap();
            self.model_user = self.get_model_user().await;
        }

        // Assumes a test user is already in database, then insert a twofa_secret into postgres
        pub async fn insert_two_fa(&mut self) {
            let secret = gen_random_hex(32);
            let two_fa_setup = RedisTwoFASetup::new(&secret);
            let req = ModelUserAgentIp::get(&self.postgres, &self.redis, &Self::gen_req())
                .await
                .unwrap();
            ModelTwoFA::insert(
                &self.postgres,
                two_fa_setup,
                &req,
                self.model_user.as_ref().unwrap(),
            )
            .await
            .unwrap();
            self.delete_email_log().await;
            self.model_user = self.get_model_user().await;
        }

        /// turn the test user into given userleve
        pub async fn change_user_level(&self, level: UserLevel) {
            if let Some(user) = self.model_user.as_ref() {
                let user_level = ModelUserLevel::get(&self.postgres, level).await.unwrap();

                let query =
                    "UPDATE registered_user SET user_level_id = $1 WHERE registered_user_id = $2";
                sqlx::query(query)
                    .bind(user_level.user_level_id.get())
                    .bind(user.registered_user_id.get())
                    .execute(&self.postgres)
                    .await
                    .unwrap();
            }
        }

        /// turn the anon user into given userlevel
        pub async fn change_anon_user_level(&self, level: UserLevel) {
            if let Some(user) = self.anon_user.as_ref() {
                let user_level = ModelUserLevel::get(&self.postgres, level).await.unwrap();

                let query =
                    "UPDATE registered_user SET user_level_id = $1 WHERE registered_user_id = $2";
                sqlx::query(query)
                    .bind(user_level.user_level_id.get())
                    .bind(user.registered_user_id.get())
                    .execute(&self.postgres)
                    .await
                    .unwrap();
            }
        }

        pub fn get_client() -> reqwest::Client {
            let req = Self::gen_req();
            reqwest::Client::builder()
                .user_agent(req.user_agent)
                .build()
                .unwrap()
        }

        /// Send a request to insert a password_reset
        pub async fn request_reset(&mut self) -> String {
            let url = format!("{}/incognito/reset", api_base_url(&self.app_env));
            let body = HashMap::from([("email", TEST_EMAIL)]);
            Self::get_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap();
            ModelPasswordReset::get_by_email(&self.postgres, TEST_EMAIL)
                .await
                .unwrap()
                .unwrap()
                .reset_string
        }

        /// attempt a signin in with an invalid password
        pub async fn invalid_signin(&mut self, email: &str) {
            let url = format!("{}/incognito/signin", api_base_url(&self.app_env));
            let body =
                Self::gen_signin_body(Some(email.to_owned()), Some(gen_random_hex(20)), None, None);
            Self::get_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap();
        }

        /// Insert a user, and sign in, then return the cookie so that other requests can be authenticated
        pub async fn authed_user_cookie(&mut self) -> String {
            self.insert_test_user().await;
            let url = format!("{}/incognito/signin", api_base_url(&self.app_env));
            let body = Self::gen_signin_body(None, None, None, None);
            let signin = Self::get_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap();
            self.delete_email_log().await;
            signin
                .headers()
                .get("set-cookie")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        }

        /// Sign in the anon user (Required anon_user to be inserted beforehand), and return cookie string
        pub async fn anon_user_cookie(&mut self) -> Option<String> {
            // Need to get token
            let token = totp_from_secret(
                self.anon_user
                    .as_ref()
                    .unwrap()
                    .two_fa_secret
                    .as_ref()
                    .unwrap(),
            )
            .unwrap()
            .generate_current()
            .unwrap();

            let url = format!("{}/incognito/signin", api_base_url(&self.app_env));
            let body = Self::gen_signin_body(
                Some(ANON_EMAIL.to_owned()),
                Some(ANON_PASSWORD.to_owned()),
                Some(token),
                None,
            );
            let signin = Self::get_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap();
            signin
                .headers()
                .get("set-cookie")
                .map(|f| f.to_str().unwrap().to_owned())
        }

        pub async fn query_password_hash(&self) -> String {
            #[derive(sqlx::FromRow)]
            struct P {
                password_hash: String,
            }
            let query = r"SELECT password_hash FROM registered_user WHERE email_address_id = $1";
            sqlx::query_as::<_, P>(query)
                .bind(self.model_user.as_ref().unwrap().email_address_id.get())
                .fetch_one(&self.postgres)
                .await
                .unwrap()
                .password_hash
        }

        /// Get Test users active devices
        pub async fn query_user_active_devices(&self) -> Vec<DeviceQuery> {
            let query = r"SELECT de.*, ap.api_key_string FROM device de LEFT JOIN api_key ap USING(api_key_id) WHERE de.registered_user_id = $1 AND de.active = true";
            sqlx::query_as::<_, DeviceQuery>(query)
                .bind(self.model_user.as_ref().unwrap().registered_user_id.get())
                .fetch_all(&self.postgres)
                .await
                .unwrap()
        }

        async fn query_anon_user_active_devices(&self) -> Vec<DeviceQuery> {
            let query = r"SELECT de.*, ap.api_key_string FROM device de LEFT JOIN api_key ap USING(api_key_id) WHERE de.registered_user_id = $1 AND de.active = true";
            sqlx::query_as::<_, DeviceQuery>(query)
                .bind(self.anon_user.as_ref().unwrap().registered_user_id.get())
                .fetch_all(&self.postgres)
                .await
                .unwrap()
        }

        // Generate signin body
        pub fn gen_signin_body(
            email: Option<String>,
            password: Option<String>,
            token: Option<String>,
            remember: Option<bool>,
        ) -> TestBodySignin {
            TestBodySignin {
                email: email.unwrap_or_else(|| TEST_EMAIL.to_owned()),
                password: password.unwrap_or_else(|| TEST_PASSWORD.to_owned()),
                token,
                remember: remember.unwrap_or(false),
            }
        }

        pub async fn insert_device(
            &self,
            authed_cookie: &str,
            device: Option<DevicePost>,
        ) -> String {
            let url = format!("{}/authenticated/device", api_base_url(&self.app_env),);
            let body = device.unwrap_or_else(|| Self::gen_device_post(1, None, None, false, None));
            let result = Self::get_client()
                .post(&url)
                .header("cookie", authed_cookie)
                .json(&body)
                .send()
                .await
                .unwrap();
            let result = result.json::<Response>().await.unwrap().response;
            result.as_str().unwrap().to_owned()
        }

        pub async fn get_access_code(&self, device_type: ConnectionType, index: usize) -> Url {
            let device = self.query_user_active_devices().await[index].clone();
            let url = format!("{}/{}", &token_base_url(&self.app_env), device_type);
            let body = HashMap::from([("key", device.api_key_string)]);
            let result = Self::get_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap();
            let result = result.json::<Response>().await.unwrap().response;
            Url::parse(&format!(
                "{}/{}/{}",
                ws_base_url(&self.app_env),
                device_type,
                result.as_str().unwrap()
            ))
            .unwrap()
        }

        pub async fn get_anon_access_code(&self, device_type: ConnectionType, index: usize) -> Url {
            let device = self.query_anon_user_active_devices().await[index].clone();
            let url = format!("{}/{}", &token_base_url(&self.app_env), device_type);
            let body = HashMap::from([("key", device.api_key_string)]);
            let result = Self::get_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap();
            let result = result.json::<Response>().await.unwrap().response;
            Url::parse(&format!(
                "{}/{}/{}",
                ws_base_url(&self.app_env),
                device_type,
                result.as_str().unwrap()
            ))
            .unwrap()
        }

        // device de
        // ON
        // co.device_id = de.device_id
        // LEFT JOIN
        // ip_address ipa
        // ON
        // co.ip_id = ipa.ip_id
        /// will sleep before query!
        pub async fn get_connections(
            &self,
            device_type: ConnectionType,
            name_of_device: &str,
        ) -> Vec<ModelConnection> {
            let query = r#"
			SELECT
				ipa.ip,
				co.connection_id, co.timestamp_online::TEXT, co.timestamp_offline::TEXT
			FROM
				connection co
			LEFT JOIN ip_address ipa USING(ip_id)
			LEFT JOIN device de USING(device_id)
			LEFT JOIN
				device_name dn
			ON
				de.device_name_id = dn.device_name_id
		
			WHERE
				de.registered_user_id = $1
			AND	
				co.is_pi = $2
			AND
				dn.name_of_device = $3
			ORDER BY
				co.timestamp_online"#;
            sqlx::query_as::<_, ModelConnection>(query)
                .bind(self.model_user.as_ref().unwrap().registered_user_id.get())
                .bind(device_type == ConnectionType::Pi)
                .bind(name_of_device)
                .fetch_all(&self.postgres)
                .await
                .unwrap()
        }

        pub fn gen_device_post(
            max_clients: i16,
            client_password: Option<&str>,
            device_password: Option<&str>,
            structured_data: bool,
            name: Option<&str>,
        ) -> DevicePost {
            DevicePost {
                max_clients,
                client_password: client_password.map(|i| i.to_owned()),
                device_password: device_password.map(|i| i.to_owned()),
                structured_data,
                name: name.map(|i| i.to_owned()),
            }
        }

        pub fn get_invalid_token(&self) -> String {
            totp_from_secret(
                self.model_user
                    .as_ref()
                    .unwrap()
                    .two_fa_secret
                    .as_ref()
                    .unwrap(),
            )
            .unwrap()
            .generate(123_456_789)
        }

        pub fn get_valid_token(&self) -> String {
            totp_from_secret(
                self.model_user
                    .as_ref()
                    .unwrap()
                    .two_fa_secret
                    .as_ref()
                    .unwrap(),
            )
            .unwrap()
            .generate_current()
            .unwrap()
        }

        // Generate register body
        pub fn gen_register_body(
            full_name: &str,
            password: &str,
            invite: &str,
            email: &str,
            age: bool,
            agree: bool,
        ) -> ij::Register {
            ij::Register {
                full_name: full_name.to_owned(),
                password: password.to_owned(),
                invite: invite.to_owned(),
                email: email.to_owned(),
                age,
                agree,
            }
        }
    }

    /// Get basic api params, also flushes all redis keys, deletes all test data, DOESN'T start the api server
    pub async fn setup() -> TestSetup {
        let app_env = parse_env::AppEnv::get_env();
        let postgres = db_postgres::db_pool(&app_env).await.unwrap();
        let redis = Arc::new(Mutex::new(DbRedis::get_connection(&app_env).await.unwrap()));
        let mut test_setup = TestSetup {
            api_handle: None,
            token_handle: None,
            ws_handle: None,
            app_env,
            postgres,
            redis,
            model_user: None,
            anon_user: None,
        };
        test_setup.clean_up().await;
        test_setup
    }

    /// start the api server on it's own thread
    pub async fn start_servers() -> TestSetup {
        let setup = setup().await;
        let app_env = setup.app_env.clone();
        let redis = Arc::clone(&setup.redis);
        let postgres = setup.postgres.clone();
        let connections = Arc::new(Mutex::new(Connections::default()));

        let api_data = ServeData {
            app_env: app_env.clone(),
            connections: Arc::clone(&connections),
            postgres: postgres.clone(),
            redis: Arc::clone(&redis),
            server_name: ServerName::Api,
        };

        let api_handle = tokio::spawn(async {
            ApiServer::serve(api_data).await.unwrap();
        });

        let auth_data = ServeData {
            app_env: app_env.clone(),
            connections: Arc::clone(&connections),
            postgres: postgres.clone(),
            redis: Arc::clone(&redis),
            server_name: ServerName::Token,
        };

        let auth_handle = tokio::spawn(async {
            TokenServer::serve(auth_data).await.unwrap();
        });

        let ws_data = ServeData {
            app_env: app_env.clone(),
            connections: Arc::clone(&connections),
            postgres: postgres.clone(),
            redis: Arc::clone(&redis),
            server_name: ServerName::Ws,
        };

        let ws_handle = tokio::spawn(async {
            WsServer::serve(ws_data).await.unwrap();
        });

        // just sleep to make sure the server is running - 1ms is enough
        sleep!(1);

        TestSetup {
            api_handle: Some(api_handle),
            token_handle: Some(auth_handle),
            ws_handle: Some(ws_handle),
            app_env: setup.app_env,
            redis: setup.redis,
            postgres: setup.postgres,
            model_user: None,
            anon_user: None,
        }
    }
}

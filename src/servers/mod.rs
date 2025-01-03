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
    C, S,
};
use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts, OriginalUri, State},
    http::{request::Parts, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
    Router,
};
use axum_extra::extract::{cookie::Key, PrivateCookieJar};

use fred::clients::Pool;
use sqlx::PgPool;
use std::{
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    ops::Deref,
    sync::Arc,
    time::SystemTime,
};
use tokio::{signal, sync::Mutex};
use ulid::Ulid;

pub mod api;
pub mod token;
pub mod ws;

pub trait ApiRouter {
    fn create_router(state: &ApplicationState) -> Router<ApplicationState>;
}

pub struct ServeData {
    pub app_env: AppEnv,
    pub connections: AMConnections,
    pub postgres: PgPool,
    pub redis: Pool,
    pub server_name: ServerName,
}

impl ServeData {
    pub async fn new(
        app_env: &AppEnv,
        connections: &AMConnections,
        server_name: ServerName,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            app_env: C!(app_env),
            connections: Arc::clone(connections),
            postgres: database::db_postgres::db_pool(app_env).await?,
            redis: database::DbRedis::get_pool(app_env).await?,
            server_name,
        })
    }
}

pub trait Serve {
    async fn serve(serve_data: ServeData) -> Result<(), ApiError>;
}

type StatusOJ<T> = (StatusCode, AsJsonRes<T>);

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
        tracing::info!("starting server::{self} @ {addr}");
    }
}

#[derive(Clone)]
pub struct ApplicationState(Arc<InnerState>);

// impl derfer mut
// deref so you can still access the inner fields easily
impl Deref for ApplicationState {
    type Target = InnerState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ApplicationState {
    pub fn new(serve_data: ServeData) -> Self {
        Self(Arc::new(InnerState::new(serve_data)))
    }
}

pub struct InnerState {
    pub connections: Arc<Mutex<Connections>>,
    pub cookie_name: String,
    pub domain: String,
    pub email_env: EmailerEnv,
    pub postgres: PgPool,
    pub redis: Pool,
    pub run_mode: RunMode,
    pub start_time: SystemTime,
    cookie_key: Key,
    invite: String,
}

impl InnerState {
    pub fn new(serve_data: ServeData) -> Self {
        Self {
            connections: Arc::clone(&serve_data.connections),
            cookie_key: Key::from(&serve_data.app_env.cookie_secret),
            cookie_name: C!(serve_data.app_env.cookie_name),
            domain: C!(serve_data.app_env.domain),
            email_env: EmailerEnv::new(&serve_data.app_env),
            invite: C!(serve_data.app_env.invite),
            postgres: serve_data.postgres,
            redis: serve_data.redis,
            run_mode: serve_data.app_env.run_mode,
            start_time: serve_data.app_env.start_time,
        }
    }
}

impl FromRef<ApplicationState> for Key {
    fn from_ref(state: &ApplicationState) -> Self {
        C!(state.0.cookie_key)
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
        .unwrap_or_else(|| addr.0.ip())
}

/// Check the current monthly bandwidth of user
/// Should take into account the incoming message size?
async fn check_monthly_bandwidth(
    postgres: &PgPool,
    redis: &Pool,
    device: &ModelWsDevice,
) -> Result<(), ApiError> {
    match ModelMonthlyBandwidth::get(postgres, redis, device.registered_user_id).await {
        Ok(Some(data)) => {
            if data.size_in_bytes >= device.max_monthly_bandwidth_in_bytes {
                return Err(ApiError::Internal(S!("max monthly bandwidth")));
            }
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Extract the user-agent string
pub fn get_user_agent_header(headers: &HeaderMap) -> String {
    S!(headers
        .get(USER_AGENT)
        .and_then(|x| x.to_str().ok())
        .unwrap_or("UNKNOWN"))
}

/// Parse a hostname + port number into a bind-able `SocketAddr`
fn parse_addr(host: &str, port: u16) -> Result<SocketAddr, ApiError> {
    match (host, port).to_socket_addrs() {
        Ok(i) => {
            let vec_i = i.take(1).collect::<Vec<SocketAddr>>();
            vec_i
                .first()
                .map_or(Err(ApiError::Internal(S!("No addr"))), |addr| Ok(*addr))
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

/// return a unknown endpoint response
pub async fn fallback(OriginalUri(original_uri): OriginalUri) -> (StatusCode, AsJsonRes<String>) {
    (
        StatusCode::NOT_FOUND,
        OutgoingJson::new(format!("unknown endpoint: {original_uri}")),
    )
}

async fn get_ratelimiter(
    state: &ApplicationState,
    jar: PrivateCookieJar,
    parts: &mut Parts,
) -> Result<RateLimit, ApiError> {
    if let Some(ulid) = get_cookie_ulid(state, &jar) {
        if let Some(user) = RedisSession::exists(&state.redis, &ulid).await? {
            return Ok(RateLimit::User(user.registered_user_id));
        }
    }
    let addr = ConnectInfo::<SocketAddr>::from_request_parts(parts, &state).await?;
    let ip = get_ip(&parts.headers, addr);
    Ok(RateLimit::Ip(ip))
}

/// Limit the users request based on ip address, using redis as mem store
async fn rate_limiting(
    State(state): State<ApplicationState>,
    jar: PrivateCookieJar,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let key = get_ratelimiter(&state, jar, &mut parts).await?;
    key.check(&state.redis).await?;
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Attempt to extract out a ULID from the cookie jar
pub fn get_cookie_ulid(state: &ApplicationState, jar: &PrivateCookieJar) -> Option<Ulid> {
    if let Some(data) = jar.get(&state.cookie_name) {
        if let Ok(ulid) = Ulid::from_string(data.value()) {
            return Some(ulid);
        }
    }
    None
}

#[expect(clippy::expect_used)]
async fn shutdown_signal(server_name: ServerName) {
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
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!(
        "signal received, starting graceful shutdown - {}",
        server_name
    );
}

/// http tests - ran via actual requests to a (local) server
/// cargo watch -q -c -w src/ -x 'test http_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
pub mod test_setup {

    use fred::clients::Pool;
    use fred::interfaces::ClientLike;
    use fred::interfaces::SetsInterface;
    use fred::types::scan::Scanner;
    use futures::TryStreamExt;
    use regex::Regex;
    use reqwest::Url;

    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use sqlx::PgPool;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::LazyLock;
    use tokio::sync::Mutex;

    use crate::connections::{ConnectionType, Connections};
    use crate::database::{
        connection::ModelConnection,
        email_address::ModelEmailAddress,
        invite::ModelInvite,
        ip_user_agent::{ModelUserAgentIp, ReqUserAgentIp},
        new_types::*,
        new_user::RedisNewUser,
        password_reset::ModelPasswordReset,
        two_fa_backup::ModelTwoFA,
        two_fa_setup::RedisTwoFASetup,
        user::ModelUser,
        user_level::{ModelUserLevel, UserLevel},
        *,
    };
    use crate::helpers::gen_random_hex;
    use crate::parse_env::{self, AppEnv};
    use crate::servers::api::authentication::totp_from_secret;
    use crate::sleep;
    use crate::user_io::incoming_json::ij;
    use crate::{ServeData, C, S};

    use super::api::{
        api_tests::{EMAIL_BODY_LOCATION, EMAIL_HEADERS_LOCATION},
        ApiServer,
    };
    // use super::api::;
    use super::{get_api_version, token::TokenServer, ws::WsServer, Serve, ServerName};

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

    pub static RATELIMIT_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("rate limited for ([5][0-9]|60) seconds").unwrap());

    pub static RATELIMIT_REGEX_BIG: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("rate limited for (29[0-9]|300) seconds").unwrap());

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Response {
        pub response: Value,
    }

    #[derive(sqlx::FromRow, Debug, Clone)]
    pub struct DeviceQuery {
        pub device_id: DeviceId,
        pub api_key_id: ApiKeyId,
        pub api_key_string: String,
        pub device_name_id: DeviceNameId,
        pub structured_data: bool,
        pub paused: bool,
        pub client_password_id: Option<DevicePasswordId>,
        pub device_password_id: Option<DevicePasswordId>,
        pub max_clients: i16,
    }

    pub struct TestSetup {
        pub app_env: AppEnv,
        pub redis: Pool,
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
            self.redis.flushall::<()>(true).await.unwrap();
        }

        /// generate user ip address, user agent, normally done in middleware automatically by server
        pub fn gen_req() -> ReqUserAgentIp {
            ReqUserAgentIp {
                user_agent: S!(TEST_USER_AGENT),
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
            let query = r"DELETE FROM registered_user WHERE full_name IN ($1, $2);";
            sqlx::query(query)
                .bind(ANON_FULL_NAME)
                .bind(TEST_FULL_NAME)
                .execute(&self.postgres)
                .await
                .unwrap();

            let query = r"DELETE FROM email_address WHERE email IN ($1, $2);";
            sqlx::query(query)
                .bind(TEST_EMAIL)
                .bind(ANON_EMAIL)
                .execute(&self.postgres)
                .await
                .unwrap();
        }

        /// Delete emails that were written to disk
        pub fn delete_emails() {
            std::fs::remove_file(EMAIL_HEADERS_LOCATION).ok();
            std::fs::remove_file(EMAIL_BODY_LOCATION).ok();
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

        pub async fn get_session(&mut self, user_id: UserId) -> Option<String> {
            let sessions: Vec<String> = self
                .redis
                .smembers(format!("session_set::user::{}", user_id.get()))
                .await
                .unwrap();
            sessions.first().map(|i| S!(i))
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
                email: S!(TEST_EMAIL),
                email_address_id: email.email_address_id,
                full_name: S!(TEST_FULL_NAME),
                password_hash: S!(TEST_PASSWORD_HASH),
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
                email: S!(ANON_EMAIL),
                email_address_id: email.email_address_id,
                full_name: S!(ANON_FULL_NAME),
                password_hash: S!(ANON_PASSWORD_HASH),
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
            let body = Self::gen_signin_body(Some(S!(email)), Some(gen_random_hex(20)), None, None);
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
            S!(signin
                .headers()
                .get("set-cookie")
                .unwrap()
                .to_str()
                .unwrap())
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
                Some(S!(ANON_EMAIL)),
                Some(S!(ANON_PASSWORD)),
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
                .map(|f| S!(f.to_str().unwrap()))
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
                email: email.unwrap_or_else(|| S!(TEST_EMAIL)),
                password: password.unwrap_or_else(|| S!(TEST_PASSWORD)),
                token,
                remember: remember.unwrap_or(false),
            }
        }

        pub async fn insert_device(
            &self,
            authed_cookie: &str,
            device: Option<ij::DevicePost>,
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
            S!(result.as_str().unwrap())
        }

        pub async fn get_access_code(&self, device_type: ConnectionType, index: usize) -> String {
            let device = C!(self.query_user_active_devices().await[index]);
            let url = format!("{}/{}", &token_base_url(&self.app_env), device_type);
            let body = HashMap::from([("key", device.api_key_string)]);
            let result = Self::get_client()
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap();
            let result = result.json::<Response>().await.unwrap().response;

            format!(
                "{}/{}/{}",
                ws_base_url(&self.app_env),
                device_type,
                result.as_str().unwrap()
            )
        }

        pub async fn get_anon_access_code(&self, device_type: ConnectionType, index: usize) -> Url {
            let device = C!(self.query_anon_user_active_devices().await[index]);
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
        ) -> ij::DevicePost {
            ij::DevicePost {
                max_clients,
                client_password: client_password.map(|i| S!(i)),
                device_password: device_password.map(|i| S!(i)),
                structured_data,
                name: name.map(|i| S!(i)),
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
                full_name: S!(full_name),
                password: S!(password),
                invite: S!(invite),
                email: S!(email),
                age,
                agree,
            }
        }
    }

    /// Get basic api params, also flushes all redis keys, deletes all test data, DOESN'T start the api server
    pub async fn setup() -> TestSetup {
        let app_env = parse_env::AppEnv::get_env();
        let postgres = db_postgres::db_pool(&app_env).await.unwrap();
        let redis = DbRedis::get_pool(&app_env).await.unwrap();
        let mut test_setup = TestSetup {
            app_env,
            postgres,
            redis,
            model_user: None,
            anon_user: None,
        };
        test_setup.clean_up().await;
        test_setup
    }
    pub async fn get_keys(redis: &Pool, pattern: &str) -> Vec<String> {
        let mut scanner = redis.next().scan(pattern, Some(100), None);
        let mut output = vec![];
        while let Some(mut page) = scanner.try_next().await.unwrap() {
            if let Some(page) = page.take_results() {
                for i in page {
                    if let Some(s) = i.as_str() {
                        output.push(S!(s));
                    }
                }
            }
            page.next();
        }
        output
    }

    /// start the api server on it's own thread
    pub async fn start_servers() -> TestSetup {
        let setup = setup().await;
        let app_env = C!(setup.app_env);
        let postgres = C!(setup.postgres);
        let connections = Arc::new(Mutex::new(Connections::default()));

        let api_data = ServeData {
            app_env: C!(app_env),
            connections: Arc::clone(&connections),
            postgres: C!(postgres),
            redis: C!(setup.redis),
            server_name: ServerName::Api,
        };

        tokio::spawn(async {
            ApiServer::serve(api_data).await.unwrap();
        });

        let auth_data = ServeData {
            app_env: C!(app_env),
            connections: Arc::clone(&connections),
            postgres: C!(postgres),
            redis: C!(setup.redis),

            server_name: ServerName::Token,
        };

        tokio::spawn(async {
            TokenServer::serve(auth_data).await.unwrap();
        });

        let ws_data = ServeData {
            app_env: C!(app_env),
            connections: Arc::clone(&connections),
            postgres: C!(postgres),
            redis: C!(setup.redis),

            server_name: ServerName::Ws,
        };

        tokio::spawn(async {
            WsServer::serve(ws_data).await.unwrap();
        });

        // just sleep to make sure the server is running - 1ms is enough
        sleep!(1);

        TestSetup {
            app_env: setup.app_env,
            redis: setup.redis,
            postgres: setup.postgres,
            model_user: None,
            anon_user: None,
        }
    }
}

use axum::{
    extract::ws::{Message, WebSocket},
    http::Uri,
};
use futures::{stream::SplitSink, SinkExt};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{collections::HashMap, fmt, net::IpAddr, sync::Arc, time::Instant};
use tokio::sync::Mutex;
use ulid::Ulid;

use crate::{
    api_error::ApiError, database::{
        connection::ModelConnection,
        device::{ModelDeviceId, ModelWsDevice},
        hourly_bandwidth::ModelHourlyBandwidth,
        new_types::{ConnectionId, DeviceId},
        user::ModelUser,
        user_level::UserLevel,
    }, servers::ws::HandlerData, user_io::{
        outgoing_json::oj,
        ws_message::wm::{ClientBody, PiBody},
    }, C, S
};

pub type AMConnections = Arc<Mutex<Connections>>;

#[derive(Debug)]
pub enum SendMessage {
    Text(String),
    Binary(Vec<u8>),
}

impl SendMessage {
    pub fn get_size(&self) -> usize {
        match self {
            Self::Binary(x) => x.len(),
            Self::Text(x) => x.as_bytes().len(),
        }
    }
}

impl From<Vec<u8>> for SendMessage {
    fn from(x: Vec<u8>) -> Self {
        Self::Binary(x)
    }
}

impl From<String> for SendMessage {
    fn from(x: String) -> Self {
        Self::Text(x)
    }
}

impl From<PiBody> for SendMessage {
    fn from(x: PiBody) -> Self {
        Self::Text(x.to_string())
    }
}

impl From<ClientBody> for SendMessage {
    fn from(x: ClientBody) -> Self {
        Self::Text(x.to_string())
    }
}

impl From<SendMessage> for Message {
    fn from(x: SendMessage) -> Self {
        match x {
            SendMessage::Text(a) => Self::Text(a),
            SendMessage::Binary(a) => Self::Binary(a),
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Deserialize, Serialize)]
pub enum ConnectionType {
    Client,
    Pi,
}

impl ConnectionType {
    pub const fn is_pi(self) -> bool {
        match self {
            Self::Pi => true,
            Self::Client => false,
        }
    }

    /// If Pi return Client, if Client return Pi
    pub const fn get_inverse(self) -> Self {
        match self {
            Self::Pi => Self::Client,
            Self::Client => Self::Pi,
        }
    }
}

impl fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let to_disp = match self {
            Self::Client => "client",
            Self::Pi => "pi",
        };
        write!(f, "{to_disp}")
    }
}

impl TryFrom<String> for ConnectionType {
    type Error = ApiError;
    fn try_from(x: String) -> Result<Self, ApiError> {
        match x.to_lowercase().as_str() {
            "pi" => Ok(Self::Pi),
            "client" => Ok(Self::Client),
            _ => Err(ApiError::Internal(S!("unknown device type"))),
        }
    }
}

/// This will convert the url path into device type, to work out if a pi or client is trying to connect
impl TryFrom<Uri> for ConnectionType {
    type Error = ApiError;
    fn try_from(uri: Uri) -> Result<Self, ApiError> {
        match uri
            .to_string()
            .split('/')
            .skip(1)
            .take(1)
            .collect::<String>()
            .to_lowercase()
            .as_str()
        {
            "pi" => Ok(Self::Pi),
            "client" => Ok(Self::Client),
            _ => Err(ApiError::Internal(S!("unknown device type"))),
        }
    }
}
pub struct WsSender {
    auto_close: Instant,
    connection_id: ConnectionId,
    device_id: DeviceId,
    device_type: ConnectionType,
    ip: IpAddr,
    socket: SplitSink<WebSocket, Message>,
    ulid: Ulid,
}

impl WsSender {
    // Create a new Instant which is 40 in the future from now
    fn new_auto_close() -> Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(40)
    }

    /// Check if the auto_close timestamp is valid, as in has yet to occur
    fn auto_close_valid(&self, now: &Instant) -> Result<(), ()> {
        if now < &self.auto_close {
            Ok(())
        } else {
            Err(())
        }
    }

    // Update the auto_close time
    pub fn update_auto_close(&mut self) {
        self.auto_close = Self::new_auto_close();
    }

    pub fn new(
        connection_id: ConnectionId,
        device_type: ConnectionType,
        device: &ModelWsDevice,
        ip: IpAddr,
        sender: SplitSink<WebSocket, Message>,
        ulid: Ulid,
    ) -> Self {
        Self {
            auto_close: Self::new_auto_close(),
            connection_id,
            device_id: device.device_id,
            device_type,
            ip,
            socket: sender,
            ulid,
        }
    }

    /// Check if auto close valid, if not, close connection, else send a ping message
    async fn ping(&mut self, now: &Instant) -> Result<(), ()> {
        if self.auto_close_valid(now).is_ok() {
            self.socket.send(Message::Ping(vec![])).await.ok();
            Ok(())
        } else {
            Err(())
        }
    }

    /// Close the connection
    async fn ws_close(&mut self) {
        // Is there any point in sending a close message?
        self.socket.send(Message::Close(None)).await.ok();
        self.socket.close().await.ok();
    }
}

pub struct PiConnections(HashMap<DeviceId, WsSender>);

impl PiConnections {
    fn new() -> Self {
        Self(HashMap::new())
    }

    /// Close connection and remove from map
    async fn close_and_remove(&mut self, device_id: DeviceId) {
        if let Some(ws_sender) = self.0.get_mut(&device_id) {
            ws_sender.ws_close().await;
        }
        self.0.remove(&device_id);
    }

    fn is_connected(&self, device_id: DeviceId) -> bool {
        self.0.contains_key(&device_id)
    }

    fn is_alive(&self, device_id: DeviceId) -> bool {
        self.0.contains_key(&device_id)
    }

    fn insert(&mut self, ws_sender: WsSender) {
        self.0.insert(ws_sender.device_id, ws_sender);
    }

    async fn ping_all(&mut self, postgres: &PgPool, now: &Instant) {
        let mut to_remove = vec![];
        for ws_sender in &mut self.0.values_mut() {
            if ws_sender.ping(now).await.is_err() {
                to_remove.push((ws_sender.device_id, ws_sender.connection_id));
            };
        }
        for i in to_remove {
            self.close_and_remove(i.0).await;
            let postgres = C!(postgres);
            let connection_id = i.1;
            tokio::spawn(async move {
                ModelConnection::update_offline(&postgres, connection_id)
                    .await
                    .map_err(|e| tracing::error!("{e:?}"))
            });
        }
    }
}

pub struct ClientConnections(HashMap<DeviceId, HashMap<Ulid, WsSender>>);

impl ClientConnections {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn number_connected(&self, device_id: DeviceId) -> usize {
        self.0
            .get(&device_id)
            .map_or(0, std::collections::HashMap::len)
    }

    fn insert(&mut self, ws_sender: WsSender) {
        if let Some(map) = self.0.get_mut(&ws_sender.device_id) {
            map.insert(ws_sender.ulid, ws_sender);
        } else {
            self.0.insert(
                ws_sender.device_id,
                HashMap::from([(ws_sender.ulid, ws_sender)]),
            );
        }
    }

    fn is_alive(&self, device_id: DeviceId, ulid: Ulid) -> bool {
        self.0
            .get(&device_id)
            .map_or(false, |map| map.get(&ulid).is_some())
    }

    /// Close all client_connections linked to a single device, and remove inner hashmap
    async fn close_by_device_id(&mut self, device_id: DeviceId) {
        if let Some(map) = self.0.get_mut(&device_id) {
            for i in map {
                i.1.ws_close().await;
            }
        }
        // remove the entire client hashmap from the connections hashmap
        self.0.remove(&device_id);
    }

    /// Close, and remove, a single client connection
    async fn close_and_remove(&mut self, ulid: Ulid, device_id: DeviceId) {
        if let Some(map) = self.0.get_mut(&device_id) {
            if let Some(ws_sender) = map.get_mut(&ulid) {
                ws_sender.ws_close().await;
            }
            map.remove(&ulid);
            if map.is_empty() {
                self.0.remove(&device_id);
            }
        }
    }

    /// If a new max_clients setting is enabled, need to remove all the clients connected that exceed this new limit, work out based on connection time
    async fn close_max_clients(&mut self, device_id: DeviceId, max_clients: i16) {
        if let Some(map) = self.0.get_mut(&device_id) {
            let mut connections = map.iter_mut().map(|i| *i.0).collect::<Vec<_>>();
            connections.sort();
            for ulid in connections
                .iter()
                .skip(usize::try_from(max_clients).unwrap_or(1))
            {
                self.close_and_remove(*ulid, device_id).await;
            }
        }
    }

    /// Ping all client connections, and if auto_close time is invalid, close the connection & remove from HashMap(s)
    async fn ping_all(&mut self, postgres: &PgPool, now: &Instant) {
        let mut to_remove = vec![];
        for map in &mut self.0.values_mut() {
            for (ulid, ws_sender) in &mut map.iter_mut() {
                if ws_sender.ping(now).await.is_err() {
                    to_remove.push((*ulid, ws_sender.device_id, ws_sender.connection_id));
                };
            }
        }

        for i in to_remove {
            self.close_and_remove(i.0, i.1).await;
            let postgres = C!(postgres);
            let connection_id = i.2;
            tokio::spawn(async move {
                ModelConnection::update_offline(&postgres, connection_id)
                    .await
                    .map_err(|e| tracing::error!("{e:?}"))
            });
        }
    }
}

pub struct Connections {
    client: ClientConnections,
    pi: PiConnections,
}

impl Connections {
    /// Update the auto close instant, to 40 seconds in the future
    pub fn update_auto_close<'a>(&mut self, input: &'a HandlerData<'a>) {
        if let Some(connection) = match &input.device_type {
            ConnectionType::Pi => self.pi.0.get_mut(&input.device.device_id),
            ConnectionType::Client => self
                .client
                .0
                .get_mut(&input.device.device_id)
                .and_then(|map| map.get_mut(&input.ulid)),
        } {
            connection.update_auto_close();
        }
    }

    /// Work out if any more connections are possible, based on hashmap rather than database calls
    pub fn max_connected(&self, device: &ModelWsDevice, device_type: ConnectionType) -> bool {
        match device_type {
            ConnectionType::Client => {
                self.client.number_connected(device.device_id)
                    >= device.max_clients.try_into().unwrap_or(1)
            }
            ConnectionType::Pi => self.pi.is_connected(device.device_id),
        }
    }

    /// Check if connection is online, when device_type is pi, ulid is ignored, so just checks if pi is online
    pub fn is_alive(&self, device_id: DeviceId, ulid: Ulid, device_type: ConnectionType) -> bool {
        match device_type {
            ConnectionType::Client => self.client.is_alive(device_id, ulid),
            ConnectionType::Pi => self.pi.is_alive(device_id),
        }
    }

    /// Close all connections of a single device
    pub async fn close_by_single_device_id(&mut self, device_id: DeviceId) {
        self.pi.close_and_remove(device_id).await;
        self.client.close_by_device_id(device_id).await;
    }

    /// Close connections of multiple devices, used when deleting all devices via api
    pub async fn close_by_multiple_device_id(&mut self, device_id: &[ModelDeviceId]) {
        for id in device_id {
            self.close_by_single_device_id(id.device_id).await;
        }
    }

    /// Close client connections that exceed the new max_client limit
    pub async fn close_max_clients(&mut self, device_id: DeviceId, max_clients: i16) {
        self.client.close_max_clients(device_id, max_clients).await;
    }

    /// Close a ws connection, update connection table, remove from hashmap
    pub async fn close(&mut self, device_id: DeviceId, ulid: Ulid, device_type: ConnectionType) {
        match device_type {
            ConnectionType::Client => {
                self.client.close_and_remove(ulid, device_id).await;
            }
            ConnectionType::Pi => self.pi.close_and_remove(device_id).await,
        }
    }

    /// Insert a new connection into correct hashmap
    /// Will error if max_connections already connected
    pub fn insert(&mut self, ws_sender: WsSender, device: &ModelWsDevice) -> Result<(), ()> {
        if self.max_connected(device, ws_sender.device_type) {
            return Err(());
        }

        match ws_sender.device_type {
            ConnectionType::Client => self.client.insert(ws_sender),
            ConnectionType::Pi => self.pi.insert(ws_sender),
        };
        Ok(())
    }

    /// Send an empty ping message to every pi & client connection, ignoring any errors
    pub async fn ping(&mut self, postgres: &PgPool) {
        let now = std::time::Instant::now();
        self.pi.ping_all(postgres, &now).await;
        self.client.ping_all(postgres, &now).await;
    }

    /// Send a message from pi to all clients, or client to pi
    /// msg should be message type?
    pub async fn send_all<'a>(&mut self, input: &'a HandlerData<'_>, msg: SendMessage) {
        let message: Message = msg.into();
        match input.device_type {
            // Send to all clients
            ConnectionType::Pi => {
                if let Some(map) = self.client.0.get_mut(&input.device.device_id) {
                    ModelHourlyBandwidth::insert(
                        input.device.device_id,
                        input.device_type.get_inverse(),
                        true,
                        input.msg_size * map.len(),
                        input.postgres,
                        input.redis,
                    );
                    for ws_sender in &mut map.values_mut() {
                        ws_sender.socket.send(C!(message)).await.ok();
                    }
                }
            }
            // Send to pi
            ConnectionType::Client => {
                if let Some(ws_sender) = self.pi.0.get_mut(&input.device.device_id) {
                    ModelHourlyBandwidth::insert(
                        input.device.device_id,
                        input.device_type.get_inverse(),
                        true,
                        input.msg_size,
                        input.postgres,
                        input.redis,
                    );
                    ws_sender.socket.send(message).await.ok();
                }
            }
        }
    }

    /// Get the ws_sender of given ulid
    fn get_self<'a>(&mut self, input: &'a HandlerData<'a>) -> Option<&mut WsSender> {
        match &input.device_type {
            ConnectionType::Pi => self.pi.0.get_mut(&input.device.device_id),
            ConnectionType::Client => self
                .client
                .0
                .get_mut(&input.device.device_id)
                .and_then(|map| map.get_mut(&input.ulid)),
        }
    }

    /// Send a message to self, used when returning error messages etc
    pub async fn send_self<'a>(&mut self, input: &'a HandlerData<'_>, msg: SendMessage) {
        let msg_size = msg.get_size();
        let message = Message::from(msg);

        if let Some(ws_sender) = self.get_self(input) {
            ModelHourlyBandwidth::insert(
                input.device.device_id,
                input.device_type,
                true,
                msg_size,
                input.postgres,
                input.redis,
            );
            ws_sender.socket.send(message).await.ok();
        }
    }

    /// Send a message to a single client
    /// Will only send if the sendee is a Pi
    pub async fn send_unique<'a>(
        &mut self,
        input: &'a HandlerData<'_>,
        msg: SendMessage,
        ulid: Ulid,
    ) {
        let message = Message::from(msg);
        if input.device_type == ConnectionType::Pi {
            if let Some(map) = self.client.0.get_mut(&input.device.device_id) {
                if let Some(ws_sender) = map.get_mut(&ulid) {
                    ModelHourlyBandwidth::insert(
                        input.device.device_id,
                        ConnectionType::Client,
                        true,
                        input.msg_size,
                        input.postgres,
                        input.redis,
                    );
                    ws_sender.socket.send(message).await.ok();
                }
            }
        }
    }

    // /// Abort the auto_close JoinHandle
    // pub fn auto_close_abort<'a>(&mut self, input: &'a HandlerData<'a>) {
    //     if let Some(ws_sender) = self.get_self(input) {
    //         if let Some(auto_close) = ws_sender.auto_close.as_ref() {
    //             auto_close.abort();
    //             ws_sender.auto_close = None;
    //         }
    //     }
    // }

    /// If admin user not supplied in, returns auth error
    pub fn get_admin_info_device(
        &self,
        user: &ModelUser,
        device_id: DeviceId,
    ) -> Result<Vec<AdminConnectionInfo>, ApiError> {
        if user.user_level != UserLevel::Admin {
            return Err(ApiError::Authentication);
        }
        let mut pi_connections = self
            .pi
            .0
            .iter()
            .filter_map(|i| {
                if &device_id == i.0 {
                    Some(AdminConnectionInfo::from(i.1))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut client_connections = self
            .client
            .0
            .values()
            .flat_map(|i| {
                i.values()
                    .filter_map(|i| {
                        if device_id == i.device_id {
                            Some(AdminConnectionInfo::from(i))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        pi_connections.append(&mut client_connections);

        Ok(pi_connections)
    }

    pub fn get_admin_info(&self, user: &ModelUser) -> Result<oj::AdminConnectionCounts, ApiError> {
        if user.user_level != UserLevel::Admin {
            return Err(ApiError::Authentication);
        }

        Ok(oj::AdminConnectionCounts {
            pi: self.pi.0.len(),
            client: self.client.0.iter().map(|i| i.1.len()).sum::<usize>(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct AdminConnectionInfo {
    pub device_id: DeviceId,
    pub device_type: ConnectionType,
    pub connection_id: ConnectionId,
    pub timestamp: u64,
    pub ulid: Ulid,
    pub ip: IpAddr,
}

impl From<&WsSender> for AdminConnectionInfo {
    fn from(x: &WsSender) -> Self {
        Self {
            connection_id: x.connection_id,
            device_id: x.device_id,
            device_type: x.device_type,
            ip: x.ip,
            timestamp: x.ulid.timestamp_ms(),
            ulid: x.ulid,
        }
    }
}

impl Default for Connections {
    fn default() -> Self {
        Self {
            pi: PiConnections::new(),
            client: ClientConnections::new(),
        }
    }
}

// previous autoclose implementation, mayeb re-introduce?
// pub struct AutoClose;

// impl AutoClose {
//     /// Spawn off a 40 second timeout, which will close the connection, this gets aborted on PONG response, thereby autokilling connections that
//     /// for whatever reason didn't send a close frame and thus don't return a PONG from the auto sent PING
//     pub async fn init(
//         connection_id: ConnectionId,
//         connections: &AMConnections,
//         device_id: DeviceId,
//         device_type: ConnectionType,
//         ulid: Ulid,
//         postgres: &PgPool,
//     ) {
//         let spawn_connections = Arc::clone(connections);
//         let duration = std::time::Duration::from_secs(40);

//         // TODO - don't really like this lock?
//         let mut locked_con = connections.lock().await;

//         let ws_sender = match device_type {
//             ConnectionType::Pi => locked_con.pi.0.get_mut(&device_id),
//             ConnectionType::Client => locked_con
//                 .client
//                 .0
//                 .get_mut(&device_id)
//                 .and_then(|map| map.get_mut(&ulid)),
//         };

//         // TODO use this instead of a spawner
//         // use this instead of the spawn below?
//         // need to combine with the pinger somewhere
//         let time_to_kill_connection =
//             std::time::Instant::now() + std::time::Duration::from_secs(40);

//         // if let Some(ws_sender) = ws_sender {
//         //     let postgres = C!(postgres);
//         //     ws_sender.auto_close = Some(tokio::spawn(async move {
//         //         tokio::time::sleep(duration).await;
//         //         if let Err(e) = ModelConnection::update_offline(&postgres, connection_id).await {
//         //               tracing::error!("{e:?}");
//         //             tracing::error!("unable to update connection details");
//         //         };
//         //         tokio::time::timeout(
//         //             std::time::Duration::from_secs(2),
//         //             spawn_connections
//         //                 .lock()
//         //                 .await
//         //                 .close(device_id, ulid, device_type),
//         //         )
//         //         .await
//         //         .unwrap_or(());
//         //     }));
//         // }
//     }
// }

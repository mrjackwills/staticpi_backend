pub mod oj {
    use axum::Json;
    use serde::Serialize;
    use ulid::Ulid;

    use crate::{
        connections::ConnectionType,
        database::{device::ModelDevice, user::ModelUser, user_level::UserLevel}, C,
    };

    pub type AsJsonRes<T> = Json<OutgoingJson<T>>;

    #[derive(serde::Serialize, Debug, PartialEq, Eq, PartialOrd)]
    pub struct OutgoingJson<T> {
        response: T,
    }

    impl<T> OutgoingJson<T> {
        pub const fn new(response: T) -> Json<Self> {
            Json(Self { response })
        }
    }

    #[derive(Serialize)]
    pub struct Online {
        pub uptime: u64,
        pub api_version: String,
    }

    #[derive(Serialize)]
    pub struct AllLimits {
        pub name_of_device: String,
        pub ttl: i64,
    }

    #[derive(Serialize)]
    pub struct AllDevices {
        pub devices: Vec<ModelDevice>,
        pub limits: Vec<AllLimits>,
    }

    #[derive(Serialize)]
    pub struct DeviceMessageCache {
        pub cache: String,
    }

    #[derive(Serialize)]
    pub struct PasswordReset {
        pub two_fa_active: bool,
        pub two_fa_backup: bool,
    }

    #[derive(Serialize)]
    pub struct SigninAccepted {
        pub two_fa_backup: bool,
    }

    #[derive(Serialize)]
    pub struct Photo {
        pub converted: String,
        pub original: String,
    }

    #[derive(Serialize)]
    pub struct AuthenticatedUser {
        pub full_name: String,
        pub email: String,
        pub max_bandwidth: i64,
        pub max_clients: i16,
        pub max_devices: i16,
        pub max_message_size: i32,
        pub timestamp: String,
        pub two_fa_active: bool,
        pub two_fa_always_required: bool,
        pub two_fa_count: i64,
        pub user_level: UserLevel,
    }

    impl From<ModelUser> for AuthenticatedUser {
        fn from(user: ModelUser) -> Self {
            Self {
                full_name: user.full_name,
                email: user.email,
                two_fa_always_required: user.two_fa_always_required,
                two_fa_active: user.two_fa_secret.is_some(),
                two_fa_count: user.two_fa_backup_count,
                max_bandwidth: user.max_monthly_bandwidth_in_bytes,
                max_clients: user.max_clients_per_device,
                max_message_size: user.max_message_size_in_bytes,
                max_devices: user.max_number_of_devices,
                user_level: user.user_level,
                timestamp: user.timestamp.to_string(),
            }
        }
    }

    impl From<&ModelUser> for AuthenticatedUser {
        fn from(user: &ModelUser) -> Self {
            Self {
                full_name: C!(user.full_name),
                email: C!(user.email),
                two_fa_always_required: user.two_fa_always_required,
                two_fa_active: user.two_fa_secret.is_some(),
                two_fa_count: user.two_fa_backup_count,
                max_bandwidth: user.max_monthly_bandwidth_in_bytes,
                max_clients: user.max_clients_per_device,
                max_message_size: user.max_message_size_in_bytes,
                max_devices: user.max_number_of_devices,
                user_level: C!(user.user_level),
                timestamp: user.timestamp.to_string(),
            }
        }
    }

    #[derive(Serialize)]
    pub struct TwoFASetup {
        pub secret: String,
    }

    #[derive(Serialize)]
    pub struct TwoFaBackup {
        pub backups: Vec<String>,
    }

    #[derive(Serialize)]
    pub struct BackupFile {
        pub file_name: String,
        pub file_size: u64,
    }

    #[derive(Serialize)]
    pub struct AdminMemory {
        pub uptime: u64,
        pub uptime_app: u64,
        pub virt: usize,
        pub rss: usize,
    }

    #[derive(Serialize, Debug)]
    pub struct AdminLimit {
        pub key: String,
        pub points: u64,
        pub max: u64,
        pub ttl: i64,
        pub blocked: bool,
    }

    #[derive(Debug, Serialize)]
    pub struct AdminConnectionCounts {
        pub pi: usize,
        pub client: usize,
    }

    #[derive(Debug, Serialize)]
    pub struct AdminEmailsCounts {
        pub hour: i64,
        pub total: i64,
    }

    #[derive(Serialize, Debug)]
    pub struct AdminConnection {
        pub device_type: ConnectionType,
        pub ip: String,
        pub timestamp: i64,
        pub ulid: Ulid,
    }
}

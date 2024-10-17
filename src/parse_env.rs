use std::{collections::HashMap, env, fmt, fs, time::SystemTime};
use thiserror::Error;

type EnvHashMap = HashMap<String, String>;

const LOCAL_ENV: &str = ".env";
const DOCKER_ENV: &str = "/app_env/.api.env";

#[derive(Debug, Error, PartialEq)]
enum EnvError {
    #[error("'{0}' - file not found'")]
    FileNotFound(String),
    #[error("'{0}' - cannot parse into number'")]
    IntParse(String),
    #[error("invalid length: '{0}'")]
    Len(String),
    #[error("missing env: '{0}'")]
    NotFound(String),
}

#[derive(Debug, Clone, Copy)]
pub enum RunMode {
    Production,
    Development,
}

impl fmt::Display for RunMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let x = match self{
			Self::Development => "DEV",
			Self::Production => "PROD"
		};
        write!(f, "{x}")
    }
}

impl RunMode {
    pub const fn is_production(self) -> bool {
        match self {
            Self::Development => false,
            Self::Production => true,
        }
    }
}

impl From<bool> for RunMode {
    fn from(value: bool) -> Self {
        if value {
            Self::Production
        } else {
            Self::Development
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppEnv {
    pub api_host: String,
    pub api_port: u16,
    pub auth_port: u16,
    pub cookie_name: String,
    pub cookie_secret: [u8; 64],
    pub domain: String,
    pub email_from_address: String,
    pub email_host: String,
    pub email_name: String,
    pub email_password: String,
    pub email_port: u16,
    pub invite: String,
    pub location_logs: String,
    pub log_level: tracing::Level,
    pub pg_database: String,
    pub pg_host: String,
    pub pg_password: String,
    pub pg_port: u16,
    pub pg_user: String,
    pub run_mode: RunMode,
    pub redis_database: u8,
    pub redis_host: String,
    pub redis_password: String,
    pub redis_port: u16,
    pub start_time: SystemTime,
    pub ws_port: u16,
}

impl AppEnv {
    /// Check a given file actually exists on the file system
    fn check_file_exists(filename: String) -> Result<String, EnvError> {
        if fs::exists(&filename).unwrap_or_default() {
            Ok(filename)
        } else {
            Err(EnvError::FileNotFound(filename))
        }
    }

    /// Parse "true" or "false" to bool, else false
    fn parse_boolean(key: &str, map: &EnvHashMap) -> bool {
        map.get(key).map_or(false, |value| value == "true")
    }

    /// Parse string to u32, else return 1
    fn parse_number<T: TryFrom<u64> + std::str::FromStr>(
        key: &str,
        map: &EnvHashMap,
    ) -> Result<T, EnvError> {
        map.get(key)
            .map_or(Err(EnvError::NotFound(key.into())), |data| {
                data.parse::<T>()
                    .map_or(Err(EnvError::IntParse(data.into())), |d| Ok(d))
            })
    }

    fn parse_string(key: &str, map: &EnvHashMap) -> Result<String, EnvError> {
        map.get(key).map_or_else(
            || Err(EnvError::NotFound(key.into())),
            |value| Ok(value.into()),
        )
    }

    fn parse_log(map: &EnvHashMap) -> tracing::Level {
        if Self::parse_boolean("LOG_TRACE", map) {
            tracing::Level::TRACE
        } else if Self::parse_boolean("LOG_DEBUG", map) {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        }
    }

    fn parse_production(map: &EnvHashMap) -> RunMode {
        RunMode::from(Self::parse_boolean("PRODUCTION", map))
    }

    // Messy solution - should improve
    fn parse_cookie_secret(key: &str, map: &EnvHashMap) -> Result<[u8; 64], EnvError> {
        map.get(key).map_or_else(
            || Err(EnvError::NotFound(key.into())),
            |value| {
                let as_bytes = value.as_bytes();
                if as_bytes.len() == 64 {
                    value
                        .as_bytes()
                        .try_into()
                        .map_or(Err(EnvError::Len(key.into())), Ok)
                } else {
                    Err(EnvError::Len(key.into()))
                }
            },
        )
    }

    /// Load, and parse .env file, return `AppEnv`
    fn generate() -> Result<Self, EnvError> {
        let env_map = env::vars().map(|i| (i.0, i.1)).collect::<EnvHashMap>();

        Ok(Self {
            api_host: Self::parse_string("API_HOST", &env_map)?,
            api_port: Self::parse_number("API_PORT", &env_map)?,
            auth_port: Self::parse_number("TOKEN_PORT", &env_map)?,
            cookie_name: Self::parse_string("COOKIE_NAME", &env_map)?,
            cookie_secret: Self::parse_cookie_secret("COOKIE_SECRET", &env_map)?,
            domain: Self::parse_string("DOMAIN", &env_map)?,
            email_from_address: Self::parse_string("EMAIL_ADDRESS", &env_map)?,
            email_host: Self::parse_string("EMAIL_HOST", &env_map)?,
            email_name: Self::parse_string("EMAIL_NAME", &env_map)?,
            email_password: Self::parse_string("EMAIL_PASSWORD", &env_map)?,
            email_port: Self::parse_number("EMAIL_PORT", &env_map)?,
            invite: Self::parse_string("INVITE", &env_map)?,
            location_logs: Self::check_file_exists(Self::parse_string("LOCATION_LOGS", &env_map)?)?,
            log_level: Self::parse_log(&env_map),
            pg_database: Self::parse_string("PG_DATABASE", &env_map)?,
            pg_host: Self::parse_string("PG_HOST", &env_map)?,
            pg_password: Self::parse_string("PG_PASSWORD", &env_map)?,
            pg_port: Self::parse_number("PG_PORT", &env_map)?,
            pg_user: Self::parse_string("PG_USER", &env_map)?,
            redis_database: Self::parse_number("REDIS_DB", &env_map)?,
            redis_host: Self::parse_string("REDIS_HOST", &env_map)?,
            redis_password: Self::parse_string("REDIS_PASSWORD", &env_map)?,
            redis_port: Self::parse_number("REDIS_PORT", &env_map)?,
            run_mode: Self::parse_production(&env_map),
            start_time: SystemTime::now(),
            ws_port: Self::parse_number("WS_PORT", &env_map)?,
        })
    }

    /// Load up .env from file, instead of using environmental variables
    /// On docker, mount /`app_env`/ as a readonly share
    pub fn get_env() -> Self {
        let env_path = if std::fs::exists(DOCKER_ENV).unwrap_or_default() {
            DOCKER_ENV
        } else if std::fs::exists(LOCAL_ENV).unwrap_or_default() {
            LOCAL_ENV
        } else {
            println!("\n\x1b[31munable to load env file\x1b[0m\n");
            std::process::exit(1);
        };

        // change to dotenvy
        dotenvy::from_path(env_path).ok();
        match Self::generate() {
            Ok(s) => s,
            Err(e) => {
                println!("\n\x1b[31m{e}\x1b[0m\n");
                std::process::exit(1);
            }
        }
    }
}

/// Run tests with
///
/// cargo watch -q -c -w src/ -x 'test env_ -- --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use crate::S;

    use super::*;

    #[test]
    fn env_missing_env() {
        let map = HashMap::from([(S!("not_fish"), S!("not_fish"))]);

        let result = AppEnv::parse_string("fish", &map);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "missing env: 'fish'");
    }

    #[test]
    fn env_check_file_exists_ok() {
        // check folder exists ok
        let result = AppEnv::check_file_exists(S!("./src"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "./src");

        // check file exists ok
        let result = AppEnv::check_file_exists(S!("./Cargo.toml"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "./Cargo.toml");
    }

    #[test]
    fn env_check_file_exists_err() {
        // random folder error
        let result = AppEnv::check_file_exists(S!("./some_random_folder"));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            EnvError::FileNotFound(S!("./some_random_folder"))
        );

        // random file err
        let result = AppEnv::check_file_exists(S!("./some_random_file.txt"));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            EnvError::FileNotFound(S!("./some_random_file.txt"))
        );
    }

    #[test]
    fn env_parse_string_valid() {
        let map = HashMap::from([(S!("RANDOM_STRING"), S!("123"))]);

        let result = AppEnv::parse_string("RANDOM_STRING", &map).unwrap();

        assert_eq!(result, "123");

        let map = HashMap::from([(S!("RANDOM_STRING"), S!("hello_world"))]);

        let result = AppEnv::parse_string("RANDOM_STRING", &map).unwrap();

        assert_eq!(result, "hello_world");
    }

    #[test]
    fn env_parse_log_valid() {
        let map = HashMap::from([(S!("RANDOM_STRING"), S!("123"))]);

        let result = AppEnv::parse_log(&map);

        assert_eq!(result, tracing::Level::INFO);

        let map = HashMap::from([(S!("LOG_DEBUG"), S!("false"))]);

        let result = AppEnv::parse_log(&map);

        assert_eq!(result, tracing::Level::INFO);

        let map = HashMap::from([(S!("LOG_TRACE"), S!("false"))]);

        let result = AppEnv::parse_log(&map);

        assert_eq!(result, tracing::Level::INFO);

        let map = HashMap::from([
            (S!("LOG_DEBUG"), S!("false")),
            (S!("LOG_TRACE"), S!("false")),
        ]);

        let result = AppEnv::parse_log(&map);

        assert_eq!(result, tracing::Level::INFO);

        let map = HashMap::from([
            (S!("LOG_DEBUG"), S!("true")),
            (S!("LOG_TRACE"), S!("false")),
        ]);

        let result = AppEnv::parse_log(&map);

        assert_eq!(result, tracing::Level::DEBUG);

        let map = HashMap::from([(S!("LOG_DEBUG"), S!("true")), (S!("LOG_TRACE"), S!("true"))]);

        let result = AppEnv::parse_log(&map);

        assert_eq!(result, tracing::Level::TRACE);

        let map = HashMap::from([
            (S!("LOG_DEBUG"), S!("false")),
            (S!("LOG_TRACE"), S!("true")),
        ]);

        let result = AppEnv::parse_log(&map);

        assert_eq!(result, tracing::Level::TRACE);
    }

    #[test]
    fn env_parse_run_mode_valid() {
        let map = HashMap::from([(S!("PRODUCTION"), S!("123"))]);

        let result = AppEnv::parse_production(&map);

        assert!(!result.is_production());

        let map = HashMap::from([(S!("PRODUCTION"), S!("false"))]);

        let result = AppEnv::parse_production(&map);

        assert!(!result.is_production());

        let map = HashMap::from([(S!("PRODUCTION"), "".to_owned())]);

        let result = AppEnv::parse_production(&map);

        assert!(!result.is_production());

        let map = HashMap::from([(S!("PRODUCTION"), S!("true"))]);

        let result = AppEnv::parse_production(&map);

        assert!(result.is_production());
    }

    #[test]
    fn env_parse_cookie_err() {
        let map = HashMap::from([(S!("RANDOM_STRING"), S!("123"))]);

        let result = AppEnv::parse_cookie_secret("RANDOM_STRING", &map);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), EnvError::Len(S!("RANDOM_STRING")));
    }

    #[test]
    fn env_parse_cookie_ok() {
        let map = HashMap::from([(
            S!("RANDOM_STRING"),
            S!("1234567890123456789012345678901234567890123456789012345678901234"),
        )]);

        let result = AppEnv::parse_cookie_secret("RANDOM_STRING", &map);

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "1234567890123456789012345678901234567890123456789012345678901234".as_bytes()
        );
    }

    #[test]
    fn env_parse_number_valid() {
        let map = HashMap::from([(S!("RANDOM_STRING"), S!("123"))]);

        let result = AppEnv::parse_number::<u8>("RANDOM_STRING", &map).unwrap();

        assert_eq!(result, 123);

        let map = HashMap::from([(S!("RANDOM_STRING"), S!("123123456"))]);

        let result = AppEnv::parse_number::<u32>("RANDOM_STRING", &map).unwrap();

        assert_eq!(result, 123_123_456);
    }

    #[test]
    fn env_parse_number_err() {
        let map = HashMap::from([(S!("RANDOM_STRING"), S!("123456"))]);

        let result = AppEnv::parse_number::<u8>("RANDOM_STRING", &map);

        assert!(result.is_err());

        assert_eq!(result.unwrap_err(), EnvError::IntParse("123456".into()));
    }

    #[test]
    fn env_parse_boolean_ok() {
        let map = HashMap::from([
            (S!("valid_true"), S!("true")),
            (S!("valid_false"), S!("false")),
            (S!("invalid_but_false"), S!("as")),
        ]);

        let result01 = AppEnv::parse_boolean("valid_true", &map);
        let result02 = AppEnv::parse_boolean("valid_false", &map);
        let result03 = AppEnv::parse_boolean("invalid_but_false", &map);
        let result04 = AppEnv::parse_boolean("missing", &map);

        assert!(result01);
        assert!(!result02);
        assert!(!result03);
        assert!(!result04);
    }

    // #[test]
    // fn test_generate() {
    // 	todo!("impl me");
    // }
}

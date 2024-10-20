pub mod wm {

    use std::fmt;

    use crate::{user_io::deserializer::IncomingDeserializer as is, S};

    use serde::{self, Deserialize, Serialize};
    use serde_json::Value;
    use ulid::Ulid;

    pub enum Error {
        RateLimit(i64),
        InvalidStructure,
        MessageSize,
        MonthlyBandwidth,
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "{}",
                serde_json::to_string(&ErrorMessage::from(self)).unwrap_or_default()
            )
        }
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PiBody {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache: Option<bool>,
        pub data: Value,
        #[serde(
            default,
            deserialize_with = "is::option_ulid",
            skip_serializing_if = "Option::is_none"
        )]
        pub unique: Option<Ulid>,
    }

    impl fmt::Display for PiBody {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", serde_json::to_string(&self).unwrap_or_default())
        }
    }

    impl PiBody {
        pub fn from_client(body: ClientBody, unique: Option<Ulid>) -> Self {
            Self {
                cache: None,
                data: body.data,
                unique,
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct ClientBody {
        #[serde(skip_serializing_if = "Option::is_none", skip_deserializing)]
        pub cache: Option<bool>,
        pub data: Value,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "is::option_always_true"
        )]
        pub unique: Option<bool>,
    }

    impl fmt::Display for ClientBody {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", serde_json::to_string(&self).unwrap_or_default())
        }
    }

    impl ClientBody {
        pub fn from_pi(body: PiBody) -> Self {
            Self {
                cache: None,
                data: body.data,
                unique: None,
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct ErrorBody {
        message: String,
        code: u32,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct ErrorMessage {
        pub error: ErrorBody,
    }

    impl From<&Error> for ErrorMessage {
        fn from(err: &Error) -> Self {
            let error = match err {
                Error::InvalidStructure => ErrorBody {
                    message: S!("received data is invalid structure"),
                    code: 400,
                },
                Error::RateLimit(limit) => ErrorBody {
                    message: format!("rate limited for {limit} seconds"),
                    code: 429,
                },
                Error::MessageSize => ErrorBody {
                    message: S!("message size too large"),
                    code: 413,
                },
                Error::MonthlyBandwidth => ErrorBody {
                    message: S!("monthly bandwidth allowance exceeded"),
                    code: 509,
                },
            };
            Self { error }
        }
    }
}

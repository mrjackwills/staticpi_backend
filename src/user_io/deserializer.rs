use regex::Regex;
use serde::{
    Deserialize, Deserializer,
    de::{self, IntoDeserializer},
};
use std::sync::LazyLock;
use ulid::Ulid;

use crate::{
    S,
    connections::ConnectionType,
    database::{
        new_types::{ContactMessageId, DeviceId},
        rate_limit::RateLimit,
    },
};

use super::incoming_json::ij;

pub struct IncomingDeserializer;

#[expect(clippy::expect_used)]
pub static REGEX_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#).expect("email regex")
});

impl IncomingDeserializer {
    /// Is a given string the length given, and also only uses hex chars [a-zA-Z0-9]
    pub fn is_hex(input: &str, len: usize) -> bool {
        input.chars().count() == len && input.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Check if given &str is an email, return Some(lowercase email) or None
    pub fn valid_email(parsed: &str) -> Option<String> {
        if parsed.is_empty() || !parsed.contains('@') {
            return None;
        }
        let email = S!(parsed).to_lowercase();

        if REGEX_EMAIL.is_match(&email) {
            Some(email)
        } else {
            None
        }
    }

    /// Parse a string, custom error if failure
    fn parse_string<'de, D>(deserializer: D, name: &str) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map_or(Err(de::Error::custom(name)), Ok)
    }

    /// Parse an i64, custom error if failure
    fn parse_i64<'de, D>(deserializer: D, name: &str) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        i64::deserialize(deserializer).map_or(Err(de::Error::custom(name)), Ok)
    }

    /// Check valid 2fa token, either hex 16, or six digits
    fn valid_token(token: &str) -> bool {
        Self::is_hex(token, 16)
            || token.chars().count() == 6 && token.chars().all(|c| c.is_ascii_digit())
    }

    // Actually deserializers here, used with is::name in the derived macro

    /// Only allows string.len() > 12 && string.len() < 100 (counting chars!)
    fn string_range<'de, D>(deserializer: D, name: &str) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parsed = Self::parse_string(deserializer, name)?;

        let allowed_len = 12..=99;

        if !allowed_len.contains(&parsed.chars().count()) {
            return Err(de::Error::custom(name));
        }
        Ok(parsed)
    }

    /// make sure a contact us message is len 64-1024
    pub fn message<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "message";
        let parsed = Self::parse_string(deserializer, name)?;
        let parsed = parsed.trim();
        if (64..=1024).contains(&parsed.chars().count()) {
            Ok(S!(parsed))
        } else {
            Err(de::Error::custom(name))
        }
    }

    /// Should return a new type Email(String)
    /// Check email isn't empty, lowercase it, contains an '@' sign, and matches a 99.9% email regex
    pub fn email<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "email";
        let parsed = Self::parse_string(deserializer, name)?;
        Self::valid_email(&parsed).ok_or_else(|| de::Error::custom(name))
    }

    /// Check is a user_session, used when admin is deleting user sessions
    /// TEST ME
    pub fn user_session<'de, D>(deserializer: D) -> Result<Ulid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "user_session";
        let parsed = Self::parse_string(deserializer, name)?;
        let (_, suffix) = parsed.split_once("::").unwrap_or_default();
        let as_ulid = Ulid::from_string(suffix);
        if let (_, Ok(ulid)) = ("session", as_ulid) {
            Ok(ulid)
        } else {
            Err(de::Error::custom(name))
        }
    }

    /// Check is a valid ulid, used for access tokens
    pub fn ulid<'de, D>(deserializer: D) -> Result<Ulid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "ulid";
        let parsed = Self::parse_string(deserializer, name)?;

        Ulid::from_string(&parsed).map_or(Err(de::Error::custom(name)), Ok)
    }

    pub fn option_ulid<'de, D>(deserializer: D) -> Result<Option<Ulid>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "option_ulid";
        (Option::<String>::deserialize(deserializer)?).map_or(Ok(None), |parsed| {
            Ulid::from_string(&parsed).map_or(Err(de::Error::custom(name)), |ulid| Ok(Some(ulid)))
        })
    }

    pub fn device_type<'de, D>(deserializer: D) -> Result<ConnectionType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "device_type";
        let parsed = Self::parse_string(deserializer, name)?;
        ConnectionType::try_from(parsed).map_or(Err(de::Error::custom(name)), Ok)
    }

    pub fn option_always_true<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "option_always_true";
        (Option::<bool>::deserialize(deserializer)?).map_or(Ok(None), |parsed| {
            if parsed {
                Ok(Some(parsed))
            } else {
                Err(de::Error::custom(name))
            }
        })
    }

    /// Only allows strings > 0 & alpha/or space, and also trims result
    /// So "John", "John ", "John Smith" "John Smith " are valid & then trimmed
    pub fn name<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "name";
        let parsed = Self::parse_string(deserializer, name)?;
        if parsed.chars().count() < 1
            || parsed.trim().chars().count() < 1
            || !parsed.chars().all(|x| x.is_alphabetic() || x == ' ')
        {
            return Err(de::Error::custom(name));
        }
        Ok(S!(parsed.trim()))
    }

    /// Check a given string matches the rate_limit structure
    pub fn rate_limit<'de, D>(deserializer: D) -> Result<RateLimit, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "rate_limit";
        let parsed = Self::parse_string(deserializer, name)?;
        RateLimit::try_from(parsed.as_str()).map_or(Err(de::Error::custom(name)), Ok)
    }

    /// Only allow tokens in either format 000 000 (with/without space)
    /// or a backup token 0123456789abcedf, again spaces get removed, will be uppercased
    pub fn token<'de, D>(deserializer: D) -> Result<ij::Token, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "token";
        let mut parsed = Self::parse_string(deserializer, name)?;

        // Remove any spaces from the token string and lowercase it
        parsed = parsed.replace(' ', "");

        if Self::valid_token(&parsed) {
            if parsed.chars().count() == 6 {
                Ok(ij::Token::Totp(parsed))
            } else {
                Ok(ij::Token::Backup(parsed.to_uppercase()))
            }
        } else {
            Err(de::Error::custom(name))
        }
    }

    pub fn option_token<'de, D>(deserializer: D) -> Result<Option<ij::Token>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(x) => Ok(Some(Self::token(x.into_deserializer())?)),
            _ => Ok(None),
        }
    }

    /// Only allows strings > 12 && string < 100
    pub fn password<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::string_range(deserializer, "password")
    }

    // TEST ME
    pub fn option_password<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(x) => Ok(Some(Self::password(x.into_deserializer())?)),
            _ => Ok(None),
        }
    }

    /// Device name needs to be 1-64, but else any valid utf 8 string is fine
    pub fn device_name<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "device_name";
        let parsed = Self::parse_string(deserializer, name)?;
        let trimmed = parsed.trim();
        let allowed_len = 1..=64;
        if !allowed_len.contains(&trimmed.chars().count()) {
            return Err(de::Error::custom(name));
        }
        Ok(S!(trimmed))
    }

    /// Device name needs to be 1-64, but else any valid utf 8 string is fine
    pub fn option_device_name<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(parsed) => {
                let trimmed = parsed.trim();
                // remove / ban all spaces?
                let allowed_len = 1..=64;
                if !allowed_len.contains(&trimmed.chars().count()) {
                    return Err(de::Error::custom("device_name"));
                }
                Ok(Some(S!(trimmed)))
            }
            _ => Ok(None),
        }
    }

    /// Change this to 4 minimum?
    /// Device name needs to be 1-64, but else any valid utf 8 string is fine
    pub fn device_password<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "device_password";
        let parsed = Self::parse_string(deserializer, name)?;
        let trimmed = parsed.trim();
        let allowed_len = 1..=64;
        if !allowed_len.contains(&trimmed.chars().count()) {
            return Err(de::Error::custom(name));
        }
        Ok(S!(trimmed))
    }

    /// Shouldn't trim?
    /// <Option>Device name needs to be 1-64, but else any valid utf 8 string is fine
    pub fn option_device_password<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(parsed) => {
                let trimmed = parsed.trim();
                let allowed_len = 1..=64;
                if !allowed_len.contains(&trimmed.chars().count()) {
                    return Err(de::Error::custom("device_password"));
                }
                Ok(Some(S!(trimmed)))
            }
            _ => Ok(None),
        }
    }

    /// Only allows strings > 12 && string < 100
    pub fn invite<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::string_range(deserializer, "invite")
    }

    /// Allow only positive i64, due to sql id issues
    pub fn device_id<'de, D>(deserializer: D) -> Result<DeviceId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "id";
        let parsed = Self::parse_i64(deserializer, name)?;
        if parsed < 1 {
            return Err(de::Error::custom(name));
        }
        Ok(DeviceId::from(parsed))
    }

    /// Allow only positive i64, due to sql id issues
    pub fn contact_message_id<'de, D>(deserializer: D) -> Result<ContactMessageId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "id";
        let parsed = Self::parse_i64(deserializer, name)?;
        if parsed < 1 {
            return Err(de::Error::custom(name));
        }
        Ok(ContactMessageId::from(parsed))
    }

    /// Allow only positive i16 1-100
    pub fn max_clients<'de, D>(deserializer: D) -> Result<i16, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = "max_clients";
        match i16::deserialize(deserializer) {
            Ok(parsed) => {
                if parsed < 1 {
                    return Err(de::Error::custom(name));
                }
                Ok(parsed)
            }
            Err(_) => Err(de::Error::custom(name)),
        }
    }
}

/// incoming_serializer
/// cargo watch -q -c -w src/ -x 'test incoming_serializer -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use serde::de::value::{Error as ValueError, StringDeserializer};
    use serde::de::{IntoDeserializer, value::I64Deserializer};

    use rand::{Rng, distributions::Alphanumeric};

    use crate::helpers::gen_random_hex;

    use super::*;

    fn ran_s(x: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(x)
            .map(char::from)
            .collect()
    }

    fn ran_u8() -> u8 {
        // TODO rand update, but waiting for argon crypto as well
        rand::thread_rng().r#gen()
    }

    fn ran_n() -> i64 {
        rand::thread_rng().gen_range(0..2500)
    }

    fn ran_token(backup: bool) -> String {
        if backup {
            let charset = b"abcdef0123456789";
            let token_len = 16;
            let mut rng = rand::thread_rng();

            (0..token_len)
                .map(|_| {
                    let idx = rng.gen_range(0..charset.len());
                    charset[idx] as char
                })
                .collect()
        } else {
            let digit = || rand::thread_rng().gen_range(0..=9);
            format!(
                "{}{}{}{}{}{}",
                digit(),
                digit(),
                digit(),
                digit(),
                digit(),
                digit()
            )
        }
    }

    #[test]
    fn helpers_is_hex() {
        let len = 16;
        let result = gen_random_hex(len);

        assert!(IncomingDeserializer::is_hex(&result, len.into()));

        let len = 16;
        let result = gen_random_hex(len);
        assert!(IncomingDeserializer::is_hex(
            &result.to_lowercase(),
            len.into()
        ));

        let len = 128;
        let result = gen_random_hex(len);
        assert!(IncomingDeserializer::is_hex(&result, len.into()));

        let len = 128;
        let result = gen_random_hex(len);
        assert!(IncomingDeserializer::is_hex(
            &result.to_lowercase(),
            len.into()
        ));

        let len = 16;
        let result = format!("{}g", gen_random_hex(len));
        assert!(!IncomingDeserializer::is_hex(&result, 17));

        let len = 16;
        let result = format!("{}%", gen_random_hex(len));
        assert!(!IncomingDeserializer::is_hex(&result, 17));

        let len = 16;
        let result = gen_random_hex(len);
        assert!(!IncomingDeserializer::is_hex(&result.to_lowercase(), 17));
    }

    #[test]
    fn incoming_serializer_ulid_invalid() {
        let test = |ulid: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(ulid).into_deserializer();
            let result = IncomingDeserializer::ulid(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "ulid");
        };

        test("0");
        test("123");
        test(&gen_random_hex(128));
        test(&gen_random_hex(36));
        test(&format!("{}I", gen_random_hex(25)));
        test("a23e4567e89b12d3a45655664244000");

        test(&format!(
            "{}-{}-{}-{}-{}",
            gen_random_hex(8),
            gen_random_hex(4),
            gen_random_hex(4),
            gen_random_hex(4),
            gen_random_hex(12)
        ));
    }

    #[test]
    fn incoming_serializer_ulid_valid() {
        let test = |ulid: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(ulid).into_deserializer();
            let result = IncomingDeserializer::ulid(deserializer);
            assert!(result.is_ok());
        };
        test(&Ulid::new().to_string());
        test(&Ulid::new().to_string());
        test(&Ulid::new().to_string());
    }

    #[test]
    fn incoming_serializer_rate_limit_invalid() {
        let test = |rate_limit: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(rate_limit).into_deserializer();
            let result = IncomingDeserializer::rate_limit(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "rate_limit");
        };

        test(&gen_random_hex(128));
        test(&gen_random_hex(36));
        test("ratelimit:e");
        test("::e");
        test("ratelimit::api_key::");
        test("ratelimit::ws_free::");
        test("ratelimit::ws_pro::");
        test("ratelimit::ip::");
        test("ratelimit::email::");
        test(&format!("ratelimit::apikey::{}", gen_random_hex(128)));
        test(&format!("ratelimit::wsfree::{}", ran_n()));
        test("ratelimit::ws_pro");
        test("ratelimit::ip");
        test("ratelimit::email");
        test(&format!("ratelimit::api_key::{}", ran_u8()));
        test(&format!("ratelimit::ws_free::{}", gen_random_hex(128)));
        test(&format!("ratelimit::ws_pro::{}", gen_random_hex(128)));
        test(&format!(
            "ratelimit::ip::{}.{}.{}",
            ran_u8(),
            ran_u8(),
            ran_u8()
        ));
        test(&format!(
            "ratelimit::email::{}@{}",
            gen_random_hex(10),
            gen_random_hex(10)
        ));
    }

    #[test]
    fn incoming_serializer_rate_limit_valid() {
        let test = |rate_limit: String| {
            let deserializer: StringDeserializer<ValueError> = rate_limit.into_deserializer();
            let result = IncomingDeserializer::rate_limit(deserializer);
            assert!(result.is_ok());
        };
        test(format!("ratelimit::api_key::{}", gen_random_hex(128)));
        test(format!("ratelimit::ws_free::{}", ran_u8()));
        test(format!("ratelimit::ws_pro::{}", ran_u8()));
        test(format!(
            "ratelimit::ip::{}.{}.{}.{}",
            ran_u8(),
            ran_u8(),
            ran_u8(),
            ran_u8()
        ));
        test(format!("ratelimit::user::{}", ran_n() + 1));
    }

    #[test]
    fn incoming_serializer_token_ok() {
        // Should split tests, match as totp, or match as backup
        let test = |token: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(token).into_deserializer();
            let result = IncomingDeserializer::token(deserializer);
            assert!(result.is_ok());
            assert_eq!(
                result.unwrap().to_string(),
                token.replace(' ', "").to_uppercase()
            );
        };

        test("111111");
        test("111 111");
        test(" 111 111 ");
        test(&ran_token(false));
        test("aaaaaabbbbbb1234");
        test("aaaaa abbbbbb1 234");
        test(&ran_token(true));
        test(&ran_token(true).to_uppercase());
    }

    #[test]
    fn incoming_serializer_token_err() {
        let test = |token: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(token).into_deserializer();
            let result = IncomingDeserializer::token(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "token");
        };

        test("12345");
        test("1234567");
        test("12345a");
        test("aaaabbbbccccdddd1");
        test("zzzzzzzzzzzzzzzz");
        test(&format!("{}z", ran_token(true)));
    }

    #[test]
    fn incoming_serializer_device_err() {
        let test = |device: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(device).into_deserializer();
            let result = IncomingDeserializer::device_type(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "device_type");
        };

        test("Pi ");
        test("P1");
        test("clien");
        test("client ");
        test("lient");
        test("");
        test("device");
        test(&gen_random_hex(6));
    }

    #[test]
    fn incoming_serializer_device_ok() {
        let device = "pi";
        let deserializer: StringDeserializer<ValueError> = S!(device).into_deserializer();
        let result = IncomingDeserializer::device_type(deserializer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ConnectionType::Pi);

        let device = "PI";
        let deserializer: StringDeserializer<ValueError> = S!(device).into_deserializer();
        let result = IncomingDeserializer::device_type(deserializer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ConnectionType::Pi);

        let device = "client";
        let deserializer: StringDeserializer<ValueError> = S!(device).into_deserializer();
        let result = IncomingDeserializer::device_type(deserializer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ConnectionType::Client);

        let device = "ClIeNt";
        let deserializer: StringDeserializer<ValueError> = S!(device).into_deserializer();
        let result = IncomingDeserializer::device_type(deserializer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ConnectionType::Client);
    }

    #[test]
    fn incoming_serializer_email_ok() {
        let test = |email: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(email).into_deserializer();
            let result = IncomingDeserializer::email(deserializer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), email.to_lowercase());
        };

        test("email@email.com");
        test("email@email.com".to_uppercase().as_str());
        test(&format!("{}@{}.{}", ran_s(10), ran_s(10), ran_s(3)));
        test(&format!("{}@{}.{}", ran_s(10), ran_s(10), ran_s(3)).to_uppercase());
    }

    #[test]
    fn incoming_serializer_email_err() {
        let test = |email: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(email).into_deserializer();
            let result = IncomingDeserializer::email(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "email");
        };

        test("emailemail.com");
        test("");
        test(" ");
        test(" @ . ");
        test(" @.com");
        test(" @ .com");
        test("email@");
        test("@email.com");
        test("email@email");
        test("email@email.");

        let deserializer: I64Deserializer<ValueError> = ran_n().into_deserializer();
        let result = IncomingDeserializer::email(deserializer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "email");
    }

    #[test]
    fn incoming_serializer_name_ok() {
        let test = |name: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(name).into_deserializer();
            let result = IncomingDeserializer::name(deserializer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), name.trim());
        };

        test("aabbccd");
        test("sdfsdf ");
        test("sdfsdf ");
        test("sdfsdf bakaks");
        test(" sdfsdf bakaks ");
    }

    #[test]
    fn incoming_serializer_name_err() {
        let test = |name: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(name).into_deserializer();
            let result = IncomingDeserializer::name(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "name");
        };

        test("invalid.name");
        test("invalid1name");
        test("John 1 Smith");
        test("");
        test(" ");
        test("        ");

        let deserializer: I64Deserializer<ValueError> = ran_n().into_deserializer();
        let result = IncomingDeserializer::name(deserializer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "name");
    }

    #[test]
    fn incoming_serializer_password() {
        let test = |password: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(password).into_deserializer();
            let result = IncomingDeserializer::password(deserializer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), password);
        };

        test(&ran_s(12));
        test("            ");
        test(&ran_s(40));
        test(&ran_s(99));
    }

    #[test]
    fn incoming_serializer_password_err() {
        let test = |password: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(password).into_deserializer();
            let result = IncomingDeserializer::password(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "password");
        };

        test("");
        test(&ran_s(11));
        test(&ran_s(100));

        let deserializer: I64Deserializer<ValueError> = ran_n().into_deserializer();
        let result = IncomingDeserializer::password(deserializer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "password");
    }

    #[test]
    fn incoming_serializer_invite() {
        let test = |invite: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(invite).into_deserializer();
            let result = IncomingDeserializer::invite(deserializer);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), invite);
        };

        test(&ran_s(12));
        test("            ");
        test(&ran_s(40));
        test(&ran_s(99));
    }

    #[test]
    fn incoming_serializer_invite_err() {
        let test = |invite: &str| {
            let deserializer: StringDeserializer<ValueError> = S!(invite).into_deserializer();
            let result = IncomingDeserializer::invite(deserializer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().to_string(), "invite");
        };

        test("");
        test(&ran_s(11));
        test(&ran_s(100));

        let deserializer: I64Deserializer<ValueError> = ran_n().into_deserializer();
        let result = IncomingDeserializer::invite(deserializer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "invite");
    }
}

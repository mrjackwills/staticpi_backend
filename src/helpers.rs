use crate::api_error::ApiError;
use rand::{prelude::SliceRandom, Rng};
use sha1::{Digest, Sha1};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::SystemTime,
};
use tracing::error;

const HEX_CHARS: &[u8; 16] = b"ABCDEF0123456789";
const HIBP: &str = "https://api.pwnedpasswords.com/range/";

const DESC: [&str; 32] = [
    "ace",
    "amazing",
    "astonishing",
    "awesome",
    "brilliant",
    "champion",
    "cool",
    "dazzling",
    "delicious",
    "delightful",
    "elegant",
    "excellent",
    "exquisite",
    "fantastic",
    "fascinating",
    "glorious",
    "great",
    "immense",
    "majestic",
    "marvellous",
    "opulent",
    "perfect",
    "phenomenal",
    "remarkable",
    "sensational",
    "stunning",
    "superb",
    "surprising",
    "tasty",
    "unbeatable",
    "unrivalled",
    "wonderful",
];

const CHEESE: [&str; 32] = [
    "asiago",
    "beaufort",
    "brie",
    "burrata",
    "camembert",
    "cheddar",
    "comté",
    "cornish",
    "edam",
    "emmental",
    "feta",
    "gorgonzola",
    "gouda",
    "halloumi",
    "havarti",
    "jarlsberg",
    "limburger",
    "manchego",
    "mascarpone",
    "mozzarella",
    "munster",
    "parmesan",
    "pepperjack",
    "provolone",
    "ricotta",
    "roquefort",
    "sagederby",
    "stilton",
    "swaledale",
    "swiss",
    "wensleydale",
    "yarg",
];

/// use `app_env.start_time` to work out how long the application has been running for, in seconds
pub fn calc_uptime(start_time: SystemTime) -> u64 {
    std::time::SystemTime::now()
        .duration_since(start_time)
        .map_or(0, |value| value.as_secs())
}
/// Generate a random, uppercase, hex string of length `output_len`
pub fn gen_random_hex(output_len: u8) -> String {
    (0..output_len)
        .map(|_| {
            let idx = rand::thread_rng().gen_range(0..HEX_CHARS.len());
            HEX_CHARS[idx] as char
        })
        .collect::<String>()
}

/// Generate a device name, will be `{description}-{cheese}`
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
pub fn gen_random_device_name() -> String {
    // Unwrap as we know that the slices to choose from are not empty
    let prefix = DESC.choose(&mut rand::thread_rng()).unwrap();
    let suffix = CHEESE.choose(&mut rand::thread_rng()).unwrap();
    format!("{prefix}-{suffix}")
}

/// Check if two byte arrays match, rather than ==
pub fn xor(input_1: &[u8], input_2: &[u8]) -> bool {
    if input_1.len() != input_2.len() {
        return false;
    }
    std::iter::zip(input_1, input_2)
        .map(|x| (x.0 ^ x.1) as usize)
        .sum::<usize>()
        == 0
}

/// Check if two byte arrays match, rather than ==, by hashing, then comparing both inputs
#[allow(unused)]
pub fn xor_hash(s1: &[u8], s2: &[u8]) -> bool {
    calculate_hash(s1) == calculate_hash(s2)
}

/// Create a hash, in order to compare to another hash, instead of using "abc" === "abc", etc
#[allow(unused)]
fn calculate_hash<T: Hash>(x: T) -> u64 {
    let mut hasher = DefaultHasher::new();
    x.hash(&mut hasher);
    hasher.finish()
}

pub async fn pwned_password(password: &str) -> Result<bool, ApiError> {
    let mut sha_digest = Sha1::default();
    sha_digest.update(password.as_bytes());
    let password_hex = hex::encode(sha_digest.finalize()).to_uppercase();
    let split_five = password_hex.split_at(5);
    let url = format!("{HIBP}{}", split_five.0);
    match reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(10000))
        .gzip(true)
        .brotli(true)
        .build()?
        .get(url)
        .send()
        .await
    {
        Ok(data) => {
            let response = data.text().await.unwrap_or_default();
            Ok(response.lines().any(|line| {
                let result_split = line.split_once(':').unwrap_or_default();
                // Check not "0", as some results get padded with a "0" response, if don't meet minimum number (think currently 381)
                result_split.0 == split_five.1 && result_split.1 != "0"
            }))
        }
        Err(e) => {
            error!("{e:?}");
            Err(ApiError::Internal(String::from("hibp request error")))
        }
    }
}

/// cargo watch -q -c -w src/ -x 'test helpers_ -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {
    use crate::servers::test_setup::UNSAFE_PASSWORD;

    use super::*;

    // WARNING - This tests against a live third party api via https
    #[tokio::test]
    async fn helpers_pwned_password() {
        let result = pwned_password(UNSAFE_PASSWORD).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = pwned_password("this_shouldn't_be_in_hibp_¯;ë±¨ÛdëzF=êÆVÜ;Ê_a¤ª<ý*;3¼z#±~xæ9áSÀ4õaJõò)*p'~fL¯se/)D¡½þ¡Kãß¢").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn helpers_random_hex() {
        let len = 16;
        let result = gen_random_hex(len);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(result.chars().count() == len as usize);

        let len = 64;
        let result = gen_random_hex(len);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(result.chars().count() == len as usize);

        let len = 128;
        let result = gen_random_hex(len);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(result.chars().count() == len as usize);
    }

    #[test]
    fn helpers_xor() {
        let s1 = gen_random_hex(16);
        let result = xor(s1.as_bytes(), s1.as_bytes());
        assert!(result);

        let s1 = gen_random_hex(16);
        let s2 = gen_random_hex(17);
        let result = xor(s1.as_bytes(), s2.as_bytes());
        assert!(!result);

        let s1 = gen_random_hex(16);
        let result = xor(s1.as_bytes(), s1.to_lowercase().as_bytes());
        assert!(!result);

        let s1 = gen_random_hex(16);
        let s2 = gen_random_hex(16);
        let result = xor(s1.as_bytes(), s2.as_bytes());
        assert!(!result);
    }

    #[test]
    fn helpers_xor_hash() {
        let s1 = gen_random_hex(16);
        let result = xor_hash(s1.as_bytes(), s1.as_bytes());
        assert!(result);

        let s1 = gen_random_hex(16);
        let s2 = gen_random_hex(17);
        let result = xor_hash(s1.as_bytes(), s2.as_bytes());
        assert!(!result);

        let s1 = gen_random_hex(16);
        let result = xor_hash(s1.as_bytes(), s1.to_lowercase().as_bytes());
        assert!(!result);

        let s1 = gen_random_hex(16);
        let s2 = gen_random_hex(16);
        let result = xor_hash(s1.as_bytes(), s2.as_bytes());
        assert!(!result);
    }

    #[test]
    fn helpers_gen_random_device_name() {
        let device_name = gen_random_device_name();
        assert!(device_name.contains('-'));
        let (desc, cheese) = device_name.split_once('-').unwrap_or_default();
        assert!(DESC.contains(&desc));
        assert!(CHEESE.contains(&cheese));
    }
}

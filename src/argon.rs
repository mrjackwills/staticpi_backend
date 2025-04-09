use argon2::{
    Algorithm::Argon2id, Argon2, Params, ParamsBuilder, PasswordHash, Version::V0x13,
    password_hash::SaltString,
};
use std::{fmt, sync::LazyLock};

use crate::{C, S, api_error::ApiError};

#[expect(clippy::unwrap_used)]
#[cfg(debug_assertions)]
static PARAMS: LazyLock<Params> = LazyLock::new(|| {
    ParamsBuilder::new()
        .m_cost(4096)
        .t_cost(1)
        .p_cost(1)
        .build()
        .unwrap()
});

/// This takes 19 seconds when testing, hence the above `not-release` version
#[cfg(not(debug_assertions))]
#[expect(clippy::unwrap_used)]
static PARAMS: LazyLock<Params> = LazyLock::new(|| {
    ParamsBuilder::new()
        .m_cost(24 * 1024)
        .t_cost(64)
        .p_cost(1)
        .build()
        .unwrap()
});

fn get_hasher() -> Argon2<'static> {
    Argon2::new(Argon2id, V0x13, C!(PARAMS))
}

// Fix this to impl from postgres!
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgonHash(String);

impl fmt::Display for ArgonHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ArgonHash {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ArgonHash {
    fn from(value: &str) -> Self {
        Self(S!(value))
    }
}

impl ArgonHash {
    // Could to impl<AsRef String> here?
    pub async fn new(password: String) -> Result<Self, ApiError> {
        let password_hash = Self::hash_password(password).await?;
        Ok(Self(password_hash))
    }

    /// create a password hash, use blocking to run in own thread
    async fn hash_password(password: String) -> Result<String, ApiError> {
        tokio::task::spawn_blocking(move || -> Result<String, ApiError> {
            let salt = SaltString::generate(rand::thread_rng());
            match PasswordHash::generate(get_hasher(), password, &salt) {
                Ok(hash) => Ok(hash.to_string()),
                Err(e) => {
                    tracing::error!("{e}");
                    Err(ApiError::Internal(S!("password_hash generate")))
                }
            }
        })
        .await?
    }
}

/// check a password against a known password hash, use blocking to run in own thread
pub async fn verify_password(password: &str, argon_hash: ArgonHash) -> Result<bool, ApiError> {
    let password = S!(password);
    tokio::task::spawn_blocking(move || -> Result<bool, ApiError> {
        PasswordHash::new(&argon_hash.0).map_or(
            Err(ApiError::Internal(S!("verify_password::new_hash"))),
            |hash| match hash.verify_password(&[&get_hasher()], password) {
                Ok(()) => Ok(true),
                Err(e) => match e {
                    // Could always just return false, no need to worry about internal errors?
                    argon2::password_hash::Error::Password => Ok(false),
                    _ => Err(ApiError::Internal(S!("verify_password"))),
                },
            },
        )
    })
    .await?
}

/// http tests - ran via actual requests to a (local) server
/// cargo watch -q -c -w src/ -x 'test argon_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::pedantic)]
mod tests {

    use rand::{Rng, distributions::Alphanumeric};
    use regex::Regex;
    use std::sync::LazyLock;

    use crate::C;

    use super::*;
    static ARGON_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\$argon2id\$v=19\$m=4096,t=1,p=1\$[a-zA-Z0-9+/=]{22}\$[a-zA-Z0-9+/=]{43}")
            .unwrap()
    });

    fn ran_s(x: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(x)
            .map(char::from)
            .collect()
    }

    #[tokio::test]
    async fn argon_mod_hash() {
        let password = ran_s(20);
        let result = ArgonHash::new(C!(password)).await;
        assert!(result.is_ok());
        assert!(ARGON_REGEX.is_match(&result.unwrap().to_string()));
    }

    #[tokio::test]
    async fn argon_mod_verify_random() {
        let password = ran_s(20);
        let argon_hash = ArgonHash::new(C!(password)).await.unwrap();

        // Verify true
        let result = verify_password(&password, argon_hash).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify false
        let short_pass = password.chars().take(19).collect::<String>();
        let argon_hash = ArgonHash::new(C!(password)).await.unwrap();
        let result = verify_password(&short_pass, argon_hash).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn argon_mod_verify_known() {
        let password = "This is a known password";
        let password_hash = ArgonHash(S!(
            "$argon2id$v=19$m=4096,t=5,p=1$rahU5enqn3WcOo9A58Ifjw$I+7yA6+29LuB5jzPUwnxtLoH66Lng7ExWqHdivwj8Es"
        ));

        // Verify true
        let result = verify_password(password, C!(password_hash)).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify false
        let result = verify_password("this is a known password", password_hash).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelBannedEmail {
    pub domain: String,
}

impl ModelBannedEmail {
    /// Check if a given email address' domain is in the table of banned domains
    pub async fn get(postgres: &PgPool, email: &str) -> Result<Option<Self>, sqlx::Error> {
        let domain = email.split_once('@').unwrap_or_default().1;
        sqlx::query_as::<_, Self>(
            r#"
		SELECT
			domain
		FROM
			banned_email_domain
		WHERE
			domain = $1"#,
        )
        .bind(domain.to_lowercase())
        .fetch_optional(postgres)
        .await
    }
}

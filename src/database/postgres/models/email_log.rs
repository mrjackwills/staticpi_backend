use crate::{api_error::ApiError, database::postgres::Count, emailer::EmailTemplate};
use serde::Deserialize;
use sqlx::PgPool;

use super::{
    email_address::ModelEmailAddress,
    ip_user_agent::ModelUserAgentIp,
    new_types::{EmailLogId, EmailSubjectId},
};

#[derive(sqlx::FromRow, Debug, Clone, Deserialize, PartialEq, Eq)]
struct EmailSubject {
    email_subject_id: EmailSubjectId,
}

#[derive(sqlx::FromRow, Debug, Deserialize, PartialEq, Eq)]
pub struct ModelEmailLog {
    email_log_id: EmailLogId,
}

impl ModelEmailLog {
    // Count of the emails sent in the past hour
    pub async fn get_count_hour(postgres: &PgPool) -> Result<Count, ApiError> {
        Ok(sqlx::query_as!(
            Count,
            r#"
SELECT
    COUNT(*) AS "count!"
FROM
    email_log
WHERE
    sent = TRUE
    AND timestamp >= NOW() - INTERVAL '1 hour'"#
        )
        .fetch_one(postgres)
        .await?)
    }

    // Count of all emails sent
    pub async fn get_count_total(postgres: &PgPool) -> Result<Count, ApiError> {
        Ok(sqlx::query_as!(
            Count,
            r#"SELECT
    COUNT(*) AS "count!"
FROM
    email_log"#
        )
        .fetch_one(postgres)
        .await?)
    }

    /// If email failure, set as sent false, issue with testing when doing this on a separate thread
    /// seemed easier this way
    pub async fn update_sent_false(&self, postgres: &PgPool) {
        if let Err(e) = sqlx::query!(
            "UPDATE
    email_log
SET
    sent = FALSE
WHERE
    email_log_id = $1",
            self.email_log_id.get()
        )
        .execute(postgres)
        .await
        {
            tracing::error!("{e:?}");
        }
    }

    pub async fn insert(
        postgres: &PgPool,
        email_template: &EmailTemplate,
        useragent_ip: &ModelUserAgentIp,
        email_address: &str,
    ) -> Result<Self, ApiError> {
        let mut transaction = postgres.begin().await?;
        let email_address_id =
            match ModelEmailAddress::get(&mut *transaction, email_address).await? {
                Some(model) => model,
                _ => ModelEmailAddress::insert(&mut *transaction, email_address).await?,
            };

        let subject = email_template.get_subject();

        let email_subject_id = if let Some(email_subject) = sqlx::query_as!(
            EmailSubject,
            "
SELECT
    email_subject_id
FROM
    email_subject
WHERE
    subject = $1",
            &subject
        )
        .fetch_optional(&mut *transaction)
        .await?
        {
            email_subject
        } else {
            sqlx::query_as!(
                EmailSubject,
                "
        INSERT INTO
            email_subject(subject)
        VALUES
            ($1)
        RETURNING
            email_subject_id",
                &subject
            )
            .fetch_one(&mut *transaction)
            .await?
        };
        let email_log = sqlx::query_as!(
            Self,
            "
INSERT INTO
    email_log (
        ip_id,
        user_agent_id,
        email_address_id,
        email_subject_id
    )
VALUES
    ($1, $2, $3, $4) RETURNING email_log_id",
            useragent_ip.ip_id.get(),
            useragent_ip.user_agent_id.get(),
            email_address_id.email_address_id.get(),
            email_subject_id.email_subject_id.get()
        )
        .fetch_one(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(email_log)
    }
}

use sqlx::{PgPool, types::time::OffsetDateTime};

use crate::{
    api_error::ApiError, argon::ArgonHash, database::redis::two_fa_setup::RedisTwoFASetup,
};

use super::{
    ip_user_agent::ModelUserAgentIp,
    new_types::{IpId, TwoFaBackupId, TwoFaSecretId, UserAgentId, UserId},
    user::ModelUser,
};

#[derive(sqlx::FromRow, Debug, Clone, PartialEq, Eq)]
pub struct ModelTwoFA {
    pub two_fa_secret_id: TwoFaSecretId,
    pub always_required: bool,
    pub timestamp: OffsetDateTime,
    pub ip_id: IpId,
    pub user_agent_id: UserAgentId,
    two_fa_secret: String,
}

impl ModelTwoFA {
    pub async fn insert(
        postgres: &PgPool,
        two_fa_setup: RedisTwoFASetup,
        useragent_ip: &ModelUserAgentIp,
        user: &ModelUser,
    ) -> Result<(), ApiError> {
        sqlx::query!(
            "
INSERT INTO
    two_fa_secret(
        registered_user_id,
        ip_id,
        user_agent_id,
        two_fa_secret
    )
VALUES
($1, $2, $3, $4)",
            user.registered_user_id.get(),
            useragent_ip.ip_id.get(),
            useragent_ip.user_agent_id.get(),
            two_fa_setup.value()
        )
        .execute(postgres)
        .await?;
        Ok(())
    }

    pub async fn update_always_required(
        postgres: &PgPool,
        always_required: bool,
        user: &ModelUser,
    ) -> Result<(), ApiError> {
        sqlx::query!(
            "
UPDATE
    two_fa_secret
SET
    always_required = $1
WHERE
    registered_user_id = $2",
            always_required,
            user.registered_user_id.get()
        )
        .execute(postgres)
        .await?;
        Ok(())
    }

    pub async fn delete(postgres: &PgPool, user: &ModelUser) -> Result<(), ApiError> {
        sqlx::query!(
            "
DELETE FROM
    two_fa_secret
WHERE
    registered_user_id = $1",
            user.registered_user_id.get()
        )
        .execute(postgres)
        .await?;
        Ok(())
    }
}

#[derive(sqlx::FromRow, Debug, Clone, PartialEq, Eq)]
pub struct ModelTwoFABackup {
    pub two_fa_backup_id: TwoFaBackupId,
    two_fa_backup_code: String,
}

impl ModelTwoFABackup {
    pub fn as_hash(&self) -> ArgonHash {
        ArgonHash::from(self.two_fa_backup_code.as_str())
    }

    pub async fn get(postgres: &PgPool, registered_user_id: UserId) -> Result<Vec<Self>, ApiError> {
        Ok(sqlx::query_as!(
            Self,
            "
SELECT
    two_fa_backup_code,
    two_fa_backup_id
FROM
    two_fa_backup
WHERE
    registered_user_id = $1",
            registered_user_id.get()
        )
        .fetch_all(postgres)
        .await?)
    }

    pub async fn insert(
        postgres: &PgPool,
        user: &ModelUser,
        useragent_ip: &ModelUserAgentIp,
        backup_hashes: Vec<ArgonHash>,
    ) -> Result<(), ApiError> {
        let mut transaction = postgres.begin().await?;

        for hash in backup_hashes {
            sqlx::query!(
                "
INSERT INTO
    two_fa_backup(
        registered_user_id,
        user_agent_id,
        ip_id,
        two_fa_backup_code
    )
VALUES
($1, $2, $3, $4)",
                user.registered_user_id.get(),
                useragent_ip.user_agent_id.get(),
                useragent_ip.ip_id.get(),
                hash.to_string()
            )
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn delete_one(
        postgres: &PgPool,
        two_fa_backup_id: TwoFaBackupId,
    ) -> Result<(), ApiError> {
        sqlx::query!(
            "
DELETE FROM
    two_fa_backup
WHERE
    two_fa_backup_id = $1",
            two_fa_backup_id.get()
        )
        .execute(postgres)
        .await?;
        Ok(())
    }

    pub async fn delete_all(postgres: &PgPool, user: &ModelUser) -> Result<(), ApiError> {
        sqlx::query!(
            "
DELETE FROM
    two_fa_backup
WHERE
    registered_user_id = $1",
            user.registered_user_id.get()
        )
        .execute(postgres)
        .await?;
        Ok(())
    }
}

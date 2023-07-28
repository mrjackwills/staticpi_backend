mod models;
use crate::api_error::ApiError;
pub use models::*;

pub trait FromModel<T> {
    type Item;
    fn from_model(t: T) -> Result<Self::Item, ApiError>;
}

#[derive(Debug, sqlx::FromRow)]
pub struct Count {
    pub count: i64,
}

pub mod db_postgres {

    use crate::{api_error::ApiError, parse_env::AppEnv};
    use sqlx::{postgres::PgPoolOptions, ConnectOptions, PgPool};

    pub async fn db_pool(app_env: &AppEnv) -> Result<PgPool, ApiError> {
        let mut options = sqlx::postgres::PgConnectOptions::new()
            .host(&app_env.pg_host)
            .port(app_env.pg_port)
            .database(&app_env.pg_database)
            .username(&app_env.pg_user)
            .password(&app_env.pg_password);

        match app_env.log_level {
            tracing::Level::TRACE | tracing::Level::DEBUG => (),
            _ => options = options.disable_statement_logging(),
        }

        let acquire_timeout = std::time::Duration::from_secs(5);
        let idle_timeout = std::time::Duration::from_secs(10);

        // Max connections on postgres is default 100, and no other application should be using it
        // Except the backup application!
        Ok(PgPoolOptions::new()
            .max_connections(75)
            .idle_timeout(idle_timeout)
            .acquire_timeout(acquire_timeout)
            .connect_with(options)
            .await?)
    }
}

/// cargo watch -q -c -w src/ -x 'test db_postgres_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic, clippy::nursery)]
mod tests {
    use crate::parse_env;

    use super::*;

    #[derive(sqlx::FromRow)]
    struct DB {
        current_database: String,
    }

    #[tokio::test]
    async fn db_postgres_mod_get_connection() {
        let app_env = parse_env::AppEnv::get_env();

        let result = db_postgres::db_pool(&app_env).await;
        assert!(result.is_ok());

        let result = sqlx::query_as::<_, DB>("SELECT current_database()")
            .fetch_one(&result.unwrap())
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().current_database, "dev_staticpi");
    }
}

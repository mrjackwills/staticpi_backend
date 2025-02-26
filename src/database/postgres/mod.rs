mod models;
pub use models::*;

#[derive(Debug, sqlx::FromRow)]
pub struct Count {
    pub count: i64,
}

pub mod db_postgres {

    use crate::{api_error::ApiError, parse_env::AppEnv};
    use sqlx::{ConnectOptions, PgPool, postgres::PgPoolOptions};

    pub async fn db_pool(app_env: &AppEnv) -> Result<PgPool, ApiError> {
        let mut options = sqlx::postgres::PgConnectOptions::new_without_pgpass()
            .host(&app_env.pg_host)
            .port(app_env.pg_port)
            .database(&app_env.pg_database)
            .username(&app_env.pg_user)
            .password(&app_env.pg_password);

        match app_env.log_level {
            tracing::Level::TRACE | tracing::Level::DEBUG => (),
            _ => options = options.disable_statement_logging(),
        }

        // Max connections on postgres is default 100, and no other application should be using it
        // Except the backup application!
        Ok(PgPoolOptions::new()
            .max_connections(75)
            .connect_with(options)
            .await?)
    }
}

/// cargo watch -q -c -w src/ -x 'test db_postgres_mod -- --test-threads=1 --nocapture'
#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::pedantic)]
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
        assert_eq!(result.unwrap().current_database, "staticpi");
    }
}

use std::sync::Arc;

use crate::connections::AMConnections;
use sqlx::PgPool;
use time::OffsetDateTime;

pub struct Pinger;

#[macro_export]
/// Sleep for a given number of milliseconds, is an async fn.
/// If no parameter supplied, defaults to 250ms
macro_rules! sleep {
    () => {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };
    ($ms:expr) => {
        tokio::time::sleep(std::time::Duration::from_millis($ms)).await;
    };
}

impl Pinger {
    /// Ping every connection every 30 seconds
    pub async fn init(connections: AMConnections, postgres: PgPool) {
        let current_second = OffsetDateTime::now_utc().second();
        let wait_for = if current_second > 30 {
            60 - current_second
        } else {
            30 - current_second
        };
        sleep!(u64::from(wait_for) * 1000);
        connections.lock().await.ping(&postgres).await;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            // should check if each kill_instant is <= now, and if so, kill connection!
            // so get all connections here, and loop over, and need to update postgres if kill, so need to take a postgres here
            interval.tick().await;

            // think might need to spawn this into it's own thread
            let postgres = postgres.clone();
            let connections = Arc::clone(&connections);
            tokio::spawn(async move {
                //  I don't like this?
                //  Should lock to get connections
                // then loop over, and kill or ping depending on autclose
                connections.lock().await.ping(&postgres).await;
            });
        }
    }
}

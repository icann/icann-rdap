use sqlx::migrate::Migrator;

use crate::error::RdapServerError;

pub static MIGRATOR: Migrator = sqlx::migrate!();

pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), RdapServerError> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| RdapServerError::Config(e.to_string()))?;
    Ok(())
}

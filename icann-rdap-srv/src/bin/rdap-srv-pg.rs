use {
    clap::{Parser, Subcommand},
    icann_rdap_common::VERSION,
    icann_rdap_srv::{
        config::LOG,
        storage::pg::{db_url::DbUrlParts, migration::run_migrations},
    },
    sqlx::{AssertSqlSafe, PgPool},
    tracing::info,
    tracing_subscriber::{
        EnvFilter, fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
    },
};

#[derive(Parser, Debug)]
#[command(name = "rdap-srv-pg", author, version = VERSION, about, long_about)]
/// PostgreSQL setup and migration tool for the RDAP server.
struct Cli {
    /// PostgreSQL connection URL for the RDAP database
    #[arg(
        long,
        env = "RDAP_SRV_DB_URL",
        default_value = "postgresql://127.0.0.1/rdap"
    )]
    db_url: String,

    #[command(subcommand)]
    command: Option<DbCommand>,
}

#[derive(Subcommand, Debug)]
enum DbCommand {
    /// Create the database user and database
    Create(CreateArgs),

    /// Destroy (drop) the database and user
    Destroy(DestroyArgs),

    /// Run database migrations
    Migrate(MigrateArgs),
}

#[derive(clap::Args, Debug)]
struct CreateArgs {
    /// The admin user.
    #[arg(long)]
    admin_user: String,

    /// Password for the admin user.
    #[arg(long)]
    admin_password: Option<String>,
}

#[derive(clap::Args, Debug)]
struct DestroyArgs {
    /// The admin user.
    #[arg(long)]
    admin_user: String,

    /// Password for the admin user.
    #[arg(long)]
    admin_password: Option<String>,
}

#[derive(clap::Args, Debug)]
struct MigrateArgs {}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env(LOG))
        .init();

    let cli = Cli::parse();

    match cli.command {
        None => {
            info!("No subcommand given, running migrate...");
            run_migrate(&cli.db_url).await?;
        }
        Some(DbCommand::Create(args)) => {
            run_create(
                &cli.db_url,
                &args.admin_user,
                args.admin_password.as_deref(),
            )
            .await?;
        }
        Some(DbCommand::Destroy(args)) => {
            run_destroy(
                &cli.db_url,
                &args.admin_user,
                args.admin_password.as_deref(),
            )
            .await?;
        }
        Some(DbCommand::Migrate(_)) => {
            run_migrate(&cli.db_url).await?;
        }
    }

    Ok(())
}

async fn run_create(
    db_url: &str,
    admin_user: &str,
    admin_password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts = DbUrlParts::from_url(db_url)?;
    let superuser_url = parts.to_superuser_url(admin_user, admin_password);

    info!("Connecting to PostgreSQL as superuser...");
    let superuser_pool = PgPool::connect(&superuser_url).await?;

    let password = if let Some(password) = parts.password {
        format!("'{password}'")
    } else {
        "NULL".to_string()
    };
    let create_user_sql = format!(
        r#"DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{}') THEN
        CREATE ROLE {} WITH LOGIN PASSWORD {} CREATEDB;
    END IF;
END
$$;"#,
        parts.user, parts.user, password
    );

    info!("Creating role {}...", parts.user);
    sqlx::query(AssertSqlSafe(create_user_sql))
        .execute(&superuser_pool)
        .await?;

    info!("Checking if database {} exists...", parts.database);
    let db_exists: Option<i32> = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT 1 FROM pg_database WHERE datname = '{}'",
        parts.database
    )))
    .fetch_optional(&superuser_pool)
    .await?;

    if db_exists.is_none() {
        let create_db_sql = format!("CREATE DATABASE {} OWNER {}", parts.database, parts.user);
        info!("Creating database {}...", parts.database);
        sqlx::query(AssertSqlSafe(create_db_sql))
            .execute(&superuser_pool)
            .await?;
    } else {
        info!("Database {} already exists.", parts.database);
    }

    info!(
        "Successfully created role '{}' and database '{}'",
        parts.user, parts.database
    );

    Ok(())
}

async fn run_destroy(
    db_url: &str,
    admin_user: &str,
    admin_password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts = DbUrlParts::from_url(db_url)?;
    let superuser_url = parts.to_superuser_url(admin_user, admin_password);

    info!("Connecting to PostgreSQL as superuser...");
    let superuser_pool = PgPool::connect(&superuser_url).await?;

    info!("Terminating existing connections to {}...", parts.database);
    let terminate_sql = format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
        parts.database
    );
    sqlx::query(AssertSqlSafe(terminate_sql))
        .execute(&superuser_pool)
        .await?;

    info!("Dropping database {}...", parts.database);
    let drop_db_sql = format!("DROP DATABASE IF EXISTS {}", parts.database);
    sqlx::query(AssertSqlSafe(drop_db_sql))
        .execute(&superuser_pool)
        .await?;

    info!("Dropping role {}...", parts.user);
    let drop_role_sql = format!("DROP ROLE IF EXISTS {}", parts.user);
    sqlx::query(AssertSqlSafe(drop_role_sql))
        .execute(&superuser_pool)
        .await?;

    info!(
        "Successfully dropped database '{}' and role '{}'",
        parts.database, parts.user
    );

    Ok(())
}

async fn run_migrate(db_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to database...");
    let pool = PgPool::connect(db_url).await?;

    info!("Running migrations...");
    run_migrations(&pool).await?;

    info!("Migrations completed successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_debug_assert_test() {
        use clap::CommandFactory;
        crate::Cli::command().debug_assert()
    }
}

use std::{
    net::{SocketAddr, TcpListener},
    time::Duration,
};

use axum::{error_handling::HandleErrorLayer, Router};
use http::{Method, StatusCode};
use icann_rdap_common::VERSION;
use sqlx::PgPool;
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    config::{ListenConfig, ServiceConfig, StorageType},
    error::RdapServerError,
    rdap::router::rdap_router,
    storage::{mem::Mem, pg::Pg, StorageOperations},
};

/// Holds information on the server listening.
pub struct Listener {
    pub local_addr: SocketAddr,
    tcp_listener: TcpListener,
}

/// Starts the RDAP service.
impl Listener {
    pub fn listen(config: &ListenConfig) -> Result<Self, RdapServerError> {
        let listener = TcpListener::bind(format!(
            "{}:{}",
            config.ip_addr.as_ref().unwrap_or(&"[::]".to_string()),
            config.port.as_ref().unwrap_or(&0)
        ))?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            local_addr,
            tcp_listener: listener,
        })
    }

    pub async fn start_server(self, config: &ServiceConfig) -> Result<(), RdapServerError> {
        tracing_subscriber::fmt::init();
        tracing::info!("dialtone version {}", VERSION);

        let app = match &config.storage_type {
            StorageType::Memory => app_router(AppState::new_mem().await),
            StorageType::Postgres { db_url } => app_router(AppState::new_pg(db_url).await),
        };

        tracing::debug!("listening on {}", self.local_addr);
        axum::Server::from_tcp(self.tcp_listener)?
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
        Ok(())
    }
}

fn app_router<T: StorageOperations + Clone + Send + Sync + 'static>(state: AppState<T>) -> Router {
    #[cfg(debug_assertions)]
    tracing::warn!("Server is running in development mode");

    Router::new()
        .nest("/rdap", rdap_router())
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {error}"),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(10))
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(vec![Method::GET])
                        .allow_headers(Any),
                )
                .into_inner(),
        )
        .with_state(state)
}

#[derive(Clone)]
pub struct AppState<T: StorageOperations + Clone + Send + Sync + 'static> {
    pub storage: T,
}

impl AppState<Pg> {
    pub async fn new_pg(db_url: &str) -> Self {
        Self {
            storage: Pg::new(PgPool::connect(db_url).await.unwrap()),
        }
    }
}

impl AppState<Mem> {
    pub async fn new_mem() -> Self {
        Self {
            storage: Mem::new(),
        }
    }
}

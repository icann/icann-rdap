use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use axum::{error_handling::HandleErrorLayer, Router};
use http::{Method, StatusCode};
use icann_rdap_common::VERSION;
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    config::{ListenConfig, ServiceConfig, StorageType},
    error::RdapServerError,
    rdap::router::rdap_router,
    storage::{
        mem::{config::MemConfig, ops::Mem},
        pg::{config::PgConfig, ops::Pg},
        StoreOps,
    },
};

/// Holds information on the server listening.
pub struct Listener {
    pub local_addr: SocketAddr,
    tcp_listener: TcpListener,
}

/// Starts the RDAP service.
impl Listener {
    pub fn listen(config: &ListenConfig) -> Result<Self, RdapServerError> {
        tracing::info!("dialtone version {}", VERSION);

        #[cfg(debug_assertions)]
        tracing::warn!("Server is running in development mode");

        let binding = format!(
            "{}:{}",
            config.ip_addr.as_ref().unwrap_or(&"[::]".to_string()),
            config.port.as_ref().unwrap_or(&0)
        );

        tracing::debug!("tcp binding to {}", binding);

        let listener = TcpListener::bind(binding)?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            local_addr,
            tcp_listener: listener,
        })
    }

    pub async fn start_server(self, config: &ServiceConfig) -> Result<(), RdapServerError> {
        if let StorageType::Memory(config) = &config.storage_type {
            let app_state = AppState::new_mem(config.clone()).await?;
            self.start_with_state(app_state).await?;
        } else if let StorageType::Postgres(config) = &config.storage_type {
            let app_state = AppState::new_pg(config.clone()).await?;
            self.start_with_state(app_state).await?;
        };
        Ok(())
    }

    pub async fn start_with_state<T>(self, app_state: AppState<T>) -> Result<(), RdapServerError>
    where
        T: StoreOps + Clone + Send + Sync + 'static,
        AppState<T>: StoreState,
    {
        let app = app_router::<T>(app_state);

        tracing::debug!("listening on {}", self.local_addr);
        axum::Server::from_tcp(self.tcp_listener)?
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
        Ok(())
    }
}

fn app_router<T>(state: AppState<T>) -> Router
where
    T: StoreOps + Clone + Send + Sync + 'static,
    AppState<T>: StoreState,
{
    let state = Arc::new(state) as DynStoreState;
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

pub(crate) type DynStoreState = Arc<dyn StoreState + Send + Sync>;

#[async_trait]
pub trait StoreState: std::fmt::Debug {
    async fn get_storage(&self) -> Result<&dyn StoreOps, RdapServerError>;
}

#[derive(Clone)]
pub struct AppState<T: StoreOps + Clone + Send + Sync + 'static> {
    pub storage: T,
}

impl AppState<Mem> {
    pub async fn new_mem(config: MemConfig) -> Result<AppState<Mem>, RdapServerError> {
        let storage = Mem::new(config);
        storage.init().await?;
        Ok(AppState::<Mem> { storage })
    }
}

impl std::fmt::Debug for AppState<Mem> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState<Mem>").finish()
    }
}

impl AppState<Pg> {
    pub async fn new_pg(config: PgConfig) -> Result<AppState<Pg>, RdapServerError> {
        let storage = Pg::new(config).await?;
        storage.init().await?;
        Ok(AppState::<Pg> { storage })
    }
}

impl std::fmt::Debug for AppState<Pg> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState<Pg>").finish()
    }
}

#[async_trait]
impl StoreState for AppState<Pg> {
    async fn get_storage(&self) -> Result<&dyn StoreOps, RdapServerError> {
        Ok(&self.storage)
    }
}

#[async_trait]
impl StoreState for AppState<Mem> {
    async fn get_storage(&self) -> Result<&dyn StoreOps, RdapServerError> {
        Ok(&self.storage)
    }
}

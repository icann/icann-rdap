use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{error_handling::HandleErrorLayer, Router};
use http::{Method, StatusCode};
use icann_rdap_common::VERSION;
use tokio::net::TcpListener;
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    bootstrap::init_bootstrap,
    config::{ListenConfig, ServiceConfig, StorageType},
    error::RdapServerError,
    rdap::router::rdap_router,
    storage::{
        data::{load_data, reload_data},
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
    pub async fn listen(config: &ListenConfig) -> Result<Self, RdapServerError> {
        tracing::info!("rdap-srv version {}", VERSION);

        #[cfg(debug_assertions)]
        tracing::warn!("Server is running in development mode");

        let binding = format!(
            "{}:{}",
            config.ip_addr.as_ref().unwrap_or(&"[::]".to_string()),
            config.port.as_ref().unwrap_or(&0)
        );

        tracing::debug!("tcp binding to {}", binding);

        let listener = TcpListener::bind(binding).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            local_addr,
            tcp_listener: listener,
        })
    }

    pub fn rdap_base(&self) -> String {
        if self.local_addr.is_ipv4() {
            format!(
                "http://{}:{}/rdap",
                self.local_addr.ip(),
                self.local_addr.port()
            )
        } else {
            format!(
                "http://[{}]:{}/rdap",
                self.local_addr.ip(),
                self.local_addr.port()
            )
        }
    }

    /// Starts the server using a [ServiceConfig]. This is the entry point for a CLI.
    /// This function will initiate any needed non-HTTP services and then call
    /// call [start_with_app_state()], which initiates the HTTP service.
    pub async fn start_server(self, service_config: &ServiceConfig) -> Result<(), RdapServerError> {
        init_bootstrap(service_config).await?;
        if let StorageType::Memory(config) = &service_config.storage_type {
            let app_state = AppState::new_mem(config.clone(), service_config).await?;
            self.start_with_state(app_state).await?;
        } else if let StorageType::Postgres(config) = &service_config.storage_type {
            let app_state = AppState::new_pg(config.clone(), service_config).await?;
            self.start_with_state(app_state).await?;
        };
        Ok(())
    }

    /// Starts the HTTP server with a specific [AppState]. This is the entry point for a library or testing
    /// framework.
    pub async fn start_with_state<T>(self, app_state: AppState<T>) -> Result<(), RdapServerError>
    where
        T: StoreOps + Clone + Send + Sync + 'static,
        AppState<T>: ServiceState,
    {
        let app = app_router::<T>(app_state);

        tracing::debug!("listening on {}", self.local_addr);
        // axum::Server::from_tcp(self.tcp_listener)?
        //     .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        //     .await?;
        axum::serve(
            self.tcp_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

async fn init_data(
    store: Box<dyn StoreOps>,
    config: &ServiceConfig,
) -> Result<(), RdapServerError> {
    load_data(config, &*store, false).await?;
    if config.auto_reload {
        tokio::spawn(reload_data(store, config.clone()));
    }
    Ok(())
}

fn app_router<T>(state: AppState<T>) -> Router
where
    T: StoreOps + Clone + Send + Sync + 'static,
    AppState<T>: ServiceState,
{
    let state = Arc::new(state) as DynServiceState;
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

pub(crate) type DynServiceState = Arc<dyn ServiceState + Send + Sync>;

#[async_trait]
pub trait ServiceState: std::fmt::Debug {
    /// Gets the backend storage lookup engine.
    async fn get_storage(&self) -> Result<&dyn StoreOps, RdapServerError>;

    /// If returns true, this indicates the server has been configured to do
    /// bootstrapping.
    fn get_bootstrap(&self) -> bool;
}

/// State that is passed to the HTTP service router and used by functions
/// servicing HTTP requests.
#[derive(Clone)]
pub struct AppState<T: StoreOps + Clone + Send + Sync + 'static> {
    pub storage: T,
    pub bootstrap: bool,
}

impl AppState<Mem> {
    pub async fn new_mem(
        config: MemConfig,
        service_config: &ServiceConfig,
    ) -> Result<AppState<Mem>, RdapServerError> {
        let storage = Mem::new(config);
        storage.init().await?;
        init_data(Box::new(storage.clone()), service_config).await?;
        Ok(AppState::<Mem> {
            storage,
            bootstrap: service_config.bootstrap,
        })
    }
}

impl std::fmt::Debug for AppState<Mem> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState<Mem>").finish()
    }
}

impl AppState<Pg> {
    pub async fn new_pg(
        config: PgConfig,
        service_config: &ServiceConfig,
    ) -> Result<AppState<Pg>, RdapServerError> {
        let storage = Pg::new(config).await?;
        storage.init().await?;
        init_data(Box::new(storage.clone()), service_config).await?;
        Ok(AppState::<Pg> {
            storage,
            bootstrap: service_config.bootstrap,
        })
    }
}

impl std::fmt::Debug for AppState<Pg> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState<Pg>").finish()
    }
}

#[async_trait]
impl ServiceState for AppState<Pg> {
    async fn get_storage(&self) -> Result<&dyn StoreOps, RdapServerError> {
        Ok(&self.storage)
    }

    fn get_bootstrap(&self) -> bool {
        self.bootstrap
    }
}

#[async_trait]
impl ServiceState for AppState<Mem> {
    async fn get_storage(&self) -> Result<&dyn StoreOps, RdapServerError> {
        Ok(&self.storage)
    }

    fn get_bootstrap(&self) -> bool {
        self.bootstrap
    }
}

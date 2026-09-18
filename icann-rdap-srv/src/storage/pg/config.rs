use buildstructor::Builder;

use crate::config::CommonConfig;

#[derive(Debug, Builder, Clone)]
pub struct PgConfig {
    pub db_url: String,
    pub common_config: CommonConfig,

    /// When true, the server ignores `RDAP_SRV_DATA_DIR` operations (the startup load and
    /// update/reload markers) because the Postgres database is the source of truth.
    pub ignore_data_dir: bool,
}

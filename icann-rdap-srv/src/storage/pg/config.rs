use buildstructor::Builder;

use crate::config::CommonConfig;

#[derive(Debug, Builder, Clone)]
pub struct PgConfig {
    pub db_url: String,
    pub common_config: CommonConfig,
}

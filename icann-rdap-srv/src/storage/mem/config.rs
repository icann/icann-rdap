use buildstructor::Builder;

use crate::config::CommonConfig;

#[derive(Debug, Builder, Clone)]
pub struct MemConfig {
    pub common_config: CommonConfig,
}

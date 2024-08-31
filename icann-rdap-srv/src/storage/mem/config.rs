use buildstructor::Builder;

use crate::storage::CommonConfig;

#[derive(Debug, Builder, Clone)]
pub struct MemConfig {
    pub common_config: CommonConfig,
}

use buildstructor::Builder;

#[derive(Debug, Builder, Clone)]
pub struct MemConfig {
    pub mirror_dir: String,
}

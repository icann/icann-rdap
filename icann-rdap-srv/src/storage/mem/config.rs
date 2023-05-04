use buildstructor::Builder;

#[derive(Debug, Builder, Clone)]
pub struct MemConfig {
    pub state_dir: String,
}

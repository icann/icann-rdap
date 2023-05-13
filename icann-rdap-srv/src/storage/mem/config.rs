use buildstructor::Builder;

#[derive(Debug, Builder, Clone)]
pub struct MemConfig {
    /// The directory where JSON files are located.
    pub state_dir: String,

    /// If true, automatically monitor the state directory and reload state.
    pub auto_reload: Option<bool>,
}

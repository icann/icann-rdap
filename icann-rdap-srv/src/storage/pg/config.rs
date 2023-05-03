use buildstructor::Builder;

#[derive(Debug, Builder, Clone)]
pub struct PgConfig {
    pub db_url: String,
}

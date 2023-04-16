pub mod response;

#[cfg(not(target_arch = "wasm32"))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

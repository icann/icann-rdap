pub mod check;
pub mod client;
pub mod contact;
pub mod iana;
pub mod media_types;
pub mod response;

#[cfg(debug_assertions)]
use const_format::formatcp;

#[cfg(not(any(target_arch = "wasm32", debug_assertions)))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(debug_assertions)]
pub const VERSION: &str = formatcp!("{}_DEV_BUILD", env!("CARGO_PKG_VERSION"));

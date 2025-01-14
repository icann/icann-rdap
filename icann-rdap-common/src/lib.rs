#![allow(rustdoc::bare_urls)]
#![doc = include_str!("../README.md")]
pub mod check;
pub mod contact;
pub mod dns_types;
pub mod httpdata;
pub mod iana;
pub mod media_types;
pub mod response;

#[cfg(debug_assertions)]
use const_format::formatcp;

/// Version of this software.
#[cfg(not(any(target_arch = "wasm32", debug_assertions)))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of this software.
#[cfg(debug_assertions)]
pub const VERSION: &str = formatcp!("{}_DEV_BUILD", env!("CARGO_PKG_VERSION"));

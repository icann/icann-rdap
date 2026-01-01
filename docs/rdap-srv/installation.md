# Installation

## From a Package Manager

### Homebrew

The RDAP server is NOT available in ICANN-RDAP Homebrew package.

### Arch Linux AUR

Several packages are available in the AUR:

<https://aur.archlinux.org/packages?O=0&SeB=nd&K=icann-rdap&outdated=&SB=p&SO=d&PP=50&submit=Go>

## Pre-Built Binaries

Pre-built binaries are available for most mainstream systems: x86_64 and Arm 64bit for Linux GNU systems, x86_64 and Arm 64bit
macOS, and x86_64 for Windows. You may find the pre-built binaries on the [Releases](https://github.com/icann/icann-rdap/releases)
page.

For non-Debian-based Linux, compiling from crates.io or source (both are easy) is recommended to avoid issues with dynamic linking to OpenSSL.

## Compiling from crates.io

If you have [Rust](https://www.rust-lang.org/) installed on your system, then compiling from source is
very straightforward. If you do not have Rust installed on your system, it is usually very easy to do:
see [Rustup](https://rustup.rs/).

If you are on a Linux system, you will need OpenSSL development files. For Debian and Ubuntu, this is
usually done via `apt install pkg-config libssl-dev`. For other Linux systems, consult your packaging
documentation.

For macOS and Windows, the native TLS libraries are used, and there are no steps needed to install them.

## Compiling from Source

If you have [Rust](https://www.rust-lang.org/) installed on your system, then compiling from source is
very straightforward. If you do not have Rust installed on your system, it is usually very easy to do:
see [Rustup](https://rustup.rs/).

If you are on a Linux system, you will need OpenSSL development files. For Debian and Ubuntu, this is
usually done via `apt install pkg-config libssl-dev`. For other Linux systems, consult your packaging
documentation.

For macOS and Windows, the native TLS libraries are used, and there are no steps needed to install them.

Run the tests: `cargo test`

Then build the software: `cargo build --release`. The executable binaries will be available in the `target/release` directory.

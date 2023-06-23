ICANN RDAP
==========

This repository contains open source code written by the Internet Corporation for Assigned Names and Numbers (ICANN)
for use with the Registry Data Access Protocol (RDAP). RDAP is standard of the [IETF](https://ietf.org/), and extensions
to RDAP are a current work activity of the IETF's [REGEXT working group](https://datatracker.ietf.org/wg/regext/documents/).

***THIS PROJECT IS IN ALPHA STAGE.*** You are welcome to use it and file issues or bug reports, however there are no
guarantees as to timeliness of responses.

Installing the RDAP Client
--------------------------

### Pre-Built Binaries

Pre-built binaries are available for most mainstream systems: x86_64 and Arm 64bit for Linux GNU systems, x86_64 and Arm 64bit
macOS, and x86_64 for Windows. You may find the pre-built binaries on the [Releases](https://github.com/icann/icann-rdap/releases)
page.

For non-Ubuntu Linux, compiling from crates.io or source (both are easy) is recommended to avoid issues with dynamic linking to OpenSSL.

### Compiling from crates.io

If you have [Rust](https://www.rust-lang.org/) installed on your system, then compiling from source is
very straightforward. If you do not have Rust installed on your system, it is usually very easy to do:
see [Rustup](https://rustup.rs/).

If you are on a Linux system, you will need OpenSSL development files. For Debian and Ubuntu, this is
usually done via `apt install pkg-config libssl-dev`. For other Linux systems, consult your packaging
documentation.

For macOS and Windows, the native TLS libraries are used, and there are no steps needed to install them.

To build and install: `cargo install icann-rdap-cli`.

### Compiling from Source

If you have [Rust](https://www.rust-lang.org/) installed on your system, then compiling from source is
very straightforward. If you do not have Rust installed on your system, it is usually very easy to do:
see [Rustup](https://rustup.rs/).

If you are on a Linux system, you will need OpenSSL development files. For Debian and Ubuntu, this is
usually done via `apt install pkg-config libssl-dev`. For other Linux systems, consult your packaging
documentation.

For macOS and Windows, the native TLS libraries are used, and there are no steps needed to install them.

Run the tests: `cargo test`

Then build the software: `cargo build --release`. The 'rdap' executable binary will be available in the `target/release` directory.

Using the RDAP Client
---------------------

The basic usage is `rdap XXX` where XXX is a domain name, IP address, AS number, etc...

For more advanced usage, run `rdap --help` which should yield the extensive help guide.

License
-------

Licensed under either of
* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT) at your option.

Contribution
------------

Unless you explicitly state otherwise, any contribution, as defined in the Apache-2.0 license, 
intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, 
shall be dual licensed pursuant to the Apache License, Version 2.0 or the MIT License referenced 
as above, at ICANN’s option, without any additional terms or conditions.

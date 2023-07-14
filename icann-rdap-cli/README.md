ICANN RDAP CLI
==============

This is a command-line interface (CLI) client for the Registration Data Access Protocol (RDAP) written and sponsored
by the Internet Corporation for Assigned Names and Numbers [(ICANN)](https://www.icann.org). 
RDAP is standard of the [IETF](https://ietf.org/), and extensions
to RDAP are a current work activity of the IETF's [REGEXT working group](https://datatracker.ietf.org/wg/regext/documents/).
More information on ICANN's role in RDAP can be found [here](https://www.icann.org/rdap).

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

Paging Output
-------------

By default, the client will attempt to determine if paging the output (showing information one page at a time)
is appropriate. This is done by attempting to determine if the terminal is interactive or not. If the terminal
is not interactive, paging will be turned off otherwise it will be on.

You can explicitly control this behavior using the `-P` command argument such as `-P none` to specify no paging.
This is also controlled via the `RDAP_PAGING` environmental variable (see configuration below).

Output Format
-------------

By default, the client will attempt to determine the output format of the information. If it determines the shell
is interactive, output will be in `rendered-markdown`. Otherwise the output will be JSON.

You can explicitly control this behavior using the `-O` command argument or the `RDAP_OUTPUT` environment variable
(see below).

Directing Queries To A Specific Server
--------------------------------------

By default, the client will use the RDAP bootstrap files provided by IANA to determine the authoritative server
for the information being requested. These IANA files have the "base URLs" for the RDAP servers.

You can override this behavior by either specifying a base "object tag" from the IANA object tags registry or with
an explicit URL.

An object tag can be specified with the `-b` command argument or the `RDAP_BASE` environment variable (see below).
For example, `-b arin` will direct the client to find the ARIN server in the RDAP object tag registry.

An explicit base URL can be specified using the `-B` command or the `RDAP_BASE_URL` environment variable.

Caching
-------

By default, the client will cache data based on the request URL and "self" links provided in the RDAP results.

This can be turned off with the `-N` command parameter or by setting the `RDAP_NO_CACHE` environment variable to "true".

Logging
-------

The client logs errors, warning, and other information on its processing. This can be controlled with the
`--log-level` command argument or the `RDAP_LOG` environment variable.

Secure Connections
------------------

By default, the client will use secure connections. The following arguments and environment variables can be used
to modify this behavior:

* `-T` or `RDAP_ALLOW_HTTP` : RDAP servers should be using HTTPS. When given or set to true, HTTP will be allowed.
* `-K` or `RDAP_ALLOW_INVALID_HOST_NAMES` : Allows HTTPS connections in which the host name does not match the certificate.
* `-I` or `RDAP_ALLOW_INVALID_CERTIFICATES` : Allows HTTPS connections in which the TLS certificate is invalid.

Configuration
-------------

Configuration of this program may be set using environment variables or 
using an environment variables configuration file in the configuration 
directory of this program. An  example is automatically written to the 
configuration directory. This configuraiton file may be customized by 
uncommenting out the provided environment variable settings.

The location of the configuration file is platform dependent.

On Linux, this file is located at $XDG_CONFIG_HOME/rdap/rdap.env or 
$HOME/.config/rdap/rdap.env.

On macOS, this file is located at 
$HOME/Library/Application Support/rdap/rdap.env.

On Windows, this file is located at
{FOLDERID_RoamingAppData}\rdap\config\rdap.env.

Resetting
---------

Use the `--reset` argument to reset all client state. This will remove the RDAP and IANA caches and
reset the `rdap.env` file (see above) to the default.


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

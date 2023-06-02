ICANN RDAP
==========

This repository contains open source code written by the Internet Corporation for Assigned Names and Numbers (ICANN)
for use with the Registry Data Access Protocol (RDAP). RDAP is standard of the [IETF](https://ietf.org/), and extensions
to RDAP are a current work activity of the IETF's [REGEXT working group](https://datatracker.ietf.org/wg/regext/documents/).

***THIS PROJECT IS IN ALPHA STAGE*** You are welcome to use it and file issues or bug reports, however there are no
guarantees as to timeliness of responses.

Installing the RDAP Client
--------------------------

### Pre-Built Binaries

Pre-built binaries are available for most mainstream systems: x86_64 and Arm 64bit for Linux GNU systems, x86_64 and Arm 64bit
macOS, and x86_64 for Windows. You may find the pre-built binaries on the [Releases](https://github.com/icann/icann-rdap/releases)
page.

For non-Ubuntu Linux, compiling from source (which is easy) is recommended to avoid issues with dynamic linking to OpenSSL.

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

For more advanced usage, run `rdap --help` which should yield the extensive help below:

```
Copyright (C) 2023 Internet Corporation for Assigned Names and Numbers
This software is dual licensed using Apache License 2.0 and MIT License.
Information on this software may be found at https://github.com/icann/icann-rdap
Information on ICANN's RDAP program may be found at https://www.icann.org/rdap


This program queries network registry information from domain name registries and registrars and Internet number registries (i.e. Regional Internet Registries) using the Registry Data Access Protocol (RDAP).

Usage: rdap [OPTIONS] <QUERY_VALUE|--url <URL>|--server-help>

Arguments:
  [QUERY_VALUE]
          Value to be queried in RDAP.

          This is the value to query. For example, a domain name or IP address.

Options:
  -t, --query-type <QUERY_TYPE>
          Type of the query when using a query value.

          Without this option, the query type will be inferred based on the query value. To supress the infererence and explicitly specifty the query type, use this option.

          Possible values:
          - v4:             Ipv4 Address Lookup
          - v6:             Ipv6 Address Lookup
          - v4-cidr:        Ipv4 CIDR Lookup
          - v6-cidr:        Ipv6 CIDR Lookup
          - autnum:         Autonomous System Number Lookup
          - domain:         Domain Lookup
          - entity:         Entity Lookup
          - ns:             Nameserver Lookup
          - entity-name:    Entity Name Search
          - entity-handle:  Entity Handle Search
          - domain-name:    Domain Name Search
          - domain-ns-name: Domain Nameserver Name Search
          - domain-ns-ip:   Domain Nameserver IP Address Search
          - ns-name:        Nameserver Name Search
          - ns-ip:          Nameserver IP Address Search

  -u, --url <URL>
          Perform a query using a specifc URL.

          When used, no query or base URL lookup will be used. Insteead, the given URL will be sent to the RDAP server in the URL directly.

  -S, --server-help
          Get an RDAP server's help information.

          Ask for a server's help information.

  -b, --base <BASE>
          An RDAP base signifier.

          This option gets a base URL from the RDAP bootstrap registry maintained by IANA. For example, using "com" will get the base URL for the .com registry.

          [env: RDAP_BASE=]

  -B, --base-url <BASE_URL>
          An RDAP base URL for a specific RDAP server.

          Use this option to explicitly give an RDAP base URL when issuing queries. If not specified, the base URL will come from the RDAP boostrap process outline in RFC 9224.

          [env: RDAP_BASE_URL=]

  -O, --output-type <OUTPUT_TYPE>
          Output format.

          This option determines the format of the result.

          [env: RDAP_OUTPUT=]
          [default: auto]

          Possible values:
          - ansi-text:
            Results are rendered as Markdown in the terminal using ANSI terminal capabilities
          - markdown:
            Results are rendered as Markdown in plain text
          - json:
            Results are output as JSON
          - pretty-json:
            Results are output as Pretty JSON
          - auto:
            Automatically determine the output type

  -P, --page-output <PAGE_OUTPUT>
          Pager Usage.

          Determines how to handle paging output. When using the embedded pager, all log messages will be sent to the pager as well. Otherwise, log messages are sent to stderr.

          [env: RDAP_PAGING=]
          [default: auto]

          Possible values:
          - embedded: Use the embedded pager
          - none:     Use no pager
          - auto:     Automatically determine pager use

  -L, --log-level <LOG_LEVEL>
          Log level.

          This option determines the level of logging.

          [env: RDAP_LOG=]
          [default: info]

          Possible values:
          - off:   No logging
          - error: Log errors
          - warn:  Log errors and warnings
          - info:  Log informational messages, errors, and warnings
          - debug: Log debug messages, informational messages, errors and warnings
          - trace: Log messages appropriate for software development

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Configuration:

Configuration of this program may also be set using an environment variables configuration file in the configuration directory of this program. An  example is automatically written to the configuration directory. This configuraiton file may be customized by uncommenting out the provided environment variable settings.

The location of the configuration file is platform dependent.

On Linux, this file is located at $XDG_CONFIG_HOME/rdap/rdap.env or
$HOME/.config/rdap/rdap.env.

On macOS, this file is located at
$HOME/Library/Application Support/rdap/rdap.env.

On Windows, this file is located at
{FOLDERID_RoamingAppData}\rdap\config\rdap.env.  
```

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

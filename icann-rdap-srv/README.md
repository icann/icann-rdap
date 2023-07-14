ICANN RDAP Server
=================

This server was created to aid in the development of the ICANN RDAP Command Line Interface client.
It can be used as a library or as a server started within its own process. It currently has in-memory
storage, though its storage layer is architected to accomodate a PostgreSQL backend if that is needed
in the future.

This software is written and sponsored
by the Internet Corporation for Assigned Names and Numbers [(ICANN)](https://www.icann.org). 
RDAP is standard of the [IETF](https://ietf.org/), and extensions
to RDAP are a current work activity of the IETF's [REGEXT working group](https://datatracker.ietf.org/wg/regext/documents/).
More information on ICANN's role in RDAP can be found [here](https://www.icann.org/rdap).

RDAP core support in this server is as follows:

- [X] LDH Domain lookup (`/domain/ldh`)
- [X] Entity lookup (`/entity/handle`)
- [X] Nameserver lookup (`/nameserver/fqdn`)
- [X] Autnum lookup (`/autnum/123`)
- [X] IP address lookup (`/ip/ip_address`)
- [X] CIDR lookup (`/ip/prefix/len`)
- [ ] Domain search
- [ ] Nameserver search
- [ ] Entity search
- [ ] Help (`/help`)

### Compiling from crates.io

If you have [Rust](https://www.rust-lang.org/) installed on your system, then compiling from source is
very straightforward. If you do not have Rust installed on your system, it is usually very easy to do:
see [Rustup](https://rustup.rs/).

If you are on a Linux system, you will need OpenSSL development files. For Debian and Ubuntu, this is
usually done via `apt install pkg-config libssl-dev`. For other Linux systems, consult your packaging
documentation.

For macOS and Windows, the native TLS libraries are used, and there are no steps needed to install them.

To build and install: `cargo install icann-rdap-srv`.

## Compiling from Source

If you have [Rust](https://www.rust-lang.org/) installed on your system, then compiling from source is
very straightforward. If you do not have Rust installed on your system, it is usually very easy to do:
see [Rustup](https://rustup.rs/).

If you are on a Linux system, you will need OpenSSL development files. For Debian and Ubuntu, this is
usually done via `apt install pkg-config libssl-dev`. For other Linux systems, consult your packaging
documentation.

For macOS and Windows, the native TLS libraries are used, and there are no steps needed to install them.

Run the tests: `cargo test`

Then build the software: `cargo build --release`. The 'rdap-srv' executable binary will be available 
in the `target/release` directory.

## Quick Start

Create a `.env` file in the directory where you intend to run the commands, and put the following in that file:

    RDAP_SRV_LOG=debug
    RDAP_SRV_DATA_DIR=/tmp/rdap-srv/data
    RDAP_BASE_URL=http://localhost:3000/rdap

Create directory in /tmp to hold server data files:

    mkdir -p /tmp/rdap-srv/data

Create some data:

    ./target/release/rdap-srv-data entity --handle foo1234 --email joe@example.com --full-name "Joe User"
    ./target/release/rdap-srv-data nameserver --ldh ns1.example.com --registrant foo1234

Start the server:

    ./target/release/rdap-srv

Query the server with the client in another terminal:

    ./target/release/rdap -T -B http://localhost:3000/rdap ns1.example.com

While the server is running, do the following in a separate terminal to add some more data:

    ./target/release/rdap-srv-data domain --ldh example.com --registrant foo1234 --ns ns1.example.com
    ./target/release/rdap-srv-store --update

Query the server for the new data:

    ./target/release/rdap -T -B http://localhost:3000/rdap example.com

For more information on the options available, use the `--help` option.

## Running the Server

The server is configured via environment variables. These variables can be configured in a shell
script or whatever normal means are used to set environment variables. Additionally, they may be
placed in a `.env` in the current directory.

* "RDAP_SRV_LOG" - can be the values 'info', 'error', 'debug', 'warn' or 'trace'. Defualts to 'info'.
* "RDAP_SRV_LISTEN_ADDR" - the IP address of the interface to listen on. Defaults to 127.0.0.1.
* "RDAP_SRV_LISTEN_PORT" - the port to listen on. Defaults to 3000.
* "RDAP_SRV_STORAGE" - either "mem" or "pg", but "pg" doesn't do anything.
* "RDAP_SRV_DB_URL" - database URL when using "pg" storage.
* "RDAP_SRV_DATA_DIR" - the directory containing the files used for storage.

## Memory Storage

The data for the memory storage is specified by the "RDAP_SRV_DATA_DIR" environment variable.
Files in this directory are either valid RDAP JSON files, or template files containing valid
RDAP JSON. Files ending in `.json` are considered to be RDAP JSON, and files ending in `.template`
are considered to be template files.

Template files are also JSON, however they allow the creation of multiple RDAP objects using
one RDAP template. The basic structure is as follows:

```json
{
  "domain":
    {
      "objectClassName":"domain",
      "ldhName":"example"
    },
  "ids":
    [
      {"ldhName":"bar.example"},
      {"ldhName":"foo.example"}
    ]
}
```

The IDs array differs for every object class:

* domain: `{"ldhName": "foo.example"}`. May optionally have a `unicodeName` as well.
* entity: `{"handle"; "XXXX"}`
* nameserver: `{"ldhName": "ns.foo.example"}`. May optionally have a `unicodeName` as well.
* autnum: `{"start_autnum": 1, "end_autnum": 99}`
* ip: either `{"networkId": {"startAddress": "xxx.xxx.xxx.xxx", "endAddress": "xxx.xxx.xxx.xxx"}}` or `{"networkId": "xxx.xxx.xxx.xxx/yyy"}`

Memory storage supports hot reloading. This can be done by "touching" either the file
named "update" or "reload" in the data directory. The "update" file triggers an update
but does not remove any previous data unless that data exists in the data directory files.
The "reload" file triggers a full reload, removing all previous data and replacing it with
the data from the files in the data directory.

Alternatively, you can use the `rdap-srv-store` command to touch the files to trigger
reloads and updates: `rdap-srv-store --update` or `rdap-srv-store --reload`.

## Create Data

RDAP data can often be tricky to create, but the `rdap-srv-data` command makes it easier.
This command does not cover all possible RDAP expressions, but it does cover the common
scenarios and can be used as a starting point for those who require more complex RDAP data.

This command has 5 sub-commands, each with its own specific set of command line arguments.
Use the `--help` option to see the arguments for each sub-command.

    rdap-srv-data entity --help
    rdap-srv-data nameserver --help
    rdap-srv-data domain --help
    rdap-srv-data autnum --help    
    rdap-srv-data network --help

## Use Your Data

As mentioned above, the `rdap-srv-store` command can be used to signal a reload or update
of the server. This command can also be used to copy your own data into the data directory
by specifiing a directory:

    rdap-srv-store --update /my_data/rdap

This command will perform checks on your data while copying them to ensure the data is
RDAP compliant.

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

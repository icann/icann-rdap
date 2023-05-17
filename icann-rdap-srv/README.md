ICANN RDAP Server
=================

This server was created to aid in the development of the ICANN RDAP Command Line Interface client.
It can be used as a library or as a server started within its own process. It currently has in-memory
storage, though its storage layer is architected to accomodate a PostgreSQL backend if that is needed
in the future.

RDAP core support is as follows:

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

Create directory in /tmp:

    mkdir -p /tmp/rdap-srv/state

Copy the files from icann-rdap-srv/resources/test-state-files and place them in the directory
created above.

Start the server:

    RDAP_SRV_LOG=debug RDAP_SRV_STATE_DIR=/tmp/rdap-srv/state target/release/rdap-srv

Query the server with the client:

    target/release/rdap -B http://localhost:3000/rdap xn--fo-5ja.example

Profit!

## Running the Server

The server is configured via environment variables. These variables can be configured in a shell
script or whatever normal means are used to set environment variables. Additionally, they may be
placed in a `.env` in the current directory.

* "RDAP_SRV_LOG" - can be the values 'info', 'error', 'debug', 'warn' or 'trace'. Defualts to 'info'.
* "RDAP_SRV_LISTEN_ADDR" - the IP address of the interface to listen on. Defaults to 127.0.0.1.
* "RDAP_SRV_LISTEN_PORT" - the port to listen on. Defaults to 3000.
* "RDAP_SRV_STORAGE" - either "mem" or "pg", but "pg" doesn't do anything.
* "RDAP_SRV_DB_URL" - database URL when using "pg" storage.
* "RDAP_SRV_STATE_DIR" - the directory containing the files used my memory storage.

## Memory Storage

The state for the memory storage is specified by the "RDAP_SRV_STATE_DIR" environment variable.
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
named "update" or "reload" in the state directory. The "update" file triggers an update
but does not remove any previous data unless that data exists in the state directory files.
The "reload" file triggers a full reload, removing all previous data and replacing it with
the data from the files in the state directory.


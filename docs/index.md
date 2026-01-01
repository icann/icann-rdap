This is the user's manual for the ICANN-RDAP project, an open-source implementation of
the Registry Data Access Protocol (RDAP). ICANN-RDAP includes four sub-projects.

# Command Line Tools

There are two command line tools, `rdap` and `rdap-test`.

The [`rdap`](rdap-cli-tools/cli-client/index.md) command is an easy-to-use, full-featured command line client.

The [`rdap-test`](rdap-cli-tools/test-tool/index.md) is an easy-to-use troubleshooting tool meant to help users identify issues.

# Rust Libraries

The Rust libraries are available from crates.io:

* [Common Library](https://crates.io/crates/icann-rdap-common) contains Rust structs and functions for RDAP. This library has been incorporated into custom, production RDAP servers and other software.
* [Client Library](https://crates.io/crates/icann-rdap-client) has useful functions for querying RDAP servers, including bootstrapping. This library has been incorporated into custom, product clients such as intrusion detection systesm.

# An RDAP Server

This is an easy-to-use RDAP server that has in-memory storage and requires no infrastucture.
This server is ideal for prototyping and testing.

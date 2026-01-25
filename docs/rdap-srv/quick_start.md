# Quick Start

Create a `.env` file in the directory where you intend to run the commands, and put the following in that file:

    RDAP_SRV_LOG=debug
    RDAP_SRV_DATA_DIR=/tmp/rdap-srv/data
    RDAP_BASE_URL=http://localhost:3000/rdap

Create directory in /tmp to hold server data files:

    mkdir -p /tmp/rdap-srv/data

Create the default server help:

    cargo run --bin rdap-srv-data -- srv-help --notice "this is a test server"

_NOTE: `cargo run` makes sure that the code is compiled before running the executable.
You may run `cargo run --release` and access all the executables in the `./target/release` directory._

Create some data:

    cargo run --bin rdap-srv-data -- entity --handle foo1234 --email joe@example.com --full-name "Joe User"
    cargo run --bin rdap-srv-data -- nameserver --ldh ns1.example.com --registrant foo1234

Start the server:

    cargo run --bin rdap-srv

Query the server with the client in another terminal:

    cargo run --bin rdap -- -T -B http://localhost:3000/rdap ns1.example.com

While the server is running, do the following in a separate terminal to add some more data:

    cargo run --bin rdap-srv-data -- domain --ldh example.com --registrant foo1234 --ns ns1.example.com
    cargo run --bin rdap-srv-store -- --update

Query the server for the new data:

    cargo run --bin rdap -- -T -B http://localhost:3000/rdap example.com

For more information on the options available, use the `--help` option.

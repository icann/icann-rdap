# Quick Start

Create a `.env` file in the directory where you intend to run the commands, and put the following in that file:

    RDAP_SRV_LOG=debug
    RDAP_SRV_DATA_DIR=/tmp/rdap-srv/data
    RDAP_BASE_URL=http://localhost:3000/rdap

Create directory in /tmp to hold server data files:

    mkdir -p /tmp/rdap-srv/data

Create the default server help:

    ./target/release/rdap-srv-data srv-help --notice "this is a test server"

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

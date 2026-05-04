# Quick Start

## Using Just

If you are building from source, the project has a useful justfile for use with [just](https://just.systems/man/en/).

Create the data:

    just srv_data_setup

Start the server:

    just srv_start

Lookup data:

    just srv_lookup_nameserver
    just srv_lookup_domain

## Without Just

Create a `.env` file in the directory where you intend to run the commands, and put the following in that file:

    RDAP_SRV_LOG=debug
    RDAP_SRV_DATA_DIR=/tmp/rdap-srv/data
    RDAP_BASE_URL=http://localhost:3000/rdap

Create directory in /tmp to hold server data files:

    mkdir -p /tmp/rdap-srv/data

Create the default server help:

    rdap-srv-data srv-help --notice "this is a test server"

Create some data:

    rdap-srv-data entity --handle foo1234 --email joe@example.com --full-name "Joe User"
    rdap-srv-data nameserver --ldh ns1.example.com --registrant foo1234

Start the server:

    rdap-srv

Query the server with the client in another terminal:

    rdap -T -B http://localhost:3000/rdap ns1.example.com

While the server is running, do the following in a separate terminal to add some more data:

    rdap-srv-data domain --ldh example.com --registrant foo1234 --ns ns1.example.com
    rdap-srv-store --update

Query the server for the new data:

    rdap -T -B http://localhost:3000/rdap example.com

For more information on the options available, use the `--help` option.

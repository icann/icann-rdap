# RDAP Server

This server was created to aid in the development of the ICANN RDAP Command Line Interface client.
It can be used as a library or as a server started within its own process. It currently has in-memory
storage, though its storage layer is architected to accommodate a PostgreSQL backend if that is needed
in the future.

RDAP query support in this server is as follows:

- [X] LDH Domain lookup (`/domain/ldh`)
- [X] IDN U-Label lookup (`/domain/unicode`)
- [X] Entity lookup (`/entity/handle`)
- [X] Nameserver lookup (`/nameserver/fqdn`)
- [X] Autnum lookup (`/autnum/123`)
- [X] IP address lookup (`/ip/ip_address`)
- [X] CIDR lookup (`/ip/prefix/len`)
- [X] Domain search
- [ ] Nameserver search
- [ ] Entity search
- [X] Help (`/help`)

This server explicityl supports the following extensions:

- Cidr0
- Exts
- JSContact
- Redacted
- SimpleRedaction

Other extensions, such as object tagging, can be placed in the `rdapConformance` array of data
used in this server.

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

## Templates

Template files allow for the creation of many RDAP objects by changing just the ID of the object.
The `rdap-srv-data` command can create a template file which can be used as a template. In other words,
one can use the `rdap-srv-data` command to create the template file and then edit the file with
the object ids desired.

The following command creates an entity template using the `--template` option:

    rdap-srv-data --template entity --handle foo --full-name "Bob Smurd"

The IDs array in the templates differ for every object class:

* domain: `{"ldhName": "foo.example"}`. May optionally have a `unicodeName` as well.
* entity: `{"handle"; "XXXX"}`
* nameserver: `{"ldhName": "ns.foo.example"}`. May optionally have a `unicodeName` as well.
* autnum: `{"start_autnum": 1, "end_autnum": 99}`
* ip: either `{"networkId": {"startAddress": "xxx.xxx.xxx.xxx", "endAddress": "xxx.xxx.xxx.xxx"}}` or `{"networkId": "xxx.xxx.xxx.xxx/yyy"}`

## Redirects

Template files can also be used to create redirects (which are modeled by the server as RDAP errors though they are not).
Like other templates, more than one object ID can be used to create a redirect for many objects.

The following command creates a redirect for an IP network:

    rdap-srv-data --redirect http://other.example/ip/11.0.0.0/16 network --cidr 11.0.0.0/16

## Use Your Data

As mentioned above, the `rdap-srv-store` command can be used to signal a reload or update
of the server. This command can also be used to copy your own data into the data directory
by specifiing a directory:

    rdap-srv-store --update /my_data/rdap

This command will perform checks on your data while copying them to ensure the data is
RDAP compliant.


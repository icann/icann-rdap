# Usage

## Exit Codes

Here's a summary of the `rdap` command exit codes, based on [`error.rs`](https://github.com/icann/icann-rdap/blob/main/icann-rdap-cli/src/bin/rdap/error.rs):

| Exit Code | Description | Category |
|---|---|---|
| 0 | Success | Success |
| 10 | `termimad` error | Internal Error |
| 11 | `minus` error | Internal Error |
| 40 | I/O error | I/O Error |
| 42 | Client error (within `RdapClient`) | I/O Error (rdap client) |
| 43 | I/O error (within `RdapClient`) | I/O Error (rdap client) |
| 60 | Response error (within `RdapClient`) | RDAP Server Error |
| 62 | Parsing error (within `RdapClient`) | RDAP Server Error |
| 63 | JSON error (within `RdapClient`) | RDAP Server Error |
| 70 | Bootstrap unavailable (within `RdapClient`) | Bootstrap Error |
| 71 | Bootstrap error (within `RdapClient`) | Bootstrap Error |
| 72 | IANA response error (within `RdapClient`) | Bootstrap Error |
| 100 | JSON error | RDAP Error |
| 101 | IANA error | RDAP Error |
| 102 | Invalid bootstrap file | RDAP Error |
| 103 | Bootstrap not found | RDAP Error |
| 104 | No registrar found | RDAP Error |
| 105 | No registry found | RDAP Error |
| 200 | Unknown output type | User Error |
| 201 | Error on checks | User Error |
| 202 | Invalid query value (within `RdapClient`) | User Error |
| 203 | Ambiguous query type (within `RdapClient`) | User Error |
| 204 | Domain name error (within `RdapClient`) | User Error |
| 250 | Poison error (internal to rdap client) | Internal Error |

## Paging Output

The client has a built-in (embedded) pager. Use of this pager is controlled via the `RDAP_PAGING`
environment variable and the `-P` command argument.

It takes three values:

* "embedded" - use the built-in pager
* "auto" - use the built-in pager if the program is being run from a terminal
* "none" - use no paging

For example, `-P embedded` will default to using the built-in pager.

By default, the client will not use a pager.

When set to "auto", the client determines if a pager is appropriate.
This is done by attempting to determine if the terminal is interactive or not. If the terminal
is not interactive, paging will be turned off otherwise it will be on.

## Output Format

By default, the client will attempt to determine the output format of the information. If it determines the shell
is interactive, output will be in `rendered-markdown`. Otherwise, the output will be JSON.

You can explicitly control this behavior using the `-O` command argument or the `RDAP_OUTPUT` environment variable
(see below).

## Directing Queries To A Specific Server

By default, the client will use the RDAP bootstrap files provided by IANA to determine the authoritative server
for the information being requested. These IANA files have the "base URLs" for the RDAP servers. This is a process
known as "bootstrapping".

You can override this behavior by either specifying a base "object tag" from the IANA object tags registry or with
an explicit URL (e.g. `rdap https://foo.example/ip/10.0.0.0`).

An object tag can be specified with the `-b` command argument or the `RDAP_BASE` environment variable (see below).
For example, `-b arin` will direct the client to find the ARIN server in the RDAP object tag registry.

An explicit base URL can be specified using the `-B` command or the `RDAP_BASE_URL` environment variable.

Two additional arguments are provided to assist with bootstrapping:
* `--tld-lookup` - Specifies where to send queries for TLDs such as ".com". This defaults to IANA.
* `--inr-backup-bootstrap` - Specifies where to send queries for IP addresses and ASNs should normal bootstrapping not yield an answer. This defaults to ARIN.

## Caching

By default, the client will cache data based on the request URL and "self" links provided in the RDAP results.

This can be turned off with the `-N` command parameter or by setting the `RDAP_NO_CACHE` environment variable to "true".

The `--max-cache-age` argument controls the maximum amount of time items are left in the cache.

## Logging

The client logs errors, warning, and other information on its processing. This can be controlled with the
`--log-level` command argument or the `RDAP_LOG` environment variable.

## Secure Connections

By default, the client will use secure connections. The following arguments and environment variables can be used
to modify this behavior:

* `-T` or `RDAP_ALLOW_HTTP` : RDAP servers should be using HTTPS. When given or set to true, HTTP will be allowed.
* `-K` or `RDAP_ALLOW_INVALID_HOST_NAMES` : Allows HTTPS connections in which the host name does not match the certificate.
* `-I` or `RDAP_ALLOW_INVALID_CERTIFICATES` : Allows HTTPS connections in which the TLS certificate is invalid.

## Retries and Timeouts

By default, the client will retry queries if given an HTTP 429 response. The following arguments and environmental variables
can be used to modify this behavior:

* `--max-retries` or `RDAP_MAX_RETRIES`: Number of retries to attempt. Default is 1.
* `--max-retry-secs` or `RDAP_MAX_RETRY_SECS`: Maximum number of seconds to wait before a retry if the `retry-after` value is greater.
* `--def-retry-secs` or `RDAP_DEF_RETRY_SECS`: Default number of seconds to wait before a retry if no `retry-after` value is provided by the server.

The `--timeout-secs` argument determines the total time the client will wait for an answer.

## Conformance Checks

Some specification conformance checks are done by this client. Each conformance check is assigned a number. These numerical values
may be found [here](https://docs.rs/icann-rdap-common/0.0.20/icann_rdap_common/check/enum.Check.html). Additionally, each check is
classified into one of the following classes:

* Informational
* Specification Note
* Standards Warning
* Standards Error
* Cidr0 Extension Error
* ICANN Extension Error

The `--error-on-checks` argument will cause the client to exit with a non-zero exit code (see above) if one of these errors
is detected. This may be useful for certain scripting purposes.

The `--check-type` argument may be used to specify which types of checks will be evaluating when the `--error-on-checks` argument
causes a non-zero exit code.

## Configuration

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

## Resetting

Use the `--reset` argument to reset all client state. This will remove the RDAP and IANA caches and
reset the `rdap.env` file (see above) to the default.


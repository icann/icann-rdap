# Usage

## Exit Codes

| Exit Code | Description                                       | Category          |
| --------- | ------------------------------------------------- | ---------------- |
| 0         | Success                                          | Success          |
| 1         | Tests completed with execution errors.          | Test Failure     |
| 2         | Tests completed, warning checks found.           | Test Warning     |
| 3         | Tests completed, error checks found.             | Test Failure     |
| 10        | Internal error related to terminal display (termimad) | Internal Error   |
| 40        | I/O Error or Test Execution Error                  | I/O Error        |
| 42        | RDAP Client Error - Client                      | RDAP Client Error |
| 43        | RDAP Client Error - I/O                          | RDAP Client Error |
| 60        | RDAP Client Error - Response                     | RDAP Client Error |
| 62        | RDAP Client Error - Parsing Error                 | RDAP Client Error |
| 63        | RDAP Client Error - JSON                         | RDAP Client Error |
| 70        | RDAP Client Error - Bootstrap Unavailable        | RDAP Client Error |
| 71        | RDAP Client Error - Bootstrap Error              | RDAP Client Error |
| 72        | RDAP Client Error - IANA Response                | RDAP Client Error |
| 100       | JSON error                                        | RDAP Error       |
| 101       | IANA error                                        | RDAP Error       |
| 102       | Invalid IANA bootstrap file                      | RDAP Error       |
| 103       | Bootstrap not found                               | RDAP Error       |
| 104       | No registrar found                                | RDAP Error       |
| 105       | No registry found                                 | RDAP Error       |
| 200       | Unknown output type                               | User Error       |
| 202       | RDAP Client Error - Invalid Query Value           | RDAP Client Error |
| 203       | RDAP Client Error - Ambiguous Query Type         | RDAP Client Error |
| 204       | RDAP Client Error - Domain Name Error             | RDAP Client Error |
| 250       | RDAP Client Error - Internal Poison Error        | RDAP Client Error |

## Test Controls

The following arguments may be used to control the behavior of tests:

* `--skip-v4` - Skip v4 tests.
* `--skip-v6` - Skip v6 tests.
* `--skip-origin` - Skip tests using the HTTP "origin" header.
* `--origin-value` - Set the "origin" header value.
* `--one-addr` - Only test one address.

## Link Target Controls

The following arguments may be used to control link following behavior during tests:

* `--link-target` - Specifies a link target. More than one link target may be given.
* `--only-show-target` - When specified, only link target results are shown.
* `--min-link-depth` - Sets the minimum number of times to query for a link target.
* `--max-link-depth` - Sets the maximum number of times to query for a link target.

### Network Hierarchy Link Targets

* `--up` - Set link target parameters for a parent network.
* `--down` - Set link target parameters for child networks.
* `--top` - Set link target parameters for least specific network.
* `--bottom` - Set link target parameters for most specific network.

### Domain-Specific Link Targets

* `--registry` - Set link target parameters for a domain registry.
* `--registrar` - Set link target parameters for a domain registrar.

## Link Target Examples

```bash
# Test with registry link following
rdap-test --registry https://rdap.nic.com/domain/example.com

# Test with registrar link following
rdap-test --registrar https://rdap.nic.com/domain/example.com

# Test with network hierarchy following
rdap-test --up https://rdap.arin.net/registry/ip/192.0.2.1
rdap-test --down https://rdap.arin.net/registry/ip/192.0.2.1
rdap-test --top https://rdap.arin.net/registry/ip/192.0.2.1
rdap-test --bottom https://rdap.arin.net/registry/ip/192.0.2.1

# Test with custom link depth
rdap-test --link-target entity --max-link-depth 3 https://rdap.nic.com/domain/example.com

# Test with multiple link targets
rdap-test --link-target entity --link-target nameserver https://rdap.nic.com/domain/example.com

# Only show link target results
rdap-test --only-show-target --link-target entity https://rdap.nic.com/domain/example.com
```

### Domain Registry and Registrar Testing

When testing domain-related RDAP servers, you can use link target controls:

```bash
# Test domain registry link following
rdap-test --registry https://rdap.nic.com/domain/example.com

# Test domain registrar link following  
rdap-test --registrar https://rdap.nic.com/domain/example.com
```

These flags will test the RDAP server's ability to handle link following requests for domain registry and registrar relationships.

By default, this command does not follow HTTP redirects unless the `--follow-redirects` argument is given.

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

The `--check-type` argument may be used to specify which types of checks will be used in reporting errors.

## Checking RDAP Extensions

This command can require the explicit presence of RDAP extensions when performing checks. This is controlled with
the following arguments:

*  `-e` or `--expect-extensions` - specifies the extension identifier
*  `-g` or `--expect-group` - specifies an extension group. Group values are "gtld", "nro" and "nro-asn".

By default, this command will issue a Standards Error check if an extension is found that is not registered with the IANA.
This check may be suppressed using the `-E` or `--allow-unregistered-extensions` argument.

## Paging Output

Unlike the `rdap` command, the `rdap-test` command does not page output.

## Output Format

By default, this command will attempt to determine the output format of the information. If it determines the shell
is interactive, output will be in `rendered-markdown`. Otherwise, the output will be JSON.

You can explicitly control this behavior using the `-O` command argument or the `RDAP_TEST_OUTPUT` environment variable
(see below).

Use the `--json` shortcut parameter to set the output type to pretty-compact-json.

## Directing Queries To A Specific Server

The `rdap-test` command will use the RDAP bootstrap files provided by IANA to determine the authoritative server
for the information being requested. These IANA files have the "base URLs" for the RDAP servers.

Unlike the `rdap` command, no explicit base URL can be specified.

## Caching

The `rdap-test` command will cache IANA bootstrap files, but does no caching of RDAP responses.

## Logging

The `rdap-test` command logs errors, warning, and other information on its processing. This can be controlled with the
`--log-level` command argument or the `RDAP_TEST_LOG` environment variable.

## Secure Connections

By default, the `rdap-test` command will use secure connections. The following arguments and environment variables can be used
to modify this behavior:

* `-T` or `RDAP_TEST_ALLOW_HTTP` : RDAP servers should be using HTTPS. When given or set to true, HTTP will be allowed.
* `-K` or `RDAP_TEST_ALLOW_INVALID_HOST_NAMES` : Allows HTTPS connections in which the host name does not match the certificate.
* `-I` or `RDAP_TEST_ALLOW_INVALID_CERTIFICATES` : Allows HTTPS connections in which the TLS certificate is invalid.

## Retries and Timeouts

By default, the client will retry queries if given an HTTP 429 response. The following arguments and environmental variables
can be used to modify this behavior:

* `--max-retries` or `RDAP_MAX_RETRIES`: Number of retries to attempt. Default is 1.
* `--max-retry-secs` or `RDAP_MAX_RETRY_SECS`: Maximum number of seconds to wait before a retry if the `retry-after` value is greater.
* `--def-retry-secs` or `RDAP_DEF_RETRY_SECS`: Default number of seconds to wait before a retry if no `retry-after` value is provided by the server.

The `--timeout-secs` argument determines the total time the client will wait for an answer.

## DNS Resolver

By default, this command will use the public DNS resolver at 8.8.8.8 port 53 to determine the set of RDAP endpoints to test.
To change this value, use the `--dns-resolver` argument.

## Configuration

The `rdap-test` command uses the same configuration techniques and file as the [`rdap`](../cli-client/usage.md#configuration) command. However,
environment variables are `RDAP_TEST_XXXX` instead of `RDAP_XXXX` (where XXXX is a specific variable).

## Resetting

Use the [`rdap`](../cli-client/usage.md#resetting) command `--reset` argument to reset all configuration and state. This will remove the IANA caches and
reset the `rdap.env` file (see above) to the default.

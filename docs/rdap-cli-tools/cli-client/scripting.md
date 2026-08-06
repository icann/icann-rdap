# Scripting with the RDAP CLI

The RDAP CLI provides several output formats designed for consumption by scripts, along with parameters that simplify processing the output.

## Output Formats for Scripts

The CLI provides multiple output formats via the `-O` (or `--output-type`) argument:

| Output Type | Shortcut | Description |
|---|---|---|
| `json` | | Standard RDAP JSON output |
| `pretty-json` | | Pretty-printed JSON output |
| `pretty-compact-json` | `--json` | Compact but readable JSON (best for scripts) |
| `json-extra` | | RDAP JSON with additional processing information |
| `nd-json` | | Newline Delimited JSON for append-only purposes |
| `json-seq` | | JSON Text Sequences (RFC7464) for append-only purposes |
| `csv` | | For filtering and output for spreadsheets |
| `url` | | Just the RDAP server URL (useful for bootstrapping) |
| `rpsl` | `--rpsl` | Routing Policy Specification Language |

## Quick JSON Output

The simplest way to get script-friendly output:

```bash
rdap --json example.com
```

This is equivalent to `-O pretty-compact-json`.

Content is sent to stdout while [log messages](usage.md#logging) are sent to stderr, so log messages will not interfere with piping or redirecting.

## Some Scripting Examples

### Extract specific fields with jq

```bash
rdap --json example.com | jq -r '.entities[0].vcardArray[1][] | select(.[0] == "fn").[3]'
```

### Target the registrar
```bash
rdap --registrar --json icann.org | jq -r '.entities[0].vcardArray[1][] | select(.[0] == "fn").[3]'
```

### Use the built-in filters

The built-in [filters](filters.md) make many simple tasks easier.

```bash
rdap --registrar --filter ldh-name,registrant-full-name,status icann.org
```

## JSContact Output

The `--to-jscontact` parameter converts vCard/jCard contact information in RDAP responses to [JSContact](https://jscontact.info/) format. This simplifies parsing contact information in scripts since JSContact is a more modern and easier-to-parse JSON format.

```bash
rdap --json --to-jscontact example.com
```

When used with JSON output, entity contact information will be in JSContact format instead of jCard/vCard, making it easier to extract specific fields:

```bash
# Get entity name from JSContact output
rdap --json --to-jscontact example.com | jq -r '.entities[0].contact.name.fullName'

# Get entity email
rdap --json --to-jscontact example.com | jq -r '.entities[0].contact.email[0].address'
```

## Environment Variables for Scripts

Several environment variables can simplify scripting:

| Variable | Description |
|---|---|
| `RDAP_OUTPUT` | Set default output format |
| `RDAP_NO_CACHE` | Disable caching (`true` or `false`) |
| `RDAP_LOG` | Set log level (off, error, warn, info, debug, trace) |
| `RDAP_BASE_URL` | Set explicit base URL |
| `RDAP_REDACTION_FLAGS` | Set redaction flags |

Example:

```bash
export RDAP_OUTPUT=json
export RDAP_NO_CACHE=true
rdap example.com
```

## Exit Codes

The CLI returns specific exit codes that scripts can use for error handling:

| Exit Code | Description |
|---|---|
| 0 | Success |
| 40 | I/O error |
| 42 | Client error |
| 60 | Response error (non-200 OK) |
| 62 | Parsing error |
| 100-106 | RDAP-specific errors |
| 200+ | User error (invalid query, etc.) |

See the [Usage](./usage.md#exit-codes) documentation for the complete exit code table.


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
| `url` | | Just the RDAP server URL (useful for bootstrapping) |
| `status-text` | | Only the object status, one per line |
| `status-json` | | Object status as JSON |
| `event-text` | | Only the events, one per line |
| `event-json` | | Events as JSON |
| `rpsl` | `--rpsl` | Routing Policy Specification Language |

## Quick JSON Output

The simplest way to get script-friendly output:

```bash
rdap --json example.com
```

This is equivalent to `-O pretty-compact-json`.

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

## Common Scripting Examples

### Extract specific fields with jq

```bash
rdap --json example.com | jq -r '.entities[0].vcardArray[1][] | select(.[0] == "fn").[3]'
```

### Get the RDAP server URL for bootstrapping

```bash
rdap -O url example.com
```

### Check if a domain exists (exit code 0 = found)

```bash
rdap --json example.com > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Domain exists"
fi
```

### Get all nameservers

```bash
rdap --json example.com | jq -r '.nameservers[].ldhName'
```

### Get all entity names

```bash
rdap --json example.com | jq -r '.entities[].fn'
```

### Get registration date

```bash
rdap --json example.com | jq -r '.events[] | select(.eventAction == "registration").eventDate'
```

### Get domain status

```bash
rdap --json example.com | jq -r '.status[]'
```

### Query an IP address and get network info

```bash
rdap --json 192.0.2.0 | jq '.network'
```

### Query an AS number

```bash
rdap --json AS15169 | jq '.autnums[0]'
```

### Get only status information

```bash
rdap -O status-json example.com
```

### Get only events

```bash
rdap -O event-json example.com
```

## Redaction Flags

When querying RDAP data, some information may be redacted. The CLI provides flags to control how redactions are handled:

```bash
rdap --redaction-flag show-rfc9537 --json example.com
```

Available flags:
- `highlight-simple-redactions` - Highlights simple redactions in output
- `show-rfc9537` - Shows RFC 9537 redaction directives
- `do-not-simplify-rfc9537` - Preserves RFC 9537 redaction format
- `do-rfc9537-redactions` - Processes RFC 9537 redactions

Multiple flags can be combined with commas:

```bash
rdap --redaction-flag highlight-simple-redactions,show-rfc9537 --json example.com
```

Or via environment variable:

```bash
RDAP_REDACTION_FLAGS=highlight-simple-redactions,show-rfc9537 rdap --json example.com
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

See the [Usage](./usage.md) documentation for the complete exit code table.

## Piping to Other Tools

The output is designed to work with standard Unix tools:

### Using grep

```bash
rdap --json example.com | jq '.entities' | grep -i "registrar"
```

### Using awk

```bash
rdap --json example.com | jq -r '.events[] | "\(.eventAction) \(.eventDate)"' | awk '{print $2}'
```

### Using while read

```bash
for domain in example.com example.org; do
    rdap --json "$domain" | jq -r '.handle // "N/A"'
done
```

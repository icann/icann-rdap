# Output Format Control

This page provides detailed information about controlling the output format of RDAP responses using the RDAP command line client.

## Overview

The RDAP client supports multiple output formats to accommodate different use cases, from human-readable terminal output to machine-readable formats for automation. You can control the output format using command-line options or environment variables.

| Type                | Works with Filters | Shortcut |
| -----------------   | ------------------ | -------- |
| Rendered Markdown   | No                 |          |
| Plain Markdown      | No                 |          |
| RPSL                | No                 | `--rpsl` |
| gTLD Whois          | No                 |          |
| Compact JSON        | Yes                |          |
| Pretty JSON         | Yes                |          |
| Pretty Compact JSON | Yes                | `--json` |
| JSON Extra          | Yes                |          |
| ND-JSON             | Yes                |          |
| JSON Sequences      | Yes                |          |
| GeoFeed             | No                 |          |
| CSV                 | Yes                |          |

## Output Format Options

### Auto Detection (Default)

By default, the client automatically determines the best output format:

```bash
# normal user output
rdap example.com

# json output for non-interactive (e.g., scripting)
rdap example.com | jq .
```

- **Interactive terminals**: Rendered markdown with ANSI colors
- **Non-interactive**: Compact JSON
- **Configuration**: Can be overridden with `-O` command line flag.

### Markdown Formats

#### Rendered Markdown
```bash
rdap -O rendered-markdown example.com
# or default for interactive terminals
rdap example.com
```

Output is rendered with ANSI terminal capabilities including:
- Color coding
- Highlighting
- Terminal-specific formatting

#### Plain Text Markdown
```bash
rdap -O markdown example.com
```

Output is in plain markdown format suitable for:
- Documentation systems
- Plain text files
- Non-ANSI terminals

### JSON Formats

#### Compact JSON
```bash
rdap -O json example.com
```

Standard JSON output with minimal whitespace, ideal for:
- Script processing
- API responses
- Data storage

#### Pretty JSON
```bash
rdap -O pretty-json example.com
```

Human-readable JSON with indentation and line breaks, ideal for:
- Debugging
- Development
- Manual inspection

#### Pretty Compact JSON (Recommended)
```bash
rdap -O pretty-compact-json example.com
# or shortcut:
rdap --json example.com
```

JSON output that is both compact and readable, providing:
- Intelligent line breaks
- Strategic indentation
- Optimal balance for human and machine reading

#### JSON with Extra Information
```bash
rdap -O json-extra example.com
```

Includes additional metadata such as:
- HTTP request/response data
- Processing timestamps
- Internal state information
- Request/response correlation data

#### Newline Delimited JSON
Otherwise called ND-JSON, JSONL, or JSON Lines.
```bash
rdap -O nd-json example.com
```

For append-only file writing.

#### JSON Text Sequences
Similar to ND-JSON. See RFC 7464.
```bash
rdap -O json-seq example.com
```

For append-only file writing.

### Specialized Formats

#### Routing Policy Specification Language (RPSL)
```bash
rdap -O rpsl 192.0.2.1
# or shortcut:
rdap --rpsl 192.0.2.1
```

RPSL format for network routing information, ideal for:
- Network management systems
- Routing policy databases
- ISP automation

#### GeoFeed
See RFC 9877.
```bash
rdap -O geofeed 192.0.2.1
```

#### CSV
See RFC 9877.
```bash
rdap -O csv --filter registrant-email icann.org
```

#### gTLD WHOIS Format
```bash
rdap -O gtld-whois example.com
```

Traditional WHOIS-style format for gTLD domains, featuring:
- WHOIS-compatible output
- Line-based formatting
- Legacy system compatibility

*Note: Only available for domain queries.*

## Environment Variable Configuration

Set default output format using `RDAP_OUTPUT` environment variable:

```bash
# Set default to pretty compact JSON
export RDAP_OUTPUT=pretty-compact-json

# Set default to rendered markdown
export RDAP_OUTPUT=rendered-markdown

# Set default to RPSL
export RDAP_OUTPUT=rpsl
```


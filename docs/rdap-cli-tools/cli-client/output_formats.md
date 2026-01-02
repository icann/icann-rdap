# Output Format Control

This page provides detailed information about controlling the output format of RDAP responses using the RDAP command line client.

## Overview

The RDAP client supports multiple output formats to accommodate different use cases, from human-readable terminal output to machine-readable formats for automation. You can control the output format using command-line options or environment variables.

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

### Specialized Formats

#### gTLD WHOIS Format
```bash
rdap -O gtld-whois example.com
```

Traditional WHOIS-style format for gTLD domains, featuring:
- WHOIS-compatible output
- Line-based formatting
- Legacy system compatibility

*Note: Only available for domain queries.*

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

### Status and Event Formats

#### Status Text
```bash
rdap -O status-text example.com
```

Outputs only the primary object's status, one status per line.

#### Status JSON
```bash
rdap -O status-json example.com
```

Outputs only the primary object's status in JSON format.

#### Event Text
```bash
rdap -O event-text example.com
```

Outputs only the primary object's events (creation, expiration, etc.), one per line.

#### Event JSON
```bash
rdap -O event-json example.com
```

Outputs only the primary object's events in JSON format.

### URL Output
```bash
rdap -O url example.com
```

Outputs only the RDAP server URL for the query, useful for:
- Debugging
- URL extraction
- Server verification

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


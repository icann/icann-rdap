# Domain Queries

This page provides detailed information about querying domain names using the RDAP command line client.

## Basic Domain Queries

### Simple Domain Lookup

The most common use case is querying information about a specific domain name:

```bash
rdap example.com
```

This command will:
- Automatically detect that "example.com" is a domain name
- Use the RDAP bootstrap process to find the authoritative server
- Display the domain information

### Explicit Domain Type Specification

You can explicitly specify the query type to avoid automatic inference:

```bash
rdap -t domain example.com
```

This is useful when the query value might be ambiguous or when you want to ensure domain-specific processing.

### A-Label Domain Queries

For internationalized domain names (IDNs) in their ASCII (A-label) form:

```bash
rdap -t alabel xn--d1acj3b
```

## Server Targeting Options

### Link Target Parameters for Registry and Registrar

The `--registry` and `--registrar` flags are used for controlling link following behavior when querying domains:

#### Registry Link Following
```bash
# Follow links to domain registry information
rdap --registry icann.org
```

This sets link target parameters to query the registry associated with the domain, with:
- Only showing the target information
- Minimum link depth: 1
- Maximum link depth: 1

#### Registrar Link Following
```bash
# Follow links to domain registrar information
rdap --registrar icann.org
```

This sets link target parameters to query the registrar associated with the domain, with:
- Link targets: "related"
- Only showing the target information
- Minimum link depth: 2
- Maximum link depth: 3

#### Combined with Depth Control
```bash
# Follow registrar links with custom depth
rdap --registrar --max-link-depth 5 example.com

# Follow registry links with depth control
rdap --registry --min-link-depth 1 --max-link-depth 2 example.com
```

### Bootstrap Registry Selection

Direct queries to a specific registry using its bootstrap identifier with `-b` or `--base` flag:

```bash
# Query the .com registry
rdap -b com example.com

# Query the ARIN registry
rdap -b arin 1.2.0.192.in-addr.arpa

# Query the RIPE NCC registry
rdap -b ripe 1.2.0.192.in-addr.arpa
```

### Explicit Server URL

Direct queries to a specific RDAP server with `-B` or `--base-url` flag:

```bash
rdap -B https://rdap.iana.org com
rdap -B https://rdap.example.net example.com
```

This bypasses the bootstrap process and sends the query directly to the specified server.


### TLD Queries

Query information about a top-level domain itself:

```bash
rdap .com
rdap .org
rdap .net
```

This will query IANA's RDAP server for information about the TLD.


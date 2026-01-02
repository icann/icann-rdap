# IP Address Queries

This page provides detailed information about querying IP addresses and networks using the RDAP command line client.

## Basic IP Address Queries

### IPv4 Address Lookup

Query information about a specific IPv4 address:

```bash
rdap 192.0.2.1
```

This command will:
- Automatically detect that "192.0.2.1" is an IPv4 address
- Use the RDAP bootstrap process to find the appropriate Regional Internet Registry (RIR)
- Display network and entity information

### IPv6 Address Lookup

Query information about a specific IPv6 address:

```bash
rdap 2001:db8::1
```

### Explicit IP Type Specification

You can explicitly specify the query type to avoid automatic inference:

```bash
# IPv4 address
rdap -t v4 192.0.2.1

# IPv6 address  
rdap -t v6 2001:db8::1
```

## CIDR Block Queries

### IPv4 CIDR Queries

Query information about IPv4 networks using CIDR notation:

```bash
rdap -t v4cidr 192.0.2.0/24
```

This will return information about the entire /24 network block.

### IPv6 CIDR Queries

Query information about IPv6 networks using CIDR notation:

```bash
rdap -t v6cidr 2001:db8::/32
```

### Short CIDR Notation

For common network sizes, you can use abbreviated notation:

```bash
# Equivalent to 192.0.2.0/24
rdap 192.0.2/24

# Equivalent to 2001:db8::/32
rdap 2001:db8/32
```

## Reverse DNS Queries

### IP Address Reverse DNS

Query reverse DNS information for an IP address:

```bash
rdap -t rdns 192.0.2.1
```

This performs a reverse DNS lookup and returns the corresponding RDAP information.

### Reverse DNS for CIDR Blocks

You can also perform reverse DNS queries on network blocks:

```bash
rdap -t rdns 192.0.2.0/24
```

## Server Targeting Options

### Bootstrap Registry Selection

Direct queries to a specific RIR using its bootstrap identifier:

```bash
# Query ARIN specifically
rdap -b arin 192.0.2.1

# Query RIPE NCC
rdap -b ripe 192.0.43.8

# Query APNIC
rdap -b apnic 203.0.113.1
```

Common RIR identifiers:
- `arin` - American Registry for Internet Numbers
- `ripe` - RIPE Network Coordination Centre  
- `apnic` - Asia-Pacific Network Information Centre
- `lacnic` - Latin America and Caribbean Network Information Centre
- `afrinic` - African Network Information Centre

### Explicit Server URL

Direct queries to a specific RDAP server:

```bash
rdap -B https://rdap.arin.net/registry/ip/192.0.2.1
```

This bypasses the bootstrap process and sends the query directly to the specified server.

### INR Backup Bootstrap

When normal bootstrapping fails for IP addresses, you can specify a backup:

```bash
# Use ARIN as backup (default)
rdap --inr-backup-bootstrap arin 192.0.2.1
```

## Link Following

Follow related objects (like parent networks) automatically:

### Network Hierarchy Link Following
```bash
# Follow to parent networks (less specific)
rdap --up 192.0.2.1

# Follow to child networks (more specific)
rdap --down 192.0.2.1

# Follow to least specific network
rdap --top 192.0.2.1

# Follow to most specific network
rdap --bottom 192.0.2.1
```


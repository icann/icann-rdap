# Autonomous System Number (AS Number) Queries

This page provides detailed information about querying Autonomous System Numbers (ASNs) using the RDAP command line client.

## Basic AS Number Queries

### Simple AS Number Lookup

Query information about a specific Autonomous System Number:

```bash
rdap as64496
```

This command will:
- Automatically detect that "as64496" is an AS number
- Use the RDAP bootstrap process to find the appropriate Regional Internet Registry (RIR)
- Display AS information

### Explicit AS Number Type Specification

You can explicitly specify the query type to avoid automatic inference:

```bash
rdap -t autnum as64496
```

## AS Number Formats

### Standard AS Number Format

The most common format uses the "as" prefix followed by the number:

```bash
rdap as64496
```

### Numeric-Only Format

You can also query using just the numeric portion:

```bash
rdap 64496
```

## Server Targeting Options

### Bootstrap Registry Selection

Direct queries to a specific RIR using its bootstrap identifier:

```bash
# Query ARIN specifically
rdap -b arin as64496

# Query RIPE NCC
rdap -b ripe as65536

# Query APNIC
rdap -b apnic as13335
```

Common RIR identifiers for AS numbers:
- `arin` - American Registry for Internet Numbers
- `ripe` - RIPE Network Coordination Centre  
- `apnic` - Asia-Pacific Network Information Centre
- `lacnic` - Latin America and Caribbean Network Information Centre
- `afrinic` - African Network Information Centre

### Explicit Server URL

Direct queries to a specific RDAP server:

```bash
rdap -B https://rdap.arin.net/registry/autnum/64496
```

This bypasses the bootstrap process and sends the query directly to the specified server.

### INR Backup Bootstrap

When normal bootstrapping fails for AS numbers, you can specify a backup:

```bash
# Use ARIN as backup (default)
rdap --inr-backup-bootstrap arin as64496
```


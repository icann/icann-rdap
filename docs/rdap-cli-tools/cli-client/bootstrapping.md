# Bootstrapping

Bootstrapping is the process by which the RDAP client determines which RDAP server to query for a given domain, IP address, ASN, or entity. By default, the client uses bootstrap files provided by IANA to find the authoritative RDAP server.

## Default Behavior

When you query the RDAP client (e.g., `rdap example.com`), the client:

1. Determines the type of query (domain, IP, ASN, entity)
2. Looks up the appropriate bootstrap registry from IANA
3. Finds the matching server URL for your query target
4. Queries that server

## Overriding Bootstrapping

There are several ways to override the default bootstrapping behavior:

### 1. Command Line Options

| Option | Environment Variable | Description |
|--------|---------------------|-------------|
| `-b` | `RDAP_BASE` | Specify an object tag from the IANA object tags registry |
| `-B` | `RDAP_BASE_URL` | Specify an explicit base URL (converted to `https://` if only hostname given) |
| `--tld-lookup` | - | Specify where to send queries for TLDs (defaults to IANA) |
| `--inr-backup-bootstrap` | - | Backup server for IP/ASN queries when normal bootstrapping fails (defaults to ARIN) |

Examples:
```bash
rdap -b arin example.com       # Use ARIN's object tag
rdap -B rdap.example.com example.com  # Use specific server
rdap --tld-lookup custom.example .com # Use custom TLD server
```

### 2. Environment Variables

| Variable | Description |
|----------|-------------|
| `RDAP_BASE` | Object tag to use for bootstrapping |
| `RDAP_BASE_URL` | Base URL to use directly |
| `RDAP_TLD_LOOKUP` | Server for TLD queries |
| `RDAP_INR_BACKUP_BOOTSTRAP` | Backup server for IP/ASN |

### 3. Bootstrap Override Files (Configuration)

You can provide your own bootstrap registry files that take precedence over IANA's cached data. Place JSON files in the RDAP configuration directory:

**Configuration directory locations:**
- Linux: `$XDG_CONFIG_HOME/rdap/` or `$HOME/.config/rdap/`
- macOS: `$HOME/Library/Application Support/rdap/`
- Windows: `{FOLDERID_RoamingAppData}\rdap\config\`

**Override file names:**

| Registry Type | File Name |
|---------------|------------|
| DNS/Domains | `dns.json` |
| ASN/Autnums | `asn.json` |
| IPv4 | `ipv4.json` |
| IPv6 | `ipv6.json` |
| Object Tags | `object-tags.json` |

**Format:**

The override files use the same format as IANA bootstrap registries. Example for DNS:

```json
{
    "version": "1.0",
    "publication": "2024-01-07T10:11:12Z",
    "description": "Custom DNS bootstrap",
    "services": [
        [
            ["com", "net"],
            [
                "https://custom.example.com/rdap/"
            ]
        ],
        [
            ["org"],
            [
                "https://registry.example.org/"
            ]
        ]
    ]
}
```

**Priority:** Config override files take precedence over cached IANA bootstrap data. If a query doesn't match anything in the config override, the client falls back to the cached IANA data.


## Bootstrap Cache

The client caches bootstrap data retrieved from IANA. The cache location:

- Linux: `$XDG_CACHE_HOME/rdap/` or `$HOME/.cache/rdap/`
- macOS: `$HOME/Library/Caches/rdap/`
- Windows: `{FOLDERID_LocalAppData}\rdap\cache\`

Use `--reset` to clear the cache and configuration.

# Following Link Targets

The RDAP client supports following links in RDAP responses to fetch additional related information.
This allows you to traverse relationships between entities, domains, networks, and other RDAP objects.

## Link Target Arguments

The client provides several arguments for controlling link following behavior:

| Argument | Description |
|---|---|
| `--link-target` | Specifies a link target (e.g., "related", "rdap-up"). Use `_none` to disable link following. |
| `--only-show-target` | When specified, only shows the link target response instead of all responses. |
| `--min-link-depth` | The minimum number of times to query for a link target. |
| `--max-link-depth` | The maximum number of times to query for a link target. |

## Preset Arguments

The client provides preset arguments that set multiple parameters at once for common use cases:

| Argument | Description |
|---|---|
| `--registry` | Set link target parameters for a domain registry. |
| `--registrar` | Set link target parameters for a domain registrar. |
| `--up` | Set link target parameters for a parent network. |
| `--down` | Set link target parameters for child networks. |
| `--top` | Set link target parameters for the least specific network. |
| `--bottom` | Set link target parameters for the most specific networks. |

## Default Behavior

Default link target behavior varies by query type:

| Query Type | Default Link Target | Default Min Depth | Default Max Depth |
|---|---|---|---|
| IP Address (IPv4/IPv6) | None | 1 | 1 |
| CIDR (IPv4/IPv6) | None | 1 | 1 |
| AS Number | None | 1 | 1 |
| Domain | "related" | 1 | 3 |
| Other | None | 1 | 1 |

## Examples

### Query the registry

```bash
rdap --registry example.com
```

This queries the domain and at the registry.

### Query the registrar

```bash
rdap --registrar example.com
```

This queries the domain and at the registrar.

### Query parent network

```bash
rdap --up 192.0.2.0
```

Follow the IP network referenced by "rdap-up" and "rdap-active" links.

### Query child networks

```bash
rdap --down 192.0.2.0/24
```

Follow the IP network referenced by "rdap-down" and "rdap-active" links.

### Custom link target with specific depth

```bash
rdap --link-target related --min-link-depth 2 --max-link-depth 5 example.com
```

Follow the object referenced by "related" links with a minimum depth of 2 and maximum depth of 5.

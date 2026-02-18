# Specifying a Link Target

The RDAP client supports specifying a target by following RDAP links.

## Link Target Arguments

The client provides several arguments for controlling link following behavior:

| Argument | Description |
|---|---|
| `--link-target` | Specifies a link target (e.g., "related", "rdap-up"). Use `_none` to disable link following. |
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

## Examples

### Test the registry response

```bash
rdap --registry example.com
```

### Test registrar response

```bash
rdap --registrar example.com
```

### Test parent network

```bash
rdap --up 192.0.2.0
```

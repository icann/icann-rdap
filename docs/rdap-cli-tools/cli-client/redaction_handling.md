# Redaction Handling

This client supports the "redacted" extension documented in RFC 9537. However, RFC 9537 redactions are extremely complicated
and often confusing to users. This client, when possible, will convert RFC 9537 redactions to "simpleRedactions".

## Redaction Flags

The client supports several redaction flags that can be combined to control redaction behavior:

### Highlight Simple Redactions

```bash
rdap --redaction-flag highlight-simple-redactions example.com
```

This flag highlights simple redactions in the output, making them more visible when displayed in terminals.

### Show RFC 9537 Redaction Directives

```bash
rdap --redaction-flag show-rfc9537 example.com
```

This flag displays detailed RFC 9537 redaction directive information, including reasons and authorities.

### Do Not Simplify RFC 9537 Redactions

```bash
rdap --redaction-flag do-not-simplify-rfc9537 example.com
```

This flag prevents RFC 9537 redactions from being converted to simple redactions, preserving the detailed directive information.

### Process RFC 9537 Redactions

```bash
rdap --redaction-flag do-rfc9537-redactions example.com
```

This flag enables full processing of RFC 9537 redactions, applying all specified redaction rules and directives.

## Redaction Flag Combinations

You can combine multiple redaction flags using commas:

```bash
# Highlight simple redactions and show RFC 9537 directives
rdap --redaction-flag highlight-simple-redactions,show-rfc9537 example.com

# Process RFC 9537 redactions without simplifying them
rdap --redaction-flag do-rfc9537-redactions,do-not-simplify-rfc9537 example.com
```

## Environment Variable Configuration

Set default redaction flags using the `RDAP_REDACTION_FLAGS` environment variable:

```bash
export RDAP_REDACTION_FLAGS=highlight-simple-redactions,show-rfc9537
```


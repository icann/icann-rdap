# RIR Searches

This client support the RIR searches specified in [RFC 9910](https://www.rfc-editor.org/rfc/rfc9910).

## Relationship Searches

The relationship queries (rdap-up, rdap-down, rdap-top, rdap-bottom) are supported for IP networks,
autonomous system numbers (autnums) and domains in the reverse DNS (in-addr.arpa and ip6.arpa).

They may be explicitly specified using the `-t` command line parameter:

```bash
# Explicit query type for IP address 'rdap-up'
# Use '--help' to see the full list.
rdap -t v4-up 192.0.2.1
```

Query values may also be prepended with "up:", "down:", "top:", and "bottom:" to infer the type of they query value. In most cases,
this is easier to use:

```bash
rdap up:192.0.2.1
```

## Handle and Name Searches

Searching by name and handle for networks and autnums requires explicitly specifying the type with `-t`. These are:

* `net-handle`
* `net-name`
* `autnum-handle`
* `autnum-name`

```bash
rdap -t net-handle FOONET-1
```

## Link Targets

Some RIRs place relationship links (i.e., referrals) in RDAP.
This allows the client to follow links from one RIR to another.

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

See [Link Targets](link_targets.md) for more information.

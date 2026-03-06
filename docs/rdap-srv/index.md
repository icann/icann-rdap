# RDAP Server

This server was created to aid in the development of the ICANN RDAP Command Line Interface client.
It can be used as a library or as a server started within its own process. It currently has in-memory
storage, though its storage layer is architected to accommodate a PostgreSQL backend if that is needed
in the future.

RDAP query support in this server is as follows:

- [X] LDH Domain lookup (`/domain/ldh`)
- [X] IDN U-Label lookup (`/domain/unicode`)
- [X] Entity lookup (`/entity/handle`)
- [X] Nameserver lookup (`/nameserver/fqdn`)
- [X] Autnum lookup (`/autnum/123`)
- [X] IP address lookup (`/ip/ip_address`)
- [X] CIDR lookup (`/ip/prefix/len`)
- [X] Domain searches
- [X] Nameserver searches
- [X] Entity searches
- [X] Help (`/help`)

This server explicitly supports the following extensions:

- Cidr0
- Exts
- JSContact
- Redacted
- SimpleRedaction
- Ttl0

Other extensions, such as object tagging, can be placed in the `rdapConformance` array of data
used in this server.

Additionally, this server can act as an RDAP bootstrap server.


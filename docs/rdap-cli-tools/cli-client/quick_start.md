# Quick Start

## Basic Queries

* [Domain](domain_queries.md): `rdap example.com`
* [TLD](domain_queries.md#tld-queries): `rdap .com`
* [IP Address](ip_queries.md): `rdap 192.0.2.1`
* [CIDR](ip_queries.md#cidr-block-queries): `rdap 10/8`
* [ASN](autnum_queries.md): `rdap as64496`
* URL: `rdap https://rdap.iana.org/domain/com`

## Command Help

* brief: `rdap -h`
* extended: `rdap --help`

## Querying Specific Servers

* Using registered servers: `rdap -b arin GOOGL` ( _note: [all the RIRs are registered](ip_queries.md#server-targeting-options)_ )
* Using base URLs: `rdap -B https://rdap.arin.net/registry GOOGL`
* Using full URLs: `rdap https://rdap.arin.net/registry/entity/GOOGL`

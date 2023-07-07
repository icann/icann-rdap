ICANN RDAP
==========

This repository contains open source code written by the Internet Corporation for Assigned Names and Numbers (ICANN)
for use with the Registry Data Access Protocol (RDAP). RDAP is standard of the [IETF](https://ietf.org/), and extensions
to RDAP are a current work activity of the IETF's [REGEXT working group](https://datatracker.ietf.org/wg/regext/documents/).

***THIS PROJECT IS IN ALPHA STAGE.*** You are welcome to use it and file issues or bug reports, however there are no
guarantees as to timeliness of responses.

Installation
------------

Add the library to your Cargo.toml: `cargo add icann-rdap-common`.

This library can be compiled for WASM targets.

Usage
-----

Create some RDAP objects:

```rust
// create an RDAP domain
use icann_rdap_common::response::domain::Domain;
let domain = Domain::basic().ldh_name("example.com").build();

// create an IP network
use cidr_utils::cidr::IpCidr;
let cidr = IpCidr::from_str("10.0.0.0/16").unwrap();
use icann_rdap_common::response::network::Network;
let net = Network::basic().cidr(cidr).build();

// create a nameserver
use icann_rdap_common::response::nameserver::Nameserver;
let ns = Nameserver::basic().ldh_name("ns1.example.com").build();

// create an autnum
use icann_rdap_common::response::autnum::Autnum;
let autnum = Autnum::basic().autnum(700).build();

// create an entity
use icann_rdap_common::response::entity::Entity;
let entity = Entity::basic().handle("foo-BAR").build();
```

Parse RDAP JSON:

```rust
use icann_rdap_common::response::RdapResponse;

let json = r#"
  {
    "objectClassName": "ip network",
    "links": [
      {
        "value": "http://localhost:3000/rdap/ip/10.0.0.0/16",
        "rel": "self",
        "href": "http://localhost:3000/rdap/ip/10.0.0.0/16",
        "type": "application/rdap+json"
      }
    ],
    "events": [
      {
        "eventAction": "registration",
        "eventDate": "2023-06-16T22:56:49.594173356+00:00"
      },
      {
        "eventAction": "last changed",
        "eventDate": "2023-06-16T22:56:49.594189140+00:00"
      }
    ],
    "startAddress": "10.0.0.0",
    "endAddress": "10.0.255.255",
    "ipVersion": "v4"
  }
"#;

let rdap: RdapResponse = serde_json::from_str(json).unwrap();
assert!(matches!(rdap, RdapResponse::Network(_)));
```

License
-------

Licensed under either of
* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT) at your option.

Contribution
------------

Unless you explicitly state otherwise, any contribution, as defined in the Apache-2.0 license, 
intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, 
shall be dual licensed pursuant to the Apache License, Version 2.0 or the MIT License referenced 
as above, at ICANN’s option, without any additional terms or conditions.

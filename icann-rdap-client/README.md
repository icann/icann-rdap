ICANN RDAP
==========

This repository contains open source code written by the Internet Corporation for Assigned Names and Numbers (ICANN)
for use with the Registry Data Access Protocol (RDAP). RDAP is standard of the [IETF](https://ietf.org/), and extensions
to RDAP are a current work activity of the IETF's [REGEXT working group](https://datatracker.ietf.org/wg/regext/documents/).

***THIS PROJECT IS IN ALPHA STAGE.*** You are welcome to use it and file issues or bug reports, however there are no
guarantees as to timeliness of responses.


Installation
------------

Add the library to your Cargo.toml: `cargo add icann-rdap-client`

Also, add the commons library: `cargo add icann-rdap-common`.

Usage
-----

```
// create a query
let query = QueryType::from_str("192.168.0.1")?;
// or
let query = QueryType::from_str("icann.org")?;

// create a client (from icann-rdap-common)
let config = ClientConfig::default();
let client = create_client(&config)?;

// issue the RDAP query
let response = rdap_request("https://rdap-bootstrap.arin.net/bootstrap", &query, &client)?;
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

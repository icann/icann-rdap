ICANN RDAP
==========

This repository contains open source code written by the Internet Corporation for Assigned Names and Numbers [(ICANN)](https://www.icann.org).
for use with the Registry Data Access Protocol (RDAP). RDAP is standard of the [IETF](https://ietf.org/), and extensions
to RDAP are a current work activity of the IETF's [REGEXT working group](https://datatracker.ietf.org/wg/regext/documents/).
More information on ICANN's role in RDAP can be found [here](https://www.icann.org/rdap).
General information on RDAP can be found [here](https://rdap.rcode3.com/).

About
-----

This repository hosts 4 separate packages (i.e. Rust crates):

* [icann-rdap-cli](icann-rdap-cli/README.md) is the Command Line Interface client and testing tool.
* [icann-rdap-client](icann-rdap-client/README.md) is a Rust library handling making RDAP requests.
* [icann-rdap-common](icann-rdap-common/README.md) is a Rust library of RDAP structures.
* [icann-rdap-srv](icann-rdap-srv/README.md) is a simple, in-memory RDAP server. This package produces multiple executable binaries.

![Example of rdap command](https://github.com/icann/icann-rdap/wiki/images/rdap_command.png)

Installation and Usage
----------------------

See the [project wiki](https://github.com/icann/icann-rdap/wiki) for information on installation
and usage of this software.

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

How To Contribute
-----------------

Before working on a Pull Request (PR), seek advice from the maintainers regarding the acceptance
of the PR. To do this, submit an issue outlining the idea for the PR. If the maintainers agree
that the contribution would be welcome, they will assign the issue to you.

When submitting the PR, submit it against the 'dev' branch (not the 'main' branch).


# http://github.com/aripitek 
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

### Coding And Test Styles

All code should be formatted according to `rustfmt`. Run `cargo fmt --check` to determine if
changes are needed.

Tests should follow the GIVEN... WHEN... THEN... pattern if possible. Such as:

```
// GIVEN a domain in the server
...

// WHEN queried
...

// THEN return 200 OK
```

There can be multiple GIVEN, WHEN, and THEN sections.

You may see some tests with the GIVEN-WHEN-THEN pattern in the test name. This is an older naming
convention we no longer use because it became impractical. Just name the test functions like
"test_domain_query" or "validate_server_404" or "check_json_parses" or something simple.

### Commit Messages

Commit messages need only be one line because the substantive purpose of the contribution
should be in the PR request. However, if you want them to have a body, that is fine too.

They take the general form of: "type(scope): description" where scope is optional.

Possible types are:
* `feat` Commits that add, adjust or remove a new feature.
* `fix` Commits that fix a feature.
* `refactor` Commits that rewrite or restructure code without altering behavior.
* `style` Commits that address code style.
* `test` Commits that add missing tests or correct existing ones.
* `docs` Commits that affect documentation.
* `build` Commits that affect build-related components.
* `chore` Miscellaneous commits e.g. modifying `.gitignore`, ...
If there is nothing that works for you, make something up.

The scope provides additional contextual information and are optional.

A commit that introduce breaking changes should be indicated by a `!` before the `:` in the subject line e.g. `feat(common)!: all output is now toml`

The description contains a concise description of the change and should convey the meaning of the commit.
The description can reference an issue or commit for simplicity, e.g. `fix: #137`.

### Before Submitting a PR

If you have `just` installed, run `just pr_check`. If you don't have just, run each of
the commands under "pr_check" in the justfile (the file is easy to read).

### Submitting a PR

When submitting the PR, submit it against the 'dev' branch (not the 'main' branch).


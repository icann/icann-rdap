set dotenv-load

rdap_log := env('RDAP_LOG',"debug")

default:
    @echo "Recipes for lookup queries against the local server."
    @echo
    @echo "RDAP_LOG taken from the environment including .env file."
    @echo
    @echo "RDAP_LOG is: '{{rdap_log}}'"
    @echo
    @just --list srv_search

[doc('Search for nameservers by name in localhost.')]
nameserver_name:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t ns-name "ns1.*.com"

[doc('Search for nameservers by IP in localhost.')]
nameserver_ip:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t ns-ip 10.0.2.1

[doc('Search for domains by nameserver IP in localhost.')]
domain_ns_ip:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t domain-ns-ip 10.0.2.1

[doc('Search for domains by nameserver name in localhost.')]
domain_ns_ldh:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t domain-ns-name "ns1.*.com"

[doc('Search for entityby by handle in localhost.')]
entity_handle:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t entity-handle "foo1234-*"

[doc('Search for entityby by name in localhost.')]
entity_name:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t entity-name "Joe*"

[doc('Lookup up IP address.')]
ip_up:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t v4-up 10.0.0.1

[doc('Lookup up IP address (Alt).')]
ip_up_alt:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap up:10.0.0.1

[doc('Search down IP cidr.')]
ip_down:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -t v4-cidr-down 10.0.0.0/8

[doc('Search down IP cidr (Alt).')]
down_alt:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap down:10.0.0.0/8

set dotenv-load

rdap_log := env('RDAP_LOG',"debug")

default:
    @echo "Recipes for lookup queries against the local server."
    @echo
    @echo "RDAP_LOG taken from the environment including .env file."
    @echo
    @echo "RDAP_LOG is: '{{rdap_log}}'"
    @echo
    @just --list srv_lookup


[doc('Get server help in localhost.')]
lookup_help:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap -S

[doc('Lookup the nameserver in localhost.')]
nameserver:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap ns1.example.com

[doc('Lookup the domain in localhost.')]
domain:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap example.com

[doc('Lookup the entity in localhost.')]
entity:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap foo1234-oid

[doc('Lookup the non-existent domain in localhost.')]
nxdomain:
    cargo run --bin rdap -- --log-level {{rdap_log}} -N -T -B http://localhost:3000/rdap nx.invalid


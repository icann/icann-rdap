mod pg 'just.d/pg.just'
mod rdap 'just.d/rdap.just'
mod rdap_test 'just.d/rdap_test.just'
mod srv_run 'just.d/srv_run.just'
mod srv_lookup 'just.d/srv_lookup.just'
mod srv_search 'just.d/srv_search.just'
mod test 'just.d/test.just'

default:
    @echo "Recipes for development."
    @echo
    @echo "To see topic specific recipes:"
    @echo "  just pg          # postgres"
    @echo "  just rdap        # running 'rdap'"
    @echo "  just rdap_test   # running 'rdap_test'"
    @echo "  just srv_run     # running 'rdap_srv'"
    @echo "  just srv_lookup  # lookup queries against 'rdap_srv'"
    @echo "  just srv_search  # search queries against 'rdap_srv'"
    @echo "  just test        # running cargo tests"

[doc('Get server help in localhost.')]
srv_lookup_help:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -S

[doc('Lookup the nameserver in localhost.')]
srv_lookup_nameserver:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap ns1.example.com

[doc('Lookup the domain in localhost.')]
srv_lookup_domain:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap example.com

[doc('Lookup the entity in localhost.')]
srv_lookup_entity:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap foo1234-oid

[doc('Lookup the non-existent domain in localhost.')]
srv_lookup_nxdomain:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap nx.invalid

[doc('Search for nameservers by name in localhost.')]
srv_search_nameserver_name:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t ns-name "ns1.*.com"

[doc('Search for nameservers by IP in localhost.')]
srv_search_nameserver_ip:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t ns-ip 10.0.2.1

[doc('Search for domains by nameserver IP in localhost.')]
srv_search_domain_ns_ip:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t domain-ns-ip 10.0.2.1

[doc('Search for domains by nameserver name in localhost.')]
srv_search_domain_ns_ldh:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t domain-ns-name "ns1.*.com"

[doc('Search for entityby by handle in localhost.')]
srv_search_entity_handle:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t entity-handle "foo1234-*"

[doc('Search for entityby by name in localhost.')]
srv_search_entity_name:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t entity-name "Joe*"

[doc('Lookup up IP address.')]
srv_lookup_ip_up:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t v4-up 10.0.0.1

[doc('Lookup up IP address (Alt).')]
srv_lookup_ip_up_alt:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap up:10.0.0.1

[doc('Search down IP cidr.')]
srv_search_ip_down:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t v4-cidr-down 10.0.0.0/8

[doc('Search down IP cidr (Alt).')]
srv_search_ip_down_alt:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap down:10.0.0.0/8

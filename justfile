default:
    just --list

[doc('Run the tests.')]
test:
    cargo test

[doc('Update golden files.')]
update_goldenfiles $UPDATE_GOLDENFILES="1":
    cargo test

[doc('Run clean and then the tests.')]
clean_test:
    cargo clean \
    && cargo test

[doc('Check IANA RDAP registries.')]
iana_tests:
    cargo test -p icann-rdap-common --features iana_registry_tests

[doc('Run tests then build docs.')]
test_n_doc:
    cargo test \
    && cargo doc --no-deps

[doc('Run this before PR. WASM32 target required.')]
pr_check:
    cargo fmt --check \
    && cargo clean \
    && cargo check --target wasm32-unknown-unknown -p icann-rdap-client \
    && cargo test \
    && cargo doc --no-deps

[doc('Do an RDAP lookup on a given value.')]
rdap_lookup value:
    cargo run --bin rdap -- -L debug {{value}}

[doc('Do an RDAP test on a given value.')]
rdap_test value:
    cargo run --bin rdap-test -- -L debug {{value}}

[doc('Run an IP lookup smoke test for 199.4.138.53.')]
ex_ip_lookup:
    cargo run --bin rdap -- -L debug 199.4.138.53

[doc('Run a domain lookup smoke test for icann.org.')]
ex_domain_lookup:
    cargo run --bin rdap -- -L debug icann.org

[doc('Look at the rdap help.')]
rdap_help:
    cargo run --bin rdap -- --help

[doc('Run an IP conformance test smoke test for 199.4.138.35.')]
ex_ip_test:
    cargo run --bin rdap-test -- 199.4.138.53

[doc('Run a domain conformance test smoke test for icann.org.')]
ex_domain_test:
    cargo run --bin rdap-test -- icann.org

[doc('Look at the rdap-test help.')]
rdap_test_help:
    cargo run --bin rdap-test -- --help

[doc('Create Server Data.')]
srv_data_setup:
    mkdir -p srv/data \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- srv-help --notice "this is a test server" \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- entity --handle foo1234-oid --email joe@example.com --full-name "Joe User" \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- nameserver --ldh ns1.example.com --registrant foo1234-oid --v4 10.0.2.1 --v6 2001::1 \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- domain --ldh example.com --registrant foo1234-oid --ns ns1.example.com \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/8 --handle net4-1 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/16 --handle net4-2 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.1.0.0/16 --handle net4-3 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.2.0.0/16 --handle net4-4 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/24 --handle net4-5 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/24 --handle net4-6 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.0.1.0/24 --handle net4-7 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.0.2.0/24 --handle net4-8 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.1.0.0/24 --handle net4-9 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.1.1.0/24 --handle net4-10 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.1.2.0/24 --handle net4-11 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.2.0.0/24 --handle net4-12 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.2.1.0/24 --handle net4-13 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 10.2.2.0/24 --handle net4-14 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 2001:db8::/20 --handle net6-1 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 2001:db8::/32 --handle net6-2 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- network --cidr 2001:db8:1::/48 --handle net6-3 --registrant foo1234-oid

[doc('Start the server')]
srv_start:
    RDAP_SRV_DATA_DIR=srv/data \
    RDAP_SRV_DOMAIN_SEARCH_BY_NAME=true \
    RDAP_SRV_DOMAIN_SEARCH_BY_NS_IP=true \
    RDAP_SRV_DOMAIN_SEARCH_BY_NS_LDH_NAME=true \
    RDAP_SRV_NAMESERVER_SEARCH_BY_NAME=true \
    RDAP_SRV_NAMESERVER_SEARCH_BY_IP=true \
    RDAP_SRV_ENTITY_SEARCH_BY_HANDLE=true \
    RDAP_SRV_ENTITY_SEARCH_BY_FULL_NAME=true \
    RDAP_SRV_IP_RDAP_UP=true \
    RDAP_SRV_IP_RDAP_TOP=true \
    RDAP_SRV_IP_RDAP_DOWN=true \
    RDAP_SRV_IP_RDAP_BOTTOM=true \
    RDAP_SRV_AUTNUM_RDAP_UP=true \
    RDAP_SRV_AUTNUM_RDAP_TOP=true \
    RDAP_SRV_AUTNUM_RDAP_DOWN=true \
    RDAP_SRV_AUTNUM_RDAP_BOTTOM=true \
    RDAP_SRV_DOMAIN_RDAP_UP=true \
    RDAP_SRV_DOMAIN_RDAP_TOP=true \
    RDAP_SRV_DOMAIN_RDAP_DOWN=true \
    RDAP_SRV_DOMAIN_RDAP_BOTTOM=true \
    RDAP_SRV_NETWORK_SEARCH_BY_HANDLE=true \
    RDAP_SRV_NETWORK_SEARCH_BY_NAME=true \
    RDAP_SRV_AUTNUM_SEARCH_BY_HANDLE=true \
    RDAP_SRV_AUTNUM_SEARCH_BY_NAME=true \
    RDAP_SRV_JSCONTACT_CONVERSION=also \
    RDAP_SRV_LOG=debug \
    cargo run --bin rdap-srv 

[doc('Update the data in the server.')]
srv_update:
    RDAP_SRV_DATA_DIR=srv/data RDAP_SRV_LOG=debug cargo run --bin rdap-srv-store -- --update

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

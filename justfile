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

[doc('Run an IP query smoke test.')]
smoke_ip_query:
    cargo run --bin rdap -- -L debug 199.4.138.53

[doc('Run a domain query smoke test.')]
smoke_domain_query:
    cargo run --bin rdap -- -L debug icann.org

[doc('Look at the rdap help.')]
smoke_rdap_help:
    cargo run --bin rdap -- --help

[doc('Run an IP conformance check smoke test.')]
smoke_ip_check:
    cargo run --bin rdap-test -- 199.4.138.53

[doc('Run a domain conformance check smoke test.')]
smoke_domain_check:
    cargo run --bin rdap-test -- icann.org

[doc('Look at the rdap-test help.')]
smoke_rdap_test_help:
    cargo run --bin rdap-test -- --help

[doc('Create a help response in the server.')]
srv_data_help:
    RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- srv-help --notice "this is a test server"

[doc('Create an entity in the server.')]
srv_data_entity:
    RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- entity --handle foo1234 --email joe@example.com --full-name "Joe User"

[doc('Create a domain in the server.')]
srv_data_domain:
    RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- domain --ldh example.com --registrant foo1234 --ns ns1.example.com

[doc('Create a nameserver in the server.')]
srv_data_nameserver:
    RDAP_SRV_LOG=debug cargo run --bin rdap-srv-data -- nameserver --ldh ns1.example.com --registrant foo1234 --v4 10.0.2.1 --v6 2001::1

[doc('Start the server')]
srv_start:
    RDAP_SRV_DOMAIN_SEARCH_BY_NAME=true \
    RDAP_SRV_NAMESERVER_SEARCH_BY_NAME=true \
    RDAP_SRV_NAMESERVER_SEARCH_BY_IP=true \
    RDAP_SRV_LOG=debug \
    cargo run --bin rdap-srv 

[doc('Update the data in the server.')]
srv_update:
    RDAP_SRV_LOG=debug cargo run --bin rdap-srv-store -- --update

[doc('Lookup the nameserver in localhost.')]
srv_lookup_nameserver:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap ns1.example.com

[doc('Lookup the domain in localhost.')]
srv_lookup_domain:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap example.com

[doc('Lookup the entity in localhost.')]
srv_lookup_entity:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap foo1234

[doc('Lookup the non-existent domain in localhost.')]
srv_lookup_nxdomain:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap nx.invalid

[doc('Search for nameservers by name in localhost.')]
srv_search_nameserver_name:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t ns-name "ns1.*.com"

[doc('Search for nameservers by IP in localhost.')]
srv_search_nameserver_ip:
    cargo run --bin rdap -- --log-level debug -N -T -B http://localhost:3000/rdap -t ns-ip 10.0.2.1

default:
    just --list

[doc('Run the tests.')]
test:
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
    cargo run --bin rdap -- 199.4.138.53

[doc('Run a domain query smoke test.')]
smoke_domain_query:
    cargo run --bin rdap -- icann.org

[doc('Run an IP conformace check smoke test.')]
smoke_ip_check:
    cargo run --bin rdap-test -- 199.4.138.53

[doc('Run a domain conformance check smoke test.')]
smoke_domain_check:
    cargo run --bin rdap-test -- icann.org


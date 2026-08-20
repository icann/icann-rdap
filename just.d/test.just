# features that normally get tested
# the iana_registry_tests should not hold up a release
features := "postgres"

default:
    @echo "These recipes run various test types."
    @echo
    @just --list test

[doc('Run the release tests.')]
release:
    cargo test --features "{{features}}"

[doc('Update golden files.')]
update_goldenfiles $UPDATE_GOLDENFILES="1":
    cargo test --features "{{features}}"

[doc('Run clean and then the tests.')]
clean_test:
    cargo clean \
    && cargo test --features "{{features}}"

[doc('Check IANA RDAP registries.')]
iana:
    cargo test -p icann-rdap-common --features iana_registry_tests

[doc('Run tests then build docs.')]
test_n_doc:
    cargo test --features "{{features}}" \
    && cargo doc --no-deps

[doc('Run this before PR. WASM32 target required.')]
pr_check:
    cargo fmt --check \
    && cargo clean \
    && cargo check --target wasm32-unknown-unknown -p icann-rdap-client \
    && cargo test --features "{{features}}" \
    && cargo doc --no-deps


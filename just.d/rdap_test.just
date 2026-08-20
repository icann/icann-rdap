set dotenv-load

rdap_test_log := env('RDAP_TEST_LOG',"debug")

default:
    @echo "Recipes for the rdap-test command."
    @echo
    @echo "RDAP_TEST_LOG taken from the environment including .env file."
    @echo
    @echo "RDAP_TEST_LOG is: '{{rdap_test_log}}'"
    @echo
    @just --list rdap_test

[doc('Do an RDAP test on a given value.')]
test_server value:
    cargo run --bin rdap-test -- -L {{rdap_test_log}} {{value}}

[doc('Run an IP conformance test smoke test for 199.4.138.35.')]
ex_ip:
    cargo run --bin rdap-test -- -L {{rdap_test_log}} 199.4.138.53

[doc('Run a domain conformance test smoke test for icann.org.')]
ex_domain:
    cargo run --bin rdap-test -- -L {{rdap_test_log}} icann.org

[doc('Look at the rdap-test help.')]
rdap_test_help:
    cargo run --bin rdap-test -- --help


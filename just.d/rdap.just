set dotenv-load

rdap_log := env('RDAP_LOG',"debug")

default:
    @echo "Recipes for the rdap command."
    @echo
    @echo "RDAP_LOG taken from the environment including .env file."
    @echo
    @echo "RDAP_LOG is: '{{rdap_log}}'"
    @echo
    @just --list rdap

[doc('Do an RDAP lookup on a given value.')]
lookup value:
    cargo run --bin rdap -- -L {{rdap_log}} {{value}}

[doc('Run an IP lookup smoke test for 199.4.138.53.')]
ex_ip:
    cargo run --bin rdap -- -L {{rdap_log}} 199.4.138.53

[doc('Run a domain lookup smoke test for icann.org.')]
ex_domain:
    cargo run --bin rdap -- -L {{rdap_log}} icann.org

[doc('Look at the rdap help.')]
rdap_help:
    cargo run --bin rdap -- --help


set dotenv-load
set no-cd

srv_log := env('RDAP_SRV_LOG',"debug")
srv_dir := env('RDAP_SRV_DATA_DIR',"srv/data")
pg_url  := env('RDAP_SRV_DB_URL',"postgresql://127.0.0.1/rdap")
admin   := env('PG_ADMIN',"postgres")

default:
    @echo "Recipes for running the server."
    @echo
    @echo "RDAP_SRV_LOG and RDAP_SRV_DATA_DIR taken from the environment including .env file."
    @echo
    @echo "RDAP_SRV_LOG      is: '{{srv_log}}'"
    @echo "RDAP_SRV_DATA_DIR is: '{{srv_dir}}'"
    @echo "RDAP_SRV_DB_URL   is: '{{pg_url}}'"
    @echo "ADMIN             is: '{{admin}}'"
    @echo
    just --list pg

[doc('Execute schema migration.')]
migrate:
    @echo "Migrating Database Schema"
    RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-pg --features "postgres" -- migrate --admin-user {{admin}}

[doc('Create role and database.')]
create:
    @echo "Creating Database"
    RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-pg --features "postgres" -- create --admin-user {{admin}}

[doc('Destroy role and database.')]
destroy:
    @echo "Destroying Database"
    RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-pg --features "postgres" -- destroy --admin-user {{admin}}

[doc('Start the server')]
start:
    RDAP_SRV_STORAGE=postgres \
    RDAP_SRV_DATA_DIR={{srv_dir}} \
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
    RDAP_SRV_LOG={{srv_log}} \
    cargo run --bin rdap-srv --features "postgres"

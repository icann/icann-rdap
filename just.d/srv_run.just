set dotenv-load
set no-cd

srv_log := env('RDAP_SRV_LOG',"debug")
srv_dir := env('RDAP_SRV_DATA_DIR',"srv/data")

default:
    @echo "Recipes for running the server."
    @echo
    @echo "RDAP_SRV_LOG and RDAP_SRV_DATA_DIR taken from the environment including .env file."
    @echo
    @echo "RDAP_SRV_LOG      is: '{{srv_log}}'"
    @echo "RDAP_SRV_DATA_DIR is: '{{srv_dir}}'"
    @echo
    just --list srv_run

[doc('Create Server Data.')]
data_setup:
    mkdir -p srv/data \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- srv-help --notice "this is a test server" \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- entity --handle foo1234-oid --email joe@example.com --full-name "Joe User" \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- nameserver --ldh ns1.example.com --registrant foo1234-oid --v4 10.0.2.1 --v6 2001::1 \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- domain --ldh example.com --registrant foo1234-oid --ns ns1.example.com \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/8 --handle net4-1 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/16 --handle net4-2 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.1.0.0/16 --handle net4-3 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.2.0.0/16 --handle net4-4 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/24 --handle net4-5 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.0.0.0/24 --handle net4-6 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.0.1.0/24 --handle net4-7 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.0.2.0/24 --handle net4-8 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.1.0.0/24 --handle net4-9 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.1.1.0/24 --handle net4-10 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.1.2.0/24 --handle net4-11 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.2.0.0/24 --handle net4-12 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.2.1.0/24 --handle net4-13 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 10.2.2.0/24 --handle net4-14 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 2001:db8::/20 --handle net6-1 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 2001:db8::/32 --handle net6-2 --registrant foo1234-oid \
    && RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-data -- network --cidr 2001:db8:1::/48 --handle net6-3 --registrant foo1234-oid

[doc('Start the server')]
start:
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
    cargo run --bin rdap-srv 

[doc('Update the data in the server.')]
update:
    RDAP_SRV_DATA_DIR={{srv_dir}} RDAP_SRV_LOG={{srv_log}} cargo run --bin rdap-srv-store -- --update


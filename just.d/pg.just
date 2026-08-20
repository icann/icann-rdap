default:
    just --list pg

[doc('Execute schema migration.')]
migrate:
    @echo "migrate"

[doc('Create role and database.')]
create:
    @echo "create"

[doc('Destroy role and database.')]
destroy:
    @echo "destroy"

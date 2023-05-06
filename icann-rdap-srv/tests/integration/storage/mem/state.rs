#![allow(non_snake_case)]

use icann_rdap_common::response::{domain::Domain, entity::Entity};
use icann_rdap_srv::{
    rdap::response::{ArcRdapResponse, RdapServerResponse},
    storage::{
        mem::{
            config::MemConfig,
            ops::Mem,
            state::{DomainId, EntityId, Template},
        },
        StoreOps,
    },
};
use test_dir::{DirBuilder, TestDir};

#[tokio::test]
async fn GIVEN_state_dir_with_domain_WHEN_mem_init_THEN_domain_is_loaded() {
    // GIVEN
    let ldh_name = "foo.example";
    let temp = TestDir::temp();
    let domain = Domain::basic().ldh_name(ldh_name).build();
    let domain_file = temp.path("foo_example.json");
    std::fs::write(
        domain_file,
        serde_json::to_string(&domain).expect("serializing domain"),
    )
    .expect("writing file");

    // WHEN
    let mem_config = MemConfig::builder()
        .state_dir(temp.root().to_string_lossy())
        .build();
    let mem = Mem::new(mem_config);
    mem.init().await.expect("initialzing memeory");

    // THEN
    let actual = mem
        .get_domain_by_ldh(ldh_name)
        .await
        .expect("getting domain by ldh");
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Domain(_)));
    let ArcRdapResponse::Domain(domain) = response else { panic!() };
    assert_eq!(domain.ldh_name.as_ref().expect("ldhName is none"), ldh_name)
}

#[tokio::test]
async fn GIVEN_state_dir_with_domain_template_WHEN_mem_init_THEN_domains_are_loaded() {
    // GIVEN
    let ldh1 = "foo.example";
    let ldh2 = "bar.example";
    let temp = TestDir::temp();
    let template = Template::Domain {
        domain: Domain::basic().ldh_name("example").build(),
        ids: vec![
            DomainId::builder().ldh_name(ldh1).build(),
            DomainId::builder().ldh_name(ldh2).build(),
        ],
    };
    let template_file = temp.path("example.template");
    std::fs::write(
        template_file,
        serde_json::to_string(&template).expect("serializing template"),
    )
    .expect("writing file");

    // WHEN
    let mem_config = MemConfig::builder()
        .state_dir(temp.root().to_string_lossy())
        .build();
    let mem = Mem::new(mem_config);
    mem.init().await.expect("initialzing memeory");

    // THEN
    for ldh in [ldh1, ldh2] {
        let actual = mem
            .get_domain_by_ldh(ldh)
            .await
            .expect("getting domain by ldh");
        let RdapServerResponse::Arc(response) = actual else { panic!() };
        assert!(matches!(response, ArcRdapResponse::Domain(_)));
        let ArcRdapResponse::Domain(domain) = response else { panic!() };
        assert_eq!(domain.ldh_name.as_ref().expect("ldhName is none"), ldh)
    }
}

#[tokio::test]
async fn GIVEN_state_dir_with_entity_WHEN_mem_init_THEN_entity_is_loaded() {
    // GIVEN
    let handle = "foo.example";
    let temp = TestDir::temp();
    let entity = Entity::basic().handle(handle).build();
    let domain_file = temp.path("foo_example.json");
    std::fs::write(
        domain_file,
        serde_json::to_string(&entity).expect("serializing entity"),
    )
    .expect("writing file");

    // WHEN
    let mem_config = MemConfig::builder()
        .state_dir(temp.root().to_string_lossy())
        .build();
    let mem = Mem::new(mem_config);
    mem.init().await.expect("initialzing memeory");

    // THEN
    let actual = mem
        .get_entity_by_handle(handle)
        .await
        .expect("getting entity by ldh");
    let RdapServerResponse::Arc(response) = actual else { panic!() };
    assert!(matches!(response, ArcRdapResponse::Entity(_)));
    let ArcRdapResponse::Entity(entity) = response else { panic!() };
    assert_eq!(
        entity
            .object_common
            .handle
            .as_ref()
            .expect("handle is none"),
        handle
    )
}

#[tokio::test]
async fn GIVEN_state_dir_with_entity_template_WHEN_mem_init_THEN_entities_are_loaded() {
    // GIVEN
    let handle1 = "foo";
    let handle2 = "bar";
    let temp = TestDir::temp();
    let template = Template::Entity {
        entity: Entity::basic().handle("example").build(),
        ids: vec![
            EntityId::builder().handle(handle1).build(),
            EntityId::builder().handle(handle2).build(),
        ],
    };
    let template_file = temp.path("example.template");
    std::fs::write(
        template_file,
        serde_json::to_string(&template).expect("serializing template"),
    )
    .expect("writing file");

    // WHEN
    let mem_config = MemConfig::builder()
        .state_dir(temp.root().to_string_lossy())
        .build();
    let mem = Mem::new(mem_config);
    mem.init().await.expect("initialzing memeory");

    // THEN
    for handle in [handle1, handle2] {
        let actual = mem
            .get_entity_by_handle(handle)
            .await
            .expect("getting entity by handle");
        let RdapServerResponse::Arc(response) = actual else { panic!() };
        assert!(matches!(response, ArcRdapResponse::Entity(_)));
        let ArcRdapResponse::Entity(entity) = response else { panic!() };
        assert_eq!(
            entity
                .object_common
                .handle
                .as_ref()
                .expect("handle is none"),
            handle
        )
    }
}

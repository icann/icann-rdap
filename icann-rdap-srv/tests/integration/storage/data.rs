#![allow(non_snake_case)]

use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
    RdapResponse,
};
use icann_rdap_srv::{
    config::{ServiceConfig, StorageType},
    storage::{
        data::{
            load_data, AutnumId, DomainId, EntityId, NameserverId, NetworkId, NetworkIdType,
            Template,
        },
        mem::{config::MemConfig, ops::Mem},
        StoreOps,
    },
};
use test_dir::{DirBuilder, TestDir};

async fn new_and_init_mem(data_dir: String) -> Mem {
    let mem_config = MemConfig::builder().build();
    let mem = Mem::new(mem_config.clone());
    mem.init().await.expect("initialzing memeory");
    load_data(
        &ServiceConfig::builder()
            .data_dir(data_dir)
            .auto_reload(false)
            .storage_type(StorageType::Memory(mem_config))
            .build(),
        &mem,
        false,
    )
    .await
    .expect("loading data");
    mem
}

#[tokio::test]
async fn GIVEN_data_dir_with_domain_WHEN_mem_init_THEN_domain_is_loaded() {
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
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    let actual = mem
        .get_domain_by_ldh(ldh_name)
        .await
        .expect("getting domain by ldh");
    assert!(matches!(actual, RdapResponse::Domain(_)));
    let RdapResponse::Domain(domain) = actual else { panic!() };
    assert_eq!(domain.ldh_name.as_ref().expect("ldhName is none"), ldh_name)
}

#[tokio::test]
async fn GIVEN_data_dir_with_domain_template_WHEN_mem_init_THEN_domains_are_loaded() {
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
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    for ldh in [ldh1, ldh2] {
        let actual = mem
            .get_domain_by_ldh(ldh)
            .await
            .expect("getting domain by ldh");
        assert!(matches!(actual, RdapResponse::Domain(_)));
        let RdapResponse::Domain(domain) = actual else { panic!() };
        assert_eq!(domain.ldh_name.as_ref().expect("ldhName is none"), ldh)
    }
}

#[tokio::test]
async fn GIVEN_data_dir_with_entity_WHEN_mem_init_THEN_entity_is_loaded() {
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
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    let actual = mem
        .get_entity_by_handle(handle)
        .await
        .expect("getting entity by ldh");
    assert!(matches!(actual, RdapResponse::Entity(_)));
    let RdapResponse::Entity(entity) = actual else { panic!() };
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
async fn GIVEN_data_dir_with_entity_template_WHEN_mem_init_THEN_entities_are_loaded() {
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
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    for handle in [handle1, handle2] {
        let actual = mem
            .get_entity_by_handle(handle)
            .await
            .expect("getting entity by handle");
        assert!(matches!(actual, RdapResponse::Entity(_)));
        let RdapResponse::Entity(entity) = actual else { panic!() };
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

#[tokio::test]
async fn GIVEN_data_dir_with_nameserver_WHEN_mem_init_THEN_nameserver_is_loaded() {
    // GIVEN
    let ldh_name = "ns.foo.example";
    let temp = TestDir::temp();
    let nameserver = Nameserver::basic().ldh_name(ldh_name).build().unwrap();
    let nameserver_file = temp.path("ns_foo_example.json");
    std::fs::write(
        nameserver_file,
        serde_json::to_string(&nameserver).expect("serializing nameserver"),
    )
    .expect("writing file");

    // WHEN
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    let actual = mem
        .get_nameserver_by_ldh(ldh_name)
        .await
        .expect("getting nameserver by ldh");
    assert!(matches!(actual, RdapResponse::Nameserver(_)));
    let RdapResponse::Nameserver(nameserver) = actual else { panic!() };
    assert_eq!(
        nameserver.ldh_name.as_ref().expect("ldhName is none"),
        ldh_name
    )
}

#[tokio::test]
async fn GIVEN_data_dir_with_nameserver_template_WHEN_mem_init_THEN_nameservers_are_loaded() {
    // GIVEN
    let ldh1 = "ns.foo.example";
    let ldh2 = "ns.bar.example";
    let temp = TestDir::temp();
    let template = Template::Nameserver {
        nameserver: Nameserver::basic().ldh_name("example").build().unwrap(),
        ids: vec![
            NameserverId::builder().ldh_name(ldh1).build(),
            NameserverId::builder().ldh_name(ldh2).build(),
        ],
    };
    let template_file = temp.path("example.template");
    std::fs::write(
        template_file,
        serde_json::to_string(&template).expect("serializing template"),
    )
    .expect("writing file");

    // WHEN
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    for ldh in [ldh1, ldh2] {
        let actual = mem
            .get_nameserver_by_ldh(ldh)
            .await
            .expect("getting nameserver by ldh");
        assert!(matches!(actual, RdapResponse::Nameserver(_)));
        let RdapResponse::Nameserver(nameserver) = actual else { panic!() };
        assert_eq!(nameserver.ldh_name.as_ref().expect("ldhName is none"), ldh)
    }
}

#[tokio::test]
async fn GIVEN_data_dir_with_autnum_WHEN_mem_init_THEN_autnum_is_loaded() {
    // GIVEN
    let num = 700u32;
    let temp = TestDir::temp();
    let autnum = Autnum::basic().autnum_range(num..num).build();
    let autnum_file = temp.path("700.json");
    std::fs::write(
        autnum_file,
        serde_json::to_string(&autnum).expect("serializing autnum"),
    )
    .expect("writing file");

    // WHEN
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    let actual = mem
        .get_autnum_by_num(num)
        .await
        .expect("getting autnum by num");
    assert!(matches!(actual, RdapResponse::Autnum(_)));
    let RdapResponse::Autnum(autnum) = actual else { panic!() };
    assert_eq!(
        *autnum.start_autnum.as_ref().expect("startAutnum is none"),
        num
    )
}

#[tokio::test]
async fn GIVEN_data_dir_with_autnum_template_WHEN_mem_init_THEN_autnums_are_loaded() {
    // GIVEN
    let num1 = 700u32;
    let num2 = 800u32;
    let temp = TestDir::temp();
    let template = Template::Autnum {
        autnum: Autnum::basic().autnum_range(0..0).build(),
        ids: vec![
            AutnumId::builder()
                .start_autnum(num1)
                .end_autnum(num1)
                .build(),
            AutnumId::builder()
                .start_autnum(num2)
                .end_autnum(num2)
                .build(),
        ],
    };
    let template_file = temp.path("example.template");
    std::fs::write(
        template_file,
        serde_json::to_string(&template).expect("serializing template"),
    )
    .expect("writing file");

    // WHEN
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    for num in [num1, num2] {
        let actual = mem
            .get_autnum_by_num(num)
            .await
            .expect("getting autnum by num");
        assert!(matches!(actual, RdapResponse::Autnum(_)));
        let RdapResponse::Autnum(autnum) = actual else { panic!() };
        assert_eq!(
            *autnum.start_autnum.as_ref().expect("startAutnum is none"),
            num
        )
    }
}

#[tokio::test]
async fn GIVEN_data_dir_with_network_WHEN_mem_init_THEN_network_is_loaded() {
    // GIVEN
    let temp = TestDir::temp();
    let network = Network::basic()
        .cidr("10.0.0.0/24")
        .build()
        .expect("cidr parsing");
    let net_file = temp.path("ten_net.json");
    std::fs::write(
        net_file,
        serde_json::to_string(&network).expect("serializing network"),
    )
    .expect("writing file");

    // WHEN
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    let actual = mem
        .get_network_by_ipaddr("10.0.0.0")
        .await
        .expect("getting autnum by num");
    assert!(matches!(actual, RdapResponse::Network(_)));
    let RdapResponse::Network(network) = actual else { panic!() };
    assert_eq!(
        *network
            .start_address
            .as_ref()
            .expect("startAddress is none"),
        "10.0.0.0"
    )
}

#[tokio::test]
async fn GIVEN_data_dir_with_network_template_with_cidr_WHEN_mem_init_THEN_networks_are_loaded() {
    // GIVEN
    let cidr1 = "10.0.0.0/24";
    let cidr2 = "10.0.1.0/24";
    let start1 = "10.0.0.0";
    let start2 = "10.0.1.0";
    let temp = TestDir::temp();
    let template = Template::Network {
        network: Network::basic()
            .cidr("1.1.1.1/32")
            .build()
            .expect("parsing cidr"),
        ids: vec![
            NetworkId::builder()
                .network_id(NetworkIdType::Cidr(cidr1.parse().expect("parsing cidr")))
                .build(),
            NetworkId::builder()
                .network_id(NetworkIdType::Cidr(cidr2.parse().expect("parsing cidr")))
                .build(),
        ],
    };
    let template_file = temp.path("example.template");
    std::fs::write(
        template_file,
        serde_json::to_string(&template).expect("serializing template"),
    )
    .expect("writing file");

    // WHEN
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    for (cidr, start) in [(cidr1, start1), (cidr2, start2)] {
        let actual = mem
            .get_network_by_cidr(cidr)
            .await
            .expect("getting cidr by num");
        assert!(matches!(actual, RdapResponse::Network(_)));
        let RdapResponse::Network(network) = actual else { panic!() };
        assert_eq!(
            *network
                .start_address
                .as_ref()
                .expect("startAddress is none"),
            start
        )
    }
}

#[tokio::test]
async fn GIVEN_data_dir_with_network_template_with_range_WHEN_mem_init_THEN_networks_are_loaded() {
    // GIVEN
    let start1 = "10.0.0.0";
    let start2 = "10.0.1.0";
    let end1 = "10.0.0.255";
    let end2 = "10.0.1.255";
    let temp = TestDir::temp();
    let template = Template::Network {
        network: Network::basic()
            .cidr("1.1.1.1/32")
            .build()
            .expect("parsing cidr"),
        ids: vec![
            NetworkId::builder()
                .network_id(NetworkIdType::Range {
                    start_address: start1.to_string(),
                    end_address: end1.to_string(),
                })
                .build(),
            NetworkId::builder()
                .network_id(NetworkIdType::Range {
                    start_address: start2.to_string(),
                    end_address: end2.to_string(),
                })
                .build(),
        ],
    };
    let template_file = temp.path("example.template");
    std::fs::write(
        template_file,
        serde_json::to_string(&template).expect("serializing template"),
    )
    .expect("writing file");

    // WHEN
    let mem = new_and_init_mem(temp.root().to_string_lossy().to_string()).await;

    // THEN
    for (start, end) in [(start1, end1), (start2, end2)] {
        let actual = mem
            .get_network_by_ipaddr(end)
            .await
            .expect("getting cidr by addr");
        assert!(matches!(actual, RdapResponse::Network(_)));
        let RdapResponse::Network(network) = actual else { panic!() };
        assert_eq!(
            *network
                .start_address
                .as_ref()
                .expect("startAddress is none"),
            start
        )
    }
}

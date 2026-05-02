use {
    icann_rdap_common::response::{Help, Notice, NoticeOrRemark, RdapResponse},
    icann_rdap_srv::storage::{mem::ops::Mem, StoreOps},
};

#[tokio::test]
async fn default_help() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_srv_help(
        &Help::response()
            .notice(Notice(
                NoticeOrRemark::builder()
                    .description_entry("foo".to_string())
                    .build(),
            ))
            .build(),
        None,
    )
    .await
    .expect("adding srv help");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem.get_srv_help(None).await.expect("getting srv help");

    // THEN
    let RdapResponse::Help(srvhelp) = actual else {
        panic!()
    };
    let notice = srvhelp
        .common
        .notices
        .expect("no notices in srvhelp")
        .first()
        .expect("notices empty")
        .to_owned();
    assert_eq!(
        notice
            .description
            .as_ref()
            .expect("no description!")
            .vec()
            .first()
            .expect("no description in notice"),
        "foo"
    );
}

#[tokio::test]
async fn hosted_help() {
    // GIVEN
    let mem = Mem::default();
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_srv_help(
        &Help::response()
            .notice(Notice(
                NoticeOrRemark::builder()
                    .description_entry("bar".to_string())
                    .build(),
            ))
            .build(),
        Some("bar.example.com"),
    )
    .await
    .expect("adding srv help");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .get_srv_help(Some("bar.example.com"))
        .await
        .expect("getting srv help");

    // THEN
    let RdapResponse::Help(srvhelp) = actual else {
        panic!()
    };
    let notice = srvhelp
        .common
        .notices
        .expect("no notices in srvhelp")
        .first()
        .expect("notices empty")
        .to_owned();
    assert_eq!(
        notice
            .description
            .as_ref()
            .expect("no description")
            .vec()
            .first()
            .expect("no description in notice"),
        "bar"
    );
}

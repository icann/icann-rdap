use crate::prelude::has_rdap_path;

use {
    crate::prelude::ObjectCommon,
    std::{any::TypeId, str::FromStr, sync::LazyLock},
};

use {
    crate::{
        media_types::RDAP_MEDIA_TYPE,
        prelude::Common,
        response::{
            autnum::Autnum,
            domain::Domain,
            entity::Entity,
            nameserver::Nameserver,
            network::Network,
            types::{
                ExtensionId, Link, Links, NoticeOrRemark, Notices, PublicIds, RdapConformance,
                Remarks,
            },
        },
    },
    chrono::DateTime,
};

use super::{
    string::{StringCheck, StringListCheck},
    Check, CheckItem, CheckParams, Checks, GetChecks, GetSubChecks,
};

impl GetChecks for RdapConformance {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items = vec![];
        if params.parent_type != params.root.get_type() {
            items.push(Check::RdapConformanceInvalidParent.check_item())
        };
        for ext in self {
            if !params.allow_unreg_ext {
                let id = ExtensionId::from_str(ext);
                if id.is_err() {
                    items.push(Check::UnknownExtention.check_item())
                }
            }
        }
        Checks {
            rdap_struct: super::RdapStructure::RdapConformance,
            items,
            sub_checks: vec![],
        }
    }
}

impl GetChecks for Links {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = vec![];
        self.iter()
            .for_each(|link| sub_checks.push(link.get_checks(params)));
        Checks {
            rdap_struct: super::RdapStructure::Links,
            items: vec![],
            sub_checks,
        }
    }
}

static RELATED_AND_SELF_LINK_PARENTS: LazyLock<Vec<TypeId>> = LazyLock::new(|| {
    vec![
        TypeId::of::<Domain>(),
        TypeId::of::<Entity>(),
        TypeId::of::<Autnum>(),
        TypeId::of::<Network>(),
    ]
});

impl GetChecks for Link {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items: Vec<CheckItem> = vec![];
        if self.value.is_none() {
            items.push(Check::LinkMissingValueProperty.check_item())
        };
        if self.href.is_none() {
            items.push(Check::LinkMissingHrefProperty.check_item())
        };
        if let Some(rel) = &self.rel {
            if rel.eq("related") {
                if let Some(media_type) = &self.media_type {
                    if !media_type.eq(RDAP_MEDIA_TYPE)
                        && RELATED_AND_SELF_LINK_PARENTS.contains(&params.parent_type)
                    {
                        items.push(Check::LinkRelatedIsNotRdap.check_item())
                    } else if media_type.eq(RDAP_MEDIA_TYPE) {
                        if let Some(ref href) = self.href {
                            if !has_rdap_path(href) {
                                items.push(Check::LinkRelatedNotToRdap.check_item())
                            }
                        }
                    }
                } else {
                    items.push(Check::LinkRelatedHasNoType.check_item())
                }
            } else if rel.eq("self") {
                if let Some(media_type) = &self.media_type {
                    if !media_type.eq(RDAP_MEDIA_TYPE) {
                        items.push(Check::LinkSelfIsNotRdap.check_item())
                    }
                } else {
                    items.push(Check::LinkSelfHasNoType.check_item())
                }
            } else if RELATED_AND_SELF_LINK_PARENTS.contains(&params.parent_type) &&
                // because some registries do not model nameservers directly,
                // they can be embedded in other objects but aren't first class
                // objects themself (see RIR example in RFC 9083). Therefore,
                // it only matters that a nameserver has no self link if it is
                // the top most object (i.e. a first class object).
                params.root.get_type() != TypeId::of::<Nameserver>()
            {
                items.push(Check::LinkObjectClassHasNoSelf.check_item())
            }
        } else {
            items.push(Check::LinkMissingRelProperty.check_item())
        }
        Checks {
            rdap_struct: super::RdapStructure::Link,
            items,
            sub_checks: vec![],
        }
    }
}

impl GetChecks for Notices {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = vec![];
        self.iter()
            .for_each(|note| sub_checks.push(note.0.get_checks(params)));
        Checks {
            rdap_struct: super::RdapStructure::Notices,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for Remarks {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = vec![];
        self.iter()
            .for_each(|remark| sub_checks.push(remark.0.get_checks(params)));
        Checks {
            rdap_struct: super::RdapStructure::Remarks,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for NoticeOrRemark {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items: Vec<CheckItem> = vec![];
        if let Some(description) = &self.description {
            if description.is_string() {
                items.push(Check::NoticeOrRemarkDescriptionIsString.check_item())
            }
        } else {
            items.push(Check::NoticeOrRemarkDescriptionIsAbsent.check_item())
        };
        let mut sub_checks: Vec<Checks> = vec![];
        if let Some(links) = &self.links {
            links.iter().for_each(|link| {
                sub_checks.push(link.get_checks(params.from_parent(TypeId::of::<NoticeOrRemark>())))
            });
        };
        // TODO checks on 'type'
        Checks {
            rdap_struct: super::RdapStructure::NoticeOrRemark,
            items,
            sub_checks,
        }
    }
}

impl GetChecks for PublicIds {
    fn get_checks(&self, _params: CheckParams) -> Checks {
        let mut items: Vec<CheckItem> = vec![];
        self.iter().for_each(|pid| {
            if let Some(id_type) = &pid.id_type {
                if id_type.is_number() || id_type.is_bool() {
                    items.push(Check::PublicIdTypeIsNotString.check_item());
                }
            } else {
                items.push(Check::PublicIdTypeIsAbsent.check_item());
            }
            if let Some(identifier) = &pid.identifier {
                if identifier.is_number() || identifier.is_bool() {
                    items.push(Check::PublicIdIdentifierIsNotString.check_item());
                }
            } else {
                items.push(Check::PublicIdIdentifierIsAbsent.check_item());
            }
        });
        Checks {
            rdap_struct: super::RdapStructure::PublidIds,
            items,
            sub_checks: vec![],
        }
    }
}

impl GetChecks for Common {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items: Vec<CheckItem> = vec![];
        let mut sub_checks: Vec<Checks> = vec![];
        if let Some(rdap_conformance) = &self.rdap_conformance {
            sub_checks.push(rdap_conformance.get_checks(params))
        };
        if let Some(notices) = &self.notices {
            sub_checks.push(notices.get_checks(params))
        };
        if params.parent_type == params.root.get_type() && self.rdap_conformance.is_none() {
            items.push(Check::RdapConformanceMissing.check_item());
        }
        Checks {
            rdap_struct: super::RdapStructure::RdapConformance,
            items,
            sub_checks,
        }
    }
}

impl GetSubChecks for ObjectCommon {
    fn get_sub_checks(&self, params: CheckParams) -> Vec<Checks> {
        let mut sub_checks: Vec<Checks> = vec![];

        // entities
        if let Some(entities) = &self.entities {
            entities
                .iter()
                .for_each(|e| sub_checks.push(e.get_checks(params)))
        };

        // links
        if let Some(links) = &self.links {
            sub_checks.push(links.get_checks(params));
        } else if params.root.get_type() != TypeId::of::<Nameserver>()
            && params.parent_type != TypeId::of::<Nameserver>()
        // because some registries do not model nameservers directly,
        // they can be embedded in other objects but aren't first class
        // objects themself (see RIR example in RFC 9083). Therefore,
        // it only matters that a nameserver has no self link if it is
        // the top most object (i.e. a first class object).
        {
            sub_checks.push(Checks {
                rdap_struct: super::RdapStructure::Links,
                items: vec![Check::LinkObjectClassHasNoSelf.check_item()],
                sub_checks: vec![],
            })
        };

        // remarks
        if let Some(remarks) = &self.remarks {
            sub_checks.push(remarks.get_checks(params))
        };

        // events
        if let Some(events) = &self.events {
            events.iter().for_each(|e| {
                if let Some(date) = &e.event_date {
                    let date = DateTime::parse_from_rfc3339(date);
                    if date.is_err() {
                        sub_checks.push(Checks {
                            rdap_struct: super::RdapStructure::Events,
                            items: vec![Check::EventDateIsNotRfc3339.check_item()],
                            sub_checks: vec![],
                        })
                    }
                } else {
                    sub_checks.push(Checks {
                        rdap_struct: super::RdapStructure::Events,
                        items: vec![Check::EventDateIsAbsent.check_item()],
                        sub_checks: vec![],
                    })
                }
                if e.event_action.is_none() {
                    sub_checks.push(Checks {
                        rdap_struct: super::RdapStructure::Events,
                        items: vec![Check::EventActionIsAbsent.check_item()],
                        sub_checks: vec![],
                    })
                }
            });
        }

        // handle
        if let Some(handle) = &self.handle {
            if handle.is_whitespace_or_empty() {
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::Handle,
                    items: vec![Check::HandleIsEmpty.check_item()],
                    sub_checks: vec![],
                })
            }
            if handle.is_number() || handle.is_bool() {
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::Handle,
                    items: vec![Check::HandleIsNotString.check_item()],
                    sub_checks: vec![],
                })
            }
        }

        // Status
        if let Some(status) = &self.status {
            // TODO add check for status is string
            let status = status.vec();
            if status.is_empty_or_any_empty_or_whitespace() {
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::Status,
                    items: vec![Check::StatusIsEmpty.check_item()],
                    sub_checks: vec![],
                })
            }
        }

        // Port 43
        if let Some(port43) = &self.port_43 {
            if port43.is_whitespace_or_empty() {
                sub_checks.push(Checks {
                    rdap_struct: super::RdapStructure::Port43,
                    items: vec![Check::Port43IsEmpty.check_item()],
                    sub_checks: vec![],
                })
            }
        }

        sub_checks
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use rstest::rstest;

    use crate::{
        check::{contains_check, Checks},
        media_types::RDAP_MEDIA_TYPE,
        prelude::{ToResponse, VectorStringish},
        response::{
            domain::Domain,
            nameserver::Nameserver,
            types::{Event, Link, Notice, NoticeOrRemark, PublicId, Remark},
            RdapResponse,
        },
    };

    use crate::check::{Check, CheckParams, GetChecks};

    #[test]
    fn check_link_with_no_rel_property() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::illegal()
                    .href("https://foo")
                    .value("https://foo")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkMissingRelProperty)
            .expect("link rel missing check");
    }

    #[test]
    fn check_link_with_no_val_property() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(Link::illegal().href("https://foo").rel("about").build())
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkMissingValueProperty)
            .expect("link missing check");
    }

    #[test]
    fn check_link_with_no_href_property() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(Link::illegal().value("https://foo").rel("about").build())
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkMissingHrefProperty)
            .expect("link missing check");
    }

    #[test]
    fn test_related_link_with_no_type_property() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("related")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkRelatedHasNoType)
            .expect("link missing check");
    }

    #[test]
    fn test_object_related_link_with_non_rdap_type() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("related")
                    .media_type("foo")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkRelatedIsNotRdap)
            .expect("link missing check");
    }

    #[test]
    fn test_object_related_link_with_not_rdap_path() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("related")
                    .media_type(RDAP_MEDIA_TYPE)
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkRelatedNotToRdap)
            .expect("link missing check");
    }

    #[test]
    fn test_self_link_with_no_type_property() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("self")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkSelfHasNoType)
            .expect("link missing check");
    }

    #[test]
    fn test_self_link_with_non_rdap_type() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("self")
                    .media_type("foo")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(find_any_check(&checks, Check::LinkSelfIsNotRdap));
    }

    #[test]
    fn test_domain_with_self_link() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("self")
                    .media_type("application/rdap+json")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(!find_any_check(&checks, Check::LinkObjectClassHasNoSelf));
    }

    #[test]
    fn test_nameserver_with_self_link() {
        // GIVEN
        let rdap = Nameserver::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("self")
                    .media_type("application/rdap+json")
                    .build(),
            )
            .build()
            .expect("unable to build nameserver")
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(!find_any_check(&checks, Check::LinkObjectClassHasNoSelf));
    }

    #[test]
    /// Issue #59
    fn test_nameserver_with_self_link_and_notice() {
        // GIVEN
        let rdap = Nameserver::response_obj()
            .ldh_name("example.com")
            .notice(Notice(
                NoticeOrRemark::builder()
                    .description_entry("a notice")
                    .link(
                        Link::builder()
                            .href("https://tos")
                            .value("https://tos")
                            .rel("terms-of-service")
                            .media_type("text/html")
                            .build(),
                    )
                    .build(),
            ))
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("self")
                    .media_type("application/rdap+json")
                    .build(),
            )
            .build()
            .expect("build nameserver")
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(!find_any_check(&checks, Check::LinkObjectClassHasNoSelf));
    }

    #[test]
    /// Issue #59
    fn test_nameserver_with_self_link_and_remark() {
        // GIVEN
        let rdap = Nameserver::builder()
            .ldh_name("exapmle.com")
            .remark(Remark(
                NoticeOrRemark::builder()
                    .description_entry("a notice")
                    .links(vec![Link::builder()
                        .href("https://tos")
                        .value("https://tos")
                        .rel("terms-of-service")
                        .media_type("text/html")
                        .build()])
                    .build(),
            ))
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("self")
                    .media_type("application/rdap+json")
                    .build(),
            )
            .build()
            .expect("building nameserver")
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(!find_any_check(&checks, Check::LinkObjectClassHasNoSelf));
    }

    #[test]
    fn test_domain_with_no_self_link() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("no_self")
                    .media_type("foo")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .sub(crate::check::RdapStructure::Link)
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkObjectClassHasNoSelf)
            .expect("link missing check");
    }

    #[test]
    fn test_domain_with_no_links() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&rdap);
        checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkObjectClassHasNoSelf)
            .expect("link missing check");
    }

    #[test]
    fn test_event_with_no_date() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .event(Event::illegal().event_action("foo").build())
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Events)
            .expect("Events not found")
            .items
            .iter()
            .find(|c| c.check == Check::EventDateIsAbsent)
            .expect("event missing check");
    }

    #[test]
    fn test_event_with_no_action() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .event(Event::illegal().event_date("1990-12-31T23:59:59Z").build())
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Events)
            .expect("Events not found")
            .items
            .iter()
            .find(|c| c.check == Check::EventActionIsAbsent)
            .expect("event missing check");
    }

    #[test]
    fn test_event_with_bad_date() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .event(
                Event::builder()
                    .event_action("foo")
                    .event_date("bar")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::Events)
            .expect("Events not found")
            .items
            .iter()
            .find(|c| c.check == Check::EventDateIsNotRfc3339)
            .expect("event missing check");
    }

    #[test]
    fn test_public_id_with_no_type() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .public_id(PublicId::illegal().identifier("thing").build())
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::PublidIds)
            .expect("Public Ids not found")
            .items
            .iter()
            .find(|c| c.check == Check::PublicIdTypeIsAbsent)
            .expect("public id missing check");
    }

    #[test]
    fn test_public_id_with_non_string_public_id_type() {
        // GIVEN
        let json = r#"
            {
              "objectClassName" : "domain",
              "ldhName" : "ns1.example.com",
              "publicIds": [
                {
                  "type": 1,
                  "identifier": "1"           
                }
              ]
            }
        "#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks
            .sub(crate::check::RdapStructure::PublidIds)
            .expect("public ids not found")
            .items
            .iter()
            .any(|c| c.check == Check::PublicIdTypeIsNotString));
    }

    #[test]
    fn test_public_id_with_non_string_identifier() {
        // GIVEN
        let json = r#"
            {
              "objectClassName" : "domain",
              "handle" : "XXXX",
              "ldhName" : "xn--fo-5ja.example",
              "publicIds": [
                {
                    "type": "thing",
                    "identifier": 1234
                }
              ]
            }
        "#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks
            .sub(crate::check::RdapStructure::PublidIds)
            .expect("Public Ids not found")
            .items
            .iter()
            .any(|c| c.check == Check::PublicIdIdentifierIsNotString));
    }

    #[test]
    fn test_public_id_with_no_identifier() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .public_id(PublicId::illegal().id_type("thing").build())
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        checks
            .sub(crate::check::RdapStructure::PublidIds)
            .expect("Public Ids not found")
            .items
            .iter()
            .find(|c| c.check == Check::PublicIdIdentifierIsAbsent)
            .expect("public id missing check");
    }

    #[test]
    fn test_notice_with_no_description() {
        // GIVEN
        let notice = NoticeOrRemark {
            title: None,
            description: None,
            links: None,
            nr_type: None,
        };
        let rdap = Domain::response_obj()
            .ldh_name("example.com")
            .notice(Notice(notice))
            .build()
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(contains_check(
            Check::NoticeOrRemarkDescriptionIsAbsent,
            &checks
        ));
    }

    #[test]
    fn test_nameserver_with_no_links() {
        // GIVEN
        let rdap = Nameserver::builder()
            .ldh_name("example.com")
            .build()
            .expect("building nameserver")
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks.sub(crate::check::RdapStructure::Links).is_none());
    }

    #[test]
    fn test_nameserver_with_no_self_links() {
        // GIVEN
        let rdap = Nameserver::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .href("https://foo")
                    .value("https://foo")
                    .rel("no_self")
                    .media_type("foo")
                    .build(),
            )
            .build()
            .expect("building nameserver")
            .to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(!checks
            .sub(crate::check::RdapStructure::Links)
            .expect("Links not found")
            .items
            .iter()
            .any(|c| c.check == Check::LinkObjectClassHasNoSelf));
    }

    #[rstest]
    #[case(vec![])]
    #[case(vec!["".to_string()])]
    #[case(vec!["  ".to_string()])]
    #[case(vec!["  ".to_string(), "foo".to_string()])]
    #[test]
    fn test_nameserver_with_empty_status(#[case] status: Vec<String>) {
        // GIVEN

        let mut ns = Nameserver::builder()
            .ldh_name("ns1.example.com")
            .build()
            .unwrap();
        ns.object_common.status = Some(VectorStringish::from(status));
        let rdap = ns.to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks
            .sub(crate::check::RdapStructure::Status)
            .expect("status not found")
            .items
            .iter()
            .any(|c| c.check == Check::StatusIsEmpty));
    }

    #[rstest]
    #[case("")]
    #[case("  ")]
    #[test]
    fn test_nameserver_with_empty_handle(#[case] handle: &str) {
        // GIVEN
        let mut ns = Nameserver::builder()
            .ldh_name("ns1.example.com")
            .build()
            .unwrap();
        ns.object_common.handle = Some(handle.to_string().into());
        let rdap = ns.to_response();

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks
            .sub(crate::check::RdapStructure::Handle)
            .expect("handle not found")
            .items
            .iter()
            .any(|c| c.check == Check::HandleIsEmpty));
    }

    #[test]
    fn test_nameserver_with_non_string_handle() {
        // GIVEN
        let json = r#"
            {
              "objectClassName" : "nameserver",
              "ldhName" : "ns1.example.com",
              "handle" : 1234
            }
        "#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        assert!(checks
            .sub(crate::check::RdapStructure::Handle)
            .expect("handle not found")
            .items
            .iter()
            .any(|c| c.check == Check::HandleIsNotString));
    }

    #[test]
    fn test_rdap_conformance_not_in_root() {
        // GIVEN
        let json = r#"
        {
          "rdapConformance": ["rdap_level_0"],
          "objectClassName" : "domain",
          "handle" : "XXXX",
          "ldhName" : "xn--fo-5ja.example",
          "entities" :
          [
            {
              "rdapConformance": ["rdap_level_0"],
              "objectClassName" : "entity",
              "handle" : "XXXX"
            }
          ]
        }            
        "#;
        let rdap = serde_json::from_str::<RdapResponse>(json).expect("parsing JSON");

        // WHEN
        let checks = rdap.get_checks(CheckParams::for_rdap(&rdap));

        // THEN
        dbg!(&checks);
        assert!(contains_check(Check::RdapConformanceInvalidParent, &checks));
    }

    fn find_any_check(checks: &Checks, check_type: Check) -> bool {
        if checks.items.iter().any(|c| c.check == check_type) {
            return true;
        }
        if checks
            .sub_checks
            .iter()
            .any(|c| find_any_check(c, check_type))
        {
            return true;
        }
        false
    }
}

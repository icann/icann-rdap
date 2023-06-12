use std::any::TypeId;

use crate::{
    media_types::RDAP_MEDIA_TYPE,
    response::{
        autnum::Autnum,
        domain::Domain,
        entity::Entity,
        nameserver::Nameserver,
        network::Network,
        types::{
            Common, Link, Links, NoticeOrRemark, Notices, ObjectCommon, RdapConformance, Remarks,
        },
    },
};
use chrono::DateTime;
use lazy_static::lazy_static;

use super::{
    string::{StringCheck, StringListCheck},
    CheckItem, CheckParams, Checks, GetChecks, GetSubChecks,
};

impl GetChecks for RdapConformance {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items = Vec::new();
        if params.parent_type != params.root.get_type() {
            items.push(CheckItem::invalid_rdap_conformance_parent())
        };
        Checks {
            struct_name: "RDAP Conformance",
            items,
            sub_checks: Vec::new(),
        }
    }
}

impl GetChecks for Links {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if params.do_subchecks {
            self.iter()
                .for_each(|link| sub_checks.push(link.get_checks(params)));
        }
        Checks {
            struct_name: "Links",
            items: Vec::new(),
            sub_checks,
        }
    }
}

lazy_static! {
    static ref RELATED_AND_SELF_LINK_PARENTS: Vec<TypeId> = vec![
        TypeId::of::<Domain>(),
        TypeId::of::<Entity>(),
        TypeId::of::<Autnum>(),
        TypeId::of::<Network>(),
    ];
}

impl GetChecks for Link {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items: Vec<CheckItem> = Vec::new();
        if self.value.is_none() {
            items.push(CheckItem::link_missing_value_property())
        };
        if let Some(rel) = &self.rel {
            if rel.eq("related") {
                if let Some(media_type) = &self.media_type {
                    if !media_type.eq(RDAP_MEDIA_TYPE)
                        && RELATED_AND_SELF_LINK_PARENTS.contains(&params.parent_type)
                    {
                        items.push(CheckItem::related_link_is_not_rdap())
                    }
                } else {
                    items.push(CheckItem::related_link_has_no_type())
                }
            } else if rel.eq("self") {
                if let Some(media_type) = &self.media_type {
                    if !media_type.eq(RDAP_MEDIA_TYPE) {
                        items.push(CheckItem::self_link_is_not_rdap())
                    }
                } else {
                    items.push(CheckItem::self_link_has_no_type())
                }
            } else if RELATED_AND_SELF_LINK_PARENTS.contains(&params.parent_type) ||
                // because some registries do not model nameservers directly,
                // they can be embedded in other objects but aren't first class
                // objects themself (see RIR example in RFC 9083). Therefore,
                // it only matters that a nameserver has no self link if it is
                // the top most object (i.e. a first class object).
                params.root.get_type() == TypeId::of::<Nameserver>()
            {
                items.push(CheckItem::object_class_has_no_self_link())
            }
        } else {
            items.push(CheckItem::link_missing_rel_property())
        }
        Checks {
            struct_name: "Link",
            items,
            sub_checks: Vec::new(),
        }
    }
}

impl GetChecks for Notices {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if params.do_subchecks {
            self.iter()
                .for_each(|note| sub_checks.push(note.0.get_checks(params)));
        }
        Checks {
            struct_name: "Notices",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for Remarks {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if params.do_subchecks {
            self.iter()
                .for_each(|remark| sub_checks.push(remark.0.get_checks(params)));
        }
        Checks {
            struct_name: "Remarks",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetChecks for NoticeOrRemark {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if params.do_subchecks {
            if let Some(links) = &self.links {
                links.iter().for_each(|link| {
                    sub_checks
                        .push(link.get_checks(params.from_parent(TypeId::of::<NoticeOrRemark>())))
                });
            };
        };
        Checks {
            struct_name: "Notice/Remark",
            items: Vec::new(),
            sub_checks,
        }
    }
}

impl GetSubChecks for Common {
    fn get_sub_checks(&self, params: CheckParams) -> Vec<Checks> {
        let mut sub_checks: Vec<Checks> = Vec::new();
        if params.do_subchecks {
            if let Some(rdap_conformance) = &self.rdap_conformance {
                sub_checks.push(rdap_conformance.get_checks(params))
            };
            if let Some(notices) = &self.notices {
                sub_checks.push(notices.get_checks(params))
            };
        };
        sub_checks
    }
}

impl GetSubChecks for ObjectCommon {
    fn get_sub_checks(&self, params: CheckParams) -> Vec<Checks> {
        let mut sub_checks: Vec<Checks> = Vec::new();

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
                struct_name: "Links",
                items: vec![CheckItem::object_class_has_no_self_link()],
                sub_checks: Vec::new(),
            })
        };

        // remarks
        if let Some(remarks) = &self.remarks {
            sub_checks.push(remarks.get_checks(params))
        };

        // events
        if let Some(events) = &self.events {
            events.iter().for_each(|e| {
                let date = DateTime::parse_from_rfc3339(&e.event_date);
                if date.is_err() {
                    sub_checks.push(Checks {
                        struct_name: "Links",
                        items: vec![CheckItem::event_date_is_not_rfc3339()],
                        sub_checks: Vec::new(),
                    })
                }
            });
        }

        // handle
        if let Some(handle) = &self.handle {
            if handle.is_whitespace_or_empty() {
                sub_checks.push(Checks {
                    struct_name: "Handle",
                    items: vec![CheckItem::handle_is_empty()],
                    sub_checks: Vec::new(),
                })
            }
        }

        // Status
        if let Some(status) = &self.status {
            let status: Vec<&str> = status.iter().map(|s| s.0.as_str()).collect();
            if status.as_slice().is_empty_or_any_empty_or_whitespace() {
                sub_checks.push(Checks {
                    struct_name: "Status",
                    items: vec![CheckItem::status_is_empty()],
                    sub_checks: Vec::new(),
                })
            }
        }

        // TODO get port43
        sub_checks
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::response::{
        domain::Domain,
        entity::Entity,
        nameserver::Nameserver,
        types::{Common, Extension, Link, ObjectCommon},
        RdapResponse,
    };

    use crate::check::{Check, CheckParams, GetChecks};

    #[test]
    fn GIVEN_link_with_no_rel_property_WHEN_checked_THEN_link_missing_rel_property() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .links(vec![Link::builder().href("https://foo").build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .sub("Link")
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkMissingRelProperty)
            .expect("link rel missing check");
    }

    #[test]
    fn GIVEN_link_with_no_val_property_WHEN_checked_THEN_link_missing_val_property() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .links(vec![Link::builder().href("https://foo").build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .sub("Link")
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::LinkMissingValueProperty)
            .expect("link missing check");
    }

    #[test]
    fn GIVEN_related_link_with_no_type_property_WHEN_checked_THEN_related_link_has_no_type() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .links(vec![Link::builder()
                            .href("https://foo")
                            .rel("related")
                            .build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .sub("Link")
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::RelatedLinkHasNoType)
            .expect("link missing check");
    }

    #[test]
    fn GIVEN_object_related_link_with_non_rdap_type_WHEN_checked_THEN_related_link_not_rdap() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .links(vec![Link::builder()
                            .href("https://foo")
                            .rel("related")
                            .media_type("foo")
                            .build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .sub("Link")
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::RelatedLinkIsNotRdap)
            .expect("link missing check");
    }

    #[test]
    fn GIVEN_self_link_with_no_type_property_WHEN_checked_THEN_self_link_has_no_type() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .links(vec![Link::builder()
                            .href("https://foo")
                            .rel("self")
                            .build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .sub("Link")
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::SelfLinkHasNoType)
            .expect("link missing check");
    }

    #[test]
    fn GIVEN_self_link_with_non_rdap_type_WHEN_checked_THEN_self_link_not_rdap() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .links(vec![Link::builder()
                            .href("https://foo")
                            .rel("self")
                            .media_type("foo")
                            .build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .sub("Link")
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::SelfLinkIsNotRdap)
            .expect("link missing check");
    }

    #[test]
    fn GIVEN_domain_with_no_self_link_WHEN_checked_THEN_object_classes_should_have_self_link() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .links(vec![Link::builder()
                            .href("https://foo")
                            .rel("no_self")
                            .media_type("foo")
                            .build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .sub("Link")
            .expect("Link not found")
            .items
            .iter()
            .find(|c| c.check == Check::ObjectClassHasNoSelfLink)
            .expect("link missing check");
    }

    #[test]
    fn GIVEN_domain_with_no_links_WHEN_checked_THEN_object_classes_should_have_self_link() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(Common::builder().build())
                .object_common(ObjectCommon::builder().object_class_name("domain").build())
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Links")
            .expect("Links not found")
            .items
            .iter()
            .find(|c| c.check == Check::ObjectClassHasNoSelfLink)
            .expect("link missing check");
    }

    #[test]
    fn GIVEN_nameserver_with_no_links_WHEN_checked_THEN_no_object_classes_should_have_self_link() {
        // GIVEN
        let rdap = RdapResponse::Nameserver(
            Nameserver::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("nameserver")
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        assert!(checks.sub("Links").is_none());
    }

    #[test]
    fn GIVEN_nameserver_with_no_self_links_WHEN_checked_THEN_no_object_classes_should_have_self_link(
    ) {
        // GIVEN
        let rdap = RdapResponse::Nameserver(
            Nameserver::builder()
                .common(Common::builder().build())
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("nameserver")
                        .links(vec![Link::builder()
                            .href("https://foo")
                            .rel("no_self")
                            .media_type("foo")
                            .build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        assert!(!checks
            .sub("Links")
            .expect("Links not found")
            .items
            .iter()
            .any(|c| c.check == Check::ObjectClassHasNoSelfLink));
    }

    #[test]
    fn GIVEN_rdap_conformance_not_in_root_WHEN_checked_THEN_invalid_rdap_conformance_parent() {
        // GIVEN
        let rdap = RdapResponse::Domain(
            Domain::builder()
                .common(
                    Common::builder()
                        .rdap_conformance(vec![Extension("foo".to_string())])
                        .build(),
                )
                .object_common(
                    ObjectCommon::builder()
                        .object_class_name("domain")
                        .entities(vec![Entity::builder()
                            .common(
                                Common::builder()
                                    .rdap_conformance(vec![Extension("foo".to_string())])
                                    .build(),
                            )
                            .object_common(
                                ObjectCommon::builder().object_class_name("entity").build(),
                            )
                            .build()])
                        .build(),
                )
                .build(),
        );

        // WHEN
        let checks = rdap.get_checks(CheckParams {
            do_subchecks: true,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        checks
            .sub("Entity")
            .expect("entity not found")
            .sub("RDAP Conformance")
            .expect("rdap conformance not found")
            .items
            .iter()
            .find(|c| c.check == Check::InvalidRdapConformanceParent)
            .expect("check missing");
    }
}

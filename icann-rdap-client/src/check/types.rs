use std::any::TypeId;

use icann_rdap_common::{
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
use lazy_static::lazy_static;

use super::{Check, CheckClass, CheckItem, CheckParams, Checks, GetChecks, GetSubChecks};

impl GetChecks for RdapConformance {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items = Vec::new();
        if let Some(parent_type) = params.parent_type {
            if parent_type != params.root.get_type() {
                items.push(CheckItem {
                    check_class: CheckClass::SpecificationError,
                    check: Check::InvalidRdapConformanceParent,
                })
            };
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
    static ref RELATED_LINK_PARENTS: Vec<TypeId> = vec![
        TypeId::of::<Domain>(),
        TypeId::of::<Entity>(),
        TypeId::of::<Autnum>(),
        TypeId::of::<Network>(),
        TypeId::of::<Nameserver>(),
    ];
}

impl GetChecks for Link {
    fn get_checks(&self, params: CheckParams) -> Checks {
        let mut items: Vec<CheckItem> = Vec::new();
        if self.value.is_none() {
            items.push(CheckItem {
                check_class: CheckClass::SpecificationError,
                check: Check::LinkMissingValueProperty,
            })
        };
        if let Some(rel) = &self.rel {
            if rel.eq_ignore_ascii_case("related") {
                if let Some(media_type) = &self.media_type {
                    if !media_type.eq_ignore_ascii_case(RDAP_MEDIA_TYPE) {
                        if let Some(parent_type) = params.parent_type {
                            if RELATED_LINK_PARENTS.contains(&parent_type) {
                                items.push(CheckItem {
                                    check_class: CheckClass::SpecificationWarning,
                                    check: Check::RelatedLinkIsNotRdap,
                                })
                            }
                        }
                    }
                } else {
                    items.push(CheckItem {
                        check_class: CheckClass::SpecificationWarning,
                        check: Check::RelatedLinkHasNoType,
                    })
                }
            }
        } else {
            items.push(CheckItem {
                check_class: CheckClass::SpecificationError,
                check: Check::LinkMissingRelProperty,
            })
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
        if let Some(entities) = &self.entities {
            entities
                .iter()
                .for_each(|e| sub_checks.push(e.get_checks(params)))
        };
        if let Some(links) = &self.links {
            sub_checks.push(links.get_checks(params));
        };
        if let Some(remarks) = &self.remarks {
            sub_checks.push(remarks.get_checks(params))
        };
        // TODO get handle
        // TODO get events
        // TODO get status
        // TODO get port43
        sub_checks
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::response::{
        domain::Domain,
        entity::Entity,
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
            parent_type: Some(rdap.get_type()),
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
            parent_type: Some(rdap.get_type()),
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
            parent_type: Some(rdap.get_type()),
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
            parent_type: Some(rdap.get_type()),
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
            parent_type: Some(rdap.get_type()),
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

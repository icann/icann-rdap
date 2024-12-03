use crate::{httpdata::HttpData, media_types::RDAP_MEDIA_TYPE, response::types::ExtensionId};

use super::{Check, Checks, GetChecks};

impl GetChecks for HttpData {
    fn get_checks(&self, params: crate::check::CheckParams) -> crate::check::Checks {
        let mut items = Vec::new();

        // RFC checks
        if let Some(allow_origin) = &self.access_control_allow_origin {
            if !allow_origin.eq("*") {
                items.push(Check::CorsAllowOriginStarRecommended.check_item())
            }
        } else {
            items.push(Check::CorsAllowOriginRecommended.check_item())
        }
        if self.access_control_allow_credentials.is_some() {
            items.push(Check::CorsAllowCredentialsNotRecommended.check_item())
        }
        if let Some(content_type) = &self.content_type {
            if !content_type.eq(RDAP_MEDIA_TYPE) {
                items.push(Check::ContentTypeIsNotRdap.check_item());
            }
        } else {
            items.push(Check::ContentTypeIsAbsent.check_item());
        }

        // checks for ICANN profile
        if params
            .root
            .has_extension(ExtensionId::IcannRdapTechnicalImplementationGuide0)
            || params
                .root
                .has_extension(ExtensionId::IcannRdapTechnicalImplementationGuide1)
        {
            if let Some(scheme) = &self.scheme {
                if !scheme.eq_ignore_ascii_case("HTTPS") {
                    items.push(Check::MustUseHttps.check_item());
                }
            } else {
                items.push(Check::MustUseHttps.check_item());
            }
            if let Some(allow_origin) = &self.access_control_allow_origin {
                if !allow_origin.eq("*") {
                    items.push(Check::AllowOriginNotStar.check_item())
                }
            } else {
                items.push(Check::AllowOriginNotStar.check_item())
            }
        }

        Checks {
            struct_name: "HttpData",
            items,
            sub_checks: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::{
        check::{Check, CheckParams, GetChecks},
        httpdata::HttpData,
        response::{
            domain::Domain,
            types::{Common, ExtensionId, ObjectCommon},
            RdapResponse,
        },
    };

    #[test]
    fn GIVEN_icann_tig_with_cors_star_WHEN_get_checks_THEN_no_check() {
        // GIVEN
        let domain = Domain {
            common: Common::level0_with_options()
                .extension(ExtensionId::IcannRdapTechnicalImplementationGuide0.to_extension())
                .build(),
            object_common: ObjectCommon::domain().build(),
            ldh_name: Some("foo.example".to_string()),
            unicode_name: None,
            variants: None,
            secure_dns: None,
            nameservers: None,
            public_ids: None,
            network: None,
        };
        let rdap = RdapResponse::Domain(domain);
        let http_data = HttpData::example().access_control_allow_origin("*").build();

        // WHEN
        let checks = http_data.get_checks(CheckParams {
            do_subchecks: false,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        assert!(!checks
            .items
            .iter()
            .any(|c| c.check == Check::AllowOriginNotStar));
    }

    #[test]
    fn GIVEN_icann_tig_with_cors_not_star_WHEN_get_checks_THEN_cors_check() {
        // GIVEN
        let domain = Domain {
            common: Common::level0_with_options()
                .extension(ExtensionId::IcannRdapTechnicalImplementationGuide0.to_extension())
                .build(),
            object_common: ObjectCommon::domain().build(),
            ldh_name: Some("foo.example".to_string()),
            unicode_name: None,
            variants: None,
            secure_dns: None,
            nameservers: None,
            public_ids: None,
            network: None,
        };
        let rdap = RdapResponse::Domain(domain);
        let http_data = HttpData::example()
            .access_control_allow_origin("foo")
            .build();

        // WHEN
        let checks = http_data.get_checks(CheckParams {
            do_subchecks: false,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::AllowOriginNotStar));
    }

    #[test]
    fn GIVEN_icann_tig_without_WHEN_get_checks_THEN_cors_check() {
        // GIVEN
        let domain = Domain {
            common: Common::level0_with_options()
                .extension(ExtensionId::IcannRdapTechnicalImplementationGuide0.to_extension())
                .build(),
            object_common: ObjectCommon::domain().build(),
            ldh_name: Some("foo.example".to_string()),
            unicode_name: None,
            variants: None,
            secure_dns: None,
            nameservers: None,
            public_ids: None,
            network: None,
        };
        let rdap = RdapResponse::Domain(domain);
        let http_data = HttpData::example().build();

        // WHEN
        let checks = http_data.get_checks(CheckParams {
            do_subchecks: false,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::AllowOriginNotStar));
    }

    #[test]
    fn GIVEN_icann_tig_with_https_WHEN_get_checks_THEN_no_check() {
        // GIVEN
        let domain = Domain {
            common: Common::level0_with_options()
                .extension(ExtensionId::IcannRdapTechnicalImplementationGuide0.to_extension())
                .build(),
            object_common: ObjectCommon::domain().build(),
            ldh_name: Some("foo.example".to_string()),
            unicode_name: None,
            variants: None,
            secure_dns: None,
            nameservers: None,
            public_ids: None,
            network: None,
        };
        let rdap = RdapResponse::Domain(domain);
        let http_data = HttpData::now().scheme("https").host("example.com").build();

        // WHEN
        let checks = http_data.get_checks(CheckParams {
            do_subchecks: false,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        assert!(!checks.items.iter().any(|c| c.check == Check::MustUseHttps));
    }

    #[test]
    fn GIVEN_icann_tig_with_http_WHEN_get_checks_THEN_must_use_https_check() {
        // GIVEN
        let domain = Domain {
            common: Common::level0_with_options()
                .extension(ExtensionId::IcannRdapTechnicalImplementationGuide0.to_extension())
                .build(),
            object_common: ObjectCommon::domain().build(),
            ldh_name: Some("foo.example".to_string()),
            unicode_name: None,
            variants: None,
            secure_dns: None,
            nameservers: None,
            public_ids: None,
            network: None,
        };
        let rdap = RdapResponse::Domain(domain);
        let http_data = HttpData::now().scheme("http").host("example.com").build();

        // WHEN
        let checks = http_data.get_checks(CheckParams {
            do_subchecks: false,
            root: &rdap,
            parent_type: rdap.get_type(),
        });

        // THEN
        assert!(checks.items.iter().any(|c| c.check == Check::MustUseHttps));
    }
}

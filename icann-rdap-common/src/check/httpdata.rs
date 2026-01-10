use crate::{httpdata::HttpData, media_types::RDAP_MEDIA_TYPE, prelude::ExtensionId};

use super::{Check, Checks, GetChecks};

impl GetChecks for HttpData {
    fn get_checks(
        &self,
        index: Option<usize>,
        params: crate::check::CheckParams,
    ) -> crate::check::Checks {
        let mut items = vec![];

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
            if !content_type.starts_with(RDAP_MEDIA_TYPE) {
                items.push(Check::ContentTypeIsNotRdap.check_item());
            }
        } else {
            items.push(Check::ContentTypeIsAbsent.check_item());
        }

        // checks for Gtld profile
        if params
            .root
            .has_extension_id(ExtensionId::IcannRdapTechnicalImplementationGuide0)
            || params
                .root
                .has_extension_id(ExtensionId::IcannRdapTechnicalImplementationGuide1)
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
            rdap_struct: super::RdapStructure::HttpData,
            index,
            items,
            sub_checks: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        check::{Check, CheckParams, GetChecks},
        httpdata::HttpData,
        media_types::{JSON_MEDIA_TYPE, RDAP_MEDIA_TYPE},
        prelude::{Common, ExtensionId, ObjectCommon, ToResponse},
        response::domain::Domain,
    };

    #[test]
    fn check_not_rdap_media() {
        // GIVEN an rdap response
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN httpdata with content type that is not RDAP media type
        let http_data = HttpData::example().content_type(JSON_MEDIA_TYPE).build();

        // WHEN checks are run
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN incorrect media type check is found
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::ContentTypeIsNotRdap));
    }

    #[test]
    fn check_exactly_rdap_media() {
        // GIVEN an rdap response
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN httpdata with content type that is not RDAP media type
        let http_data = HttpData::example().content_type(RDAP_MEDIA_TYPE).build();

        // WHEN checks are run
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN incorrect media type check is not found
        assert!(!checks
            .items
            .iter()
            .any(|c| c.check == Check::ContentTypeIsNotRdap));
    }

    #[test]
    fn check_rdap_media_with_charset_parameter() {
        // GIVEN an rdap response
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN httpdata with content type that is not RDAP media type with charset parameter
        let mt = format!("{RDAP_MEDIA_TYPE};charset=UTF-8");
        let http_data = HttpData::example().content_type(mt).build();

        // WHEN checks are run
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN incorrect media type check is not found
        assert!(!checks
            .items
            .iter()
            .any(|c| c.check == Check::ContentTypeIsNotRdap));
    }

    #[test]
    fn check_media_type_absent() {
        // GIVEN an rdap response
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN httpdata no content type
        let http_data = HttpData::example().build();

        // WHEN checks are run
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN no media type check is found
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::ContentTypeIsAbsent));
    }

    #[test]
    fn check_cors_header_with_tig() {
        // GIVEN a response with gtld tig
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN a cors header with *
        let http_data = HttpData::example().access_control_allow_origin("*").build();

        // WHEN running checks
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN no check is given
        assert!(!checks
            .items
            .iter()
            .any(|c| c.check == Check::AllowOriginNotStar));
    }

    #[test]
    fn check_cors_header_with_foo_and_tig() {
        // GIVEN a response with gtld tig extension
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN response with cors header of "foo" (not "*")
        let http_data = HttpData::example()
            .access_control_allow_origin("foo")
            .build();

        // WHEN running checks
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN the check is found
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::AllowOriginNotStar));
    }

    #[test]
    fn check_no_cors_header_and_tig() {
        // GIVEN domain response with gtld tig extension id
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN a response with no cors header
        let http_data = HttpData::example().build();

        // WHEN running checks
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN check for missing cors is found
        dbg!(&checks);
        assert!(checks
            .items
            .iter()
            .any(|c| c.check == Check::AllowOriginNotStar));
    }

    #[test]
    fn given_response_is_over_https_and_tig() {
        // GIVEN response with gtld tig extension
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN response is over https
        let http_data = HttpData::now().scheme("https").host("example.com").build();

        // WHEN running checks
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN then check for must use https is not present
        assert!(!checks.items.iter().any(|c| c.check == Check::MustUseHttps));
    }

    #[test]
    fn response_over_htttp_and_tig() {
        // GIVEN domain response with gtld tig extension
        let domain = Domain {
            common: Common::level0()
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
        let rdap = domain.to_response();

        // and GIVEN response is with http (not https)
        let http_data = HttpData::now().scheme("http").host("example.com").build();

        // WHEN running checks
        let checks = http_data.get_checks(None, CheckParams::for_rdap(&rdap));

        // THEN check for must use https is found
        assert!(checks.items.iter().any(|c| c.check == Check::MustUseHttps));
    }
}

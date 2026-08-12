use std::any::TypeId;

use crate::response::rpki::{
    Rpk1Aspa, Rpk1AspaSearchResults, Rpk1Roa, Rpk1RoaSearchResults, Rpk1RpkiType,
    Rpk1X509ResourceCert, Rpk1X509ResourceCertSearchResults,
};

use super::{Check, CheckParams, Checks, GetChecks, GetGroupChecks, RdapStructure};

impl GetChecks for Rpk1Roa {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> Checks {
        let sub_checks = {
            let mut sub_checks: Vec<Checks> = vec![];
            sub_checks.append(&mut GetGroupChecks::get_group_checks(
                &self.common,
                params.from_parent(TypeId::of::<Self>()),
            ));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_group_checks(params.from_parent(TypeId::of::<Self>())),
            );
            sub_checks
        };

        let mut items = vec![];

        if self.origin_autnum.is_none() {
            items.push(Check::Rpk1RoaOriginAutnumMissing.check_item())
        }

        if self.roa_ips.as_ref().is_none_or(|v| v.is_empty()) {
            items.push(Check::Rpk1RoaIpsIsEmpty.check_item())
        }

        if let Some(rpki_type) = &self.rpki_type {
            let valid = matches!(
                rpki_type,
                Rpk1RpkiType::Hosted | Rpk1RpkiType::Delegated | Rpk1RpkiType::Hybrid
            );
            if !valid {
                items.push(Check::Rpk1RpkiTypeInvalid.check_item())
            }
        }

        Checks {
            rdap_struct: RdapStructure::Rpk1Roa,
            index,
            items,
            sub_checks,
        }
    }
}

impl GetChecks for Rpk1Aspa {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> Checks {
        let sub_checks = {
            let mut sub_checks: Vec<Checks> = vec![];
            sub_checks.append(&mut GetGroupChecks::get_group_checks(
                &self.common,
                params.from_parent(TypeId::of::<Self>()),
            ));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_group_checks(params.from_parent(TypeId::of::<Self>())),
            );
            sub_checks
        };

        let mut items = vec![];

        if self.customer_autnum.is_none() {
            items.push(Check::Rpk1AspaCustomerAutnumMissing.check_item())
        }

        if self.provider_autnums.as_ref().is_none_or(|v| v.is_empty()) {
            items.push(Check::Rpk1AspaProviderAutnumsIsEmpty.check_item())
        }

        if let Some(rpki_type) = &self.rpki_type {
            let valid = matches!(
                rpki_type,
                Rpk1RpkiType::Hosted | Rpk1RpkiType::Delegated | Rpk1RpkiType::Hybrid
            );
            if !valid {
                items.push(Check::Rpk1RpkiTypeInvalid.check_item())
            }
        }

        Checks {
            rdap_struct: RdapStructure::Rpk1Aspa,
            index,
            items,
            sub_checks,
        }
    }
}

impl GetChecks for Rpk1X509ResourceCert {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> Checks {
        let sub_checks = {
            let mut sub_checks: Vec<Checks> = vec![];
            sub_checks.append(&mut GetGroupChecks::get_group_checks(
                &self.common,
                params.from_parent(TypeId::of::<Self>()),
            ));
            sub_checks.append(
                &mut self
                    .object_common
                    .get_group_checks(params.from_parent(TypeId::of::<Self>())),
            );
            sub_checks
        };

        let mut items = vec![];

        if self.serial_number.as_ref().is_none_or(|v| v.is_empty()) {
            items.push(Check::Rpk1X509SerialNumberMissing.check_item())
        }

        if self.issuer.as_ref().is_none_or(|v| v.is_empty()) {
            items.push(Check::Rpk1X509IssuerMissing.check_item())
        }

        if let Some(rpki_type) = &self.rpki_type {
            let valid = matches!(
                rpki_type,
                Rpk1RpkiType::Hosted | Rpk1RpkiType::Delegated | Rpk1RpkiType::Hybrid
            );
            if !valid {
                items.push(Check::Rpk1RpkiTypeInvalid.check_item())
            }
        }

        Checks {
            rdap_struct: RdapStructure::Rpk1X509ResourceCert,
            index,
            items,
            sub_checks,
        }
    }
}

impl GetChecks for Rpk1RoaSearchResults {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = self
            .common
            .get_group_checks(params.from_parent(TypeId::of::<Self>()));
        self.results.iter().enumerate().for_each(|(i, result)| {
            sub_checks.push(result.get_checks(Some(i), params.from_parent(TypeId::of::<Self>())));
        });
        Checks {
            rdap_struct: RdapStructure::Rpk1RoaSearchResults,
            index,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for Rpk1AspaSearchResults {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = self
            .common
            .get_group_checks(params.from_parent(TypeId::of::<Self>()));
        self.results.iter().enumerate().for_each(|(i, result)| {
            sub_checks.push(result.get_checks(Some(i), params.from_parent(TypeId::of::<Self>())));
        });
        Checks {
            rdap_struct: RdapStructure::Rpk1AspaSearchResults,
            index,
            items: vec![],
            sub_checks,
        }
    }
}

impl GetChecks for Rpk1X509ResourceCertSearchResults {
    fn get_checks(&self, index: Option<usize>, params: CheckParams) -> Checks {
        let mut sub_checks: Vec<Checks> = self
            .common
            .get_group_checks(params.from_parent(TypeId::of::<Self>()));
        self.results.iter().enumerate().for_each(|(i, result)| {
            sub_checks.push(result.get_checks(Some(i), params.from_parent(TypeId::of::<Self>())));
        });
        Checks {
            rdap_struct: RdapStructure::Rpk1X509ResourceCertSearchResults,
            index,
            items: vec![],
            sub_checks,
        }
    }
}

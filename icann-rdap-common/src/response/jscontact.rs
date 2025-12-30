//! Useful JSContact Functions

use crate::{
    contact::Contact,
    prelude::{
        Autnum, Domain, DomainSearchResults, Entity, EntitySearchResults, Nameserver,
        NameserverSearchResults, Network, RdapResponse, ToResponse,
    },
};

pub trait JsContactConvert {
    /// Converts an object to JSContact if it has vCard and no JSContact.
    fn to_jscontact(self) -> Self;

    /// Calls [to_jscontact] and the removes vCard.
    fn only_jscontact(self) -> Self;
}

impl JsContactConvert for RdapResponse {
    fn to_jscontact(self) -> Self {
        match self {
            RdapResponse::Entity(entity) => entity.to_jscontact().to_response(),
            RdapResponse::Domain(domain) => domain.to_jscontact().to_response(),
            RdapResponse::Nameserver(nameserver) => nameserver.to_jscontact().to_response(),
            RdapResponse::Autnum(autnum) => autnum.to_jscontact().to_response(),
            RdapResponse::Network(network) => network.to_jscontact().to_response(),
            RdapResponse::DomainSearchResults(domain_search_results) => {
                domain_search_results.to_jscontact().to_response()
            }
            RdapResponse::EntitySearchResults(entity_search_results) => {
                entity_search_results.to_jscontact().to_response()
            }
            RdapResponse::NameserverSearchResults(nameserver_search_results) => {
                nameserver_search_results.to_jscontact().to_response()
            }
            RdapResponse::ErrorResponse(rfc9083_error) => rfc9083_error.to_response(),
            RdapResponse::Help(help) => help.to_response(),
        }
    }

    fn only_jscontact(self) -> Self {
        match self {
            RdapResponse::Entity(entity) => entity.only_jscontact().to_response(),
            RdapResponse::Domain(domain) => domain.only_jscontact().to_response(),
            RdapResponse::Nameserver(nameserver) => nameserver.only_jscontact().to_response(),
            RdapResponse::Autnum(autnum) => autnum.only_jscontact().to_response(),
            RdapResponse::Network(network) => network.only_jscontact().to_response(),
            RdapResponse::DomainSearchResults(domain_search_results) => {
                domain_search_results.only_jscontact().to_response()
            }
            RdapResponse::EntitySearchResults(entity_search_results) => {
                entity_search_results.only_jscontact().to_response()
            }
            RdapResponse::NameserverSearchResults(nameserver_search_results) => {
                nameserver_search_results.only_jscontact().to_response()
            }
            RdapResponse::ErrorResponse(rfc9083_error) => rfc9083_error.to_response(),
            RdapResponse::Help(help) => help.to_response(),
        }
    }
}

impl JsContactConvert for Entity {
    fn to_jscontact(self) -> Self {
        let new_jscontact = if self.jscontact_card.is_none() {
            self.jscontact_card
        } else if let Some(ref vcard_array) = self.vcard_array {
            Contact::from_vcard(vcard_array).map(|contact| contact.to_jscontact())
        } else {
            None
        };
        Self {
            jscontact_card: new_jscontact,
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Entity {
            vcard_array: None,
            ..self.to_jscontact()
        }
    }
}

impl JsContactConvert for Vec<Entity> {
    fn to_jscontact(self) -> Self {
        self.into_iter().map(|e| e.to_jscontact()).collect()
    }

    fn only_jscontact(self) -> Self {
        self.into_iter().map(|e| e.only_jscontact()).collect()
    }
}

impl JsContactConvert for Network {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for Domain {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for Autnum {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for Nameserver {
    fn to_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.to_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            object_common: super::ObjectCommon {
                entities: self.object_common.entities.map(|v| v.only_jscontact()),
                ..self.object_common
            },
            ..self
        }
    }
}

impl JsContactConvert for DomainSearchResults {
    fn to_jscontact(self) -> Self {
        Self {
            results: self.results.into_iter().map(|i| i.to_jscontact()).collect(),
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            results: self
                .results
                .into_iter()
                .map(|i| i.only_jscontact())
                .collect(),
            ..self
        }
    }
}

impl JsContactConvert for NameserverSearchResults {
    fn to_jscontact(self) -> Self {
        Self {
            results: self.results.into_iter().map(|i| i.to_jscontact()).collect(),
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            results: self
                .results
                .into_iter()
                .map(|i| i.only_jscontact())
                .collect(),
            ..self
        }
    }
}

impl JsContactConvert for EntitySearchResults {
    fn to_jscontact(self) -> Self {
        Self {
            results: self.results.into_iter().map(|i| i.to_jscontact()).collect(),
            ..self
        }
    }

    fn only_jscontact(self) -> Self {
        Self {
            results: self
                .results
                .into_iter()
                .map(|i| i.only_jscontact())
                .collect(),
            ..self
        }
    }
}

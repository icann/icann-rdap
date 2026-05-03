//! Simplify redaction of names

use icann_rdap_common::prelude::{redacted::Redacted, Domain, EntityRole};

use crate::rdap::redacted::add_remark;

static REDACTED_STREET: &str = "////REDACTED_STREET////";
static REDACTED_STREET_DESC: &str = "Street redacted.";

static REDACTED_CITY: &str = "////REDACTED_CITY////";
static REDACTED_CITY_DESC: &str = "City redacted.";

static REDACTED_POSTAL_CODE: &str = "////REDACTED_POSTAL_CODE////";
static REDACTED_POSTAL_CODE_DESC: &str = "Postal code redacted.";

pub(crate) fn simplify_registrant_street(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Registrant.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    let mut modified = false;
                    let mut all_addrs = vec![];
                    for addr in contact.postal_addresses().to_vec().iter_mut() {
                        if addr.street_parts.is_none()
                            || addr.street_parts.as_ref().map_or(true, |v| v.is_empty())
                        {
                            addr.street_parts = Some(vec![REDACTED_STREET.to_string()]);
                            modified = true;
                        }
                        all_addrs.push(addr.clone());
                    }
                    contact = contact.with_postal_addresses(all_addrs);
                    for (_lang, localizable) in contact.localizations_iter_mut() {
                        let mut all_addrs = vec![];
                        for addr in localizable.postal_addresses().to_vec().iter_mut() {
                            if addr.street_parts.is_none()
                                || addr.street_parts.as_ref().map_or(true, |v| v.is_empty())
                            {
                                addr.street_parts = Some(vec![REDACTED_STREET.to_string()]);
                                modified = true;
                            }
                            all_addrs.push(addr.clone());
                        }
                        *localizable = localizable.clone().with_postal_addresses(all_addrs);
                    }
                    if modified {
                        entity.object_common.remarks = add_remark(
                            REDACTED_STREET,
                            REDACTED_STREET_DESC,
                            redaction,
                            entity.object_common.remarks.clone(),
                        );
                    }
                    entity.with_contact_if_vcard(&contact);
                    entity.with_contact_if_jscontact(&contact);
                    break; // Only modify first registrant
                }
            }
        }
    }
    domain
}

pub(crate) fn simplify_registrant_city(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Registrant.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    let mut modified = false;
                    let mut all_addrs = vec![];
                    for addr in contact.postal_addresses().to_vec().iter_mut() {
                        if addr.locality.is_none()
                            || addr.locality.as_ref().map_or(true, |s| s.is_empty())
                        {
                            addr.locality = Some(REDACTED_CITY.to_string());
                            modified = true;
                        }
                        all_addrs.push(addr.clone());
                    }
                    contact = contact.with_postal_addresses(all_addrs);
                    for (_lang, localizable) in contact.localizations_iter_mut() {
                        let mut all_addrs = vec![];
                        for addr in localizable.postal_addresses().to_vec().iter_mut() {
                            if addr.locality.is_none()
                                || addr.locality.as_ref().map_or(true, |s| s.is_empty())
                            {
                                addr.locality = Some(REDACTED_CITY.to_string());
                                modified = true;
                            }
                            all_addrs.push(addr.clone());
                        }
                        *localizable = localizable.clone().with_postal_addresses(all_addrs);
                    }
                    if modified {
                        entity.object_common.remarks = add_remark(
                            REDACTED_CITY,
                            REDACTED_CITY_DESC,
                            redaction,
                            entity.object_common.remarks.clone(),
                        );
                    }
                    entity.with_contact_if_vcard(&contact);
                    entity.with_contact_if_jscontact(&contact);
                    break; // Only modify first registrant
                }
            }
        }
    }
    domain
}

pub(crate) fn simplify_registrant_postal_code(
    mut domain: Box<Domain>,
    redaction: &Redacted,
) -> Box<Domain> {
    if let Some(entities) = &mut domain.object_common.entities {
        for entity in entities.iter_mut() {
            if entity.is_entity_role(&EntityRole::Registrant.to_string()) {
                let contact = entity.contact();
                if let Some(mut contact) = contact {
                    let mut modified = false;
                    let mut all_addrs = vec![];
                    for addr in contact.postal_addresses().to_vec().iter_mut() {
                        if addr.postal_code.is_none()
                            || addr.postal_code.as_ref().map_or(true, |s| s.is_empty())
                        {
                            addr.postal_code = Some(REDACTED_POSTAL_CODE.to_string());
                            modified = true;
                        }
                        all_addrs.push(addr.clone());
                    }
                    contact = contact.with_postal_addresses(all_addrs);

                    for (_lang, localizable) in contact.localizations_iter_mut() {
                        let mut all_addrs = vec![];
                        for addr in localizable.postal_addresses().to_vec().iter_mut() {
                            if addr.postal_code.is_none()
                                || addr.postal_code.as_ref().map_or(true, |s| s.is_empty())
                            {
                                addr.postal_code = Some(REDACTED_POSTAL_CODE.to_string());
                                modified = true;
                            }
                            all_addrs.push(addr.clone());
                        }
                        *localizable = localizable.clone().with_postal_addresses(all_addrs);
                    }

                    if modified {
                        entity.object_common.remarks = add_remark(
                            REDACTED_POSTAL_CODE,
                            REDACTED_POSTAL_CODE_DESC,
                            redaction,
                            entity.object_common.remarks.clone(),
                        );
                    }
                    entity.with_contact_if_vcard(&contact);
                    entity.with_contact_if_jscontact(&contact);
                    break; // Only modify first registrant
                }
            }
        }
    }
    domain
}

#[cfg(test)]
mod tests {
    use icann_rdap_common::prelude::{redacted::Name, *};

    use super::*;

    fn get_test_redacted() -> Redacted {
        Redacted::builder()
            .name(Name::builder().type_field("Tech Email").build())
            .build()
    }

    // Tests for simplify_registrant_street
    #[test]
    fn when_street_present_then_no_redaction() {
        // Given
        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .locality("Anytown")
            .postal_code("12345")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_street(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.is_entity_role(&EntityRole::Registrant.to_string()));

        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses.len(), 1);
            let address = &addresses[0];
            assert_eq!(address.street_parts, Some(vec!["123 Main St".to_string()]));
            assert_eq!(address.locality, Some("Anytown".to_string()));
            assert_eq!(address.postal_code, Some("12345".to_string()));
        }

        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn when_street_absent_then_redacts() {
        // Given
        let postal_address = PostalAddress::builder()
            .locality("Anytown")
            .postal_code("12345")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_street(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.is_entity_role(&EntityRole::Registrant.to_string()));

        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses.len(), 1);
            let address = &addresses[0];
            assert_eq!(
                address.street_parts,
                Some(vec![REDACTED_STREET.to_string()])
            );
            assert_eq!(address.locality, Some("Anytown".to_string()));
            assert_eq!(address.postal_code, Some("12345".to_string()));
        }

        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_STREET));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec()[0],
            REDACTED_STREET_DESC
        );
    }

    #[test]
    fn when_multiple_entities_then_only_first_registrant_redacted() {
        // Given
        let registrant_address = PostalAddress::builder().build();

        let registrant_contact = Contact::builder()
            .postal_address(registrant_address)
            .build();

        let registrant = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(registrant_contact)
            .build();

        let admin_address = PostalAddress::builder().street_part("456 Admin St").build();

        let admin_contact = Contact::builder().postal_address(admin_address).build();

        let admin = Entity::builder()
            .handle("test-admin")
            .role("administrative")
            .contact(admin_contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(registrant)
            .entity(admin)
            .build();

        // When
        let result = simplify_registrant_street(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 2);

        // First entity (registrant) should be redacted
        let registrant_entity = &entities[0];
        if let Some(contact) = registrant_entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(
                addresses[0].street_parts,
                Some(vec![REDACTED_STREET.to_string()])
            );
        }

        // Second entity (admin) should remain unchanged
        let admin_entity = &entities[1];
        if let Some(contact) = admin_entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(
                addresses[0].street_parts,
                Some(vec!["456 Admin St".to_string()])
            );
        }
    }

    #[test]
    fn when_no_postal_address_then_skips() {
        // Given
        let contact = Contact::builder().full_name("John Doe").build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_street(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.object_common.remarks.is_none());
    }

    // Tests for simplify_registrant_city
    #[test]
    fn when_city_present_then_no_redaction() {
        // Given
        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .locality("Anytown")
            .postal_code("12345")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_city(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.is_entity_role(&EntityRole::Registrant.to_string()));

        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses.len(), 1);
            let address = &addresses[0];
            assert_eq!(address.street_parts, Some(vec!["123 Main St".to_string()]));
            assert_eq!(address.locality, Some("Anytown".to_string()));
            assert_eq!(address.postal_code, Some("12345".to_string()));
        }

        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn when_city_absent_then_redacts() {
        // Given
        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .postal_code("12345")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_city(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.is_entity_role(&EntityRole::Registrant.to_string()));

        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses.len(), 1);
            let address = &addresses[0];
            assert_eq!(address.street_parts, Some(vec!["123 Main St".to_string()]));
            assert_eq!(address.locality, Some(REDACTED_CITY.to_string()));
            assert_eq!(address.postal_code, Some("12345".to_string()));
        }

        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_CITY));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec()[0],
            REDACTED_CITY_DESC
        );
    }

    #[test]
    fn when_city_absent_then_sets_redacted() {
        // Given
        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .postal_code("12345")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_city(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses[0].locality, Some(REDACTED_CITY.to_string()));
        }

        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert!(remarks[0].has_simple_redaction_key(REDACTED_CITY));
    }

    // Tests for simplify_registrant_postal_code
    #[test]
    fn when_postal_code_present_then_no_redaction() {
        // Given
        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .locality("Anytown")
            .postal_code("12345")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_postal_code(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.is_entity_role(&EntityRole::Registrant.to_string()));

        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses.len(), 1);
            let address = &addresses[0];
            assert_eq!(address.street_parts, Some(vec!["123 Main St".to_string()]));
            assert_eq!(address.locality, Some("Anytown".to_string()));
            assert_eq!(address.postal_code, Some("12345".to_string()));
        }

        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn when_postal_code_absent_then_redacts() {
        // Given
        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .locality("Anytown")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_postal_code(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.is_entity_role(&EntityRole::Registrant.to_string()));

        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses.len(), 1);
            let address = &addresses[0];
            assert_eq!(address.street_parts, Some(vec!["123 Main St".to_string()]));
            assert_eq!(address.locality, Some("Anytown".to_string()));
            assert_eq!(address.postal_code, Some(REDACTED_POSTAL_CODE.to_string()));
        }

        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 1);
        assert!(remarks[0].has_simple_redaction_key(REDACTED_POSTAL_CODE));
        assert_eq!(
            remarks[0].description.as_ref().unwrap().vec()[0],
            REDACTED_POSTAL_CODE_DESC
        );
    }

    #[test]
    fn when_postal_code_absent_then_sets_redacted() {
        // Given
        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .locality("Anytown")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_postal_code(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(
                addresses[0].postal_code,
                Some(REDACTED_POSTAL_CODE.to_string())
            );
        }

        assert!(entity.object_common.remarks.is_some());
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert!(remarks[0].has_simple_redaction_key(REDACTED_POSTAL_CODE));
    }

    // Common edge case tests
    #[test]
    fn when_no_entities_then_unchanged() {
        // Given
        let domain = Domain::builder().ldh_name("example.com").build();

        // When
        let result = simplify_registrant_street(Box::new(domain), &get_test_redacted());

        // Then
        assert!(result.object_common.entities.is_none());
    }

    #[test]
    fn when_non_registrant_then_unchanged() {
        // Given
        let postal_address = PostalAddress::builder().locality("Admin City").build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let admin = Entity::builder()
            .handle("test-admin")
            .role("administrative")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(admin)
            .build();

        // When
        let result = simplify_registrant_city(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses[0].locality, Some("Admin City".to_string()));
        }
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn when_no_contact_then_skips() {
        // Given
        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_postal_code(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];
        assert!(entity.contact().is_none());
        assert!(entity.object_common.remarks.is_none());
    }

    #[test]
    fn when_multiple_addresses_then_all_redacted() {
        // Given
        let address1 = PostalAddress::builder().locality("City1").build();

        let address2 = PostalAddress::builder().locality("City2").build();

        let contact = Contact::builder()
            .postal_address(address1)
            .postal_address(address2)
            .build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_street(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        if let Some(contact) = entity.contact() {
            let addresses = contact.postal_addresses();
            assert_eq!(addresses.len(), 2);
            assert_eq!(
                addresses[0].street_parts,
                Some(vec![REDACTED_STREET.to_string()])
            );
            assert_eq!(
                addresses[1].street_parts,
                Some(vec![REDACTED_STREET.to_string()])
            );
            assert_eq!(addresses[0].locality, Some("City1".to_string()));
            assert_eq!(addresses[1].locality, Some("City2".to_string()));
        }
    }

    #[test]
    fn when_existing_remarks_and_missing_city_then_adds_remark() {
        // Given
        let existing_remark = Remark::builder()
            .title("Existing Remark")
            .description_entry("Existing description")
            .build();

        let postal_address = PostalAddress::builder()
            .street_part("123 Main St")
            .postal_code("12345")
            .build();

        let contact = Contact::builder().postal_address(postal_address).build();

        let entity = Entity::builder()
            .handle("test-registrant")
            .role("registrant")
            .contact(contact)
            .remark(existing_remark)
            .build();

        let domain = Domain::builder()
            .ldh_name("example.com")
            .entity(entity)
            .build();

        // When
        let result = simplify_registrant_city(Box::new(domain), &get_test_redacted());

        // Then
        let entities = result.object_common.entities.as_ref().unwrap();
        let entity = &entities[0];
        let remarks = entity.object_common.remarks.as_ref().unwrap();
        assert_eq!(remarks.len(), 2);

        // First remark should be the existing one
        assert_eq!(remarks[0].title.as_ref().unwrap(), "Existing Remark");

        // Second remark should be the redaction remark
        assert!(remarks[1].has_simple_redaction_key(REDACTED_CITY));
        assert_eq!(
            remarks[1].description.as_ref().unwrap().vec()[0],
            REDACTED_CITY_DESC
        );
    }
}

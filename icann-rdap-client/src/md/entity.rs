use std::any::TypeId;

use icann_rdap_common::response::entity::Entity;

use super::{make_title_case, to_header, MdParams, ToMd};

impl ToMd for Entity {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Entity>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = if let Some(roles) = &self.roles {
            make_title_case(roles.first().unwrap_or(&String::default()))
        } else {
            "Entity".to_string()
        };
        md.push_str(&to_header(
            &header_text,
            params.heading_level,
            params.options,
        ));

        // remarks
        md.push_str(&self.object_common.remarks.to_md(params.from_parent(typeid)));

        // entities
        md.push_str(
            &self
                .object_common
                .entities
                .to_md(params.from_parent(typeid)),
        );

        md.push('\n');
        md
    }
}

impl ToMd for Option<Vec<Entity>> {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        if let Some(entities) = &self {
            entities
                .iter()
                .for_each(|entity| md.push_str(&entity.to_md(params.next_level())));
        }
        md
    }
}

//! Things representing registrations from the IANA RDAP registries.

pub(crate) use strum::Display as EnumDisplay;

pub mod entity_role;
pub mod event_action_value;
pub mod extension_id;
pub mod nr_type;
pub mod status_value;

pub use entity_role::EntityRole;
pub use event_action_value::EventActionValue;
pub use extension_id::ExtensionId;
pub use nr_type::NrType;
pub use status_value::StatusValue;

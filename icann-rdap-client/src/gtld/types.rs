use super::{GtldParams, ToGtldWhois};
use icann_rdap_common::response::types::Common;

impl ToGtldWhois for Common {
    fn to_gtld(&self, _params: &mut GtldParams) -> String {
        String::new()
    }
}

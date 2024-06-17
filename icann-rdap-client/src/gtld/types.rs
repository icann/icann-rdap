use super::{GtldParams, ToGtld};
use icann_rdap_common::response::types::Common;

impl ToGtld for Common {
    fn to_gtld(&self, _params: &mut GtldParams) -> String {
        String::new()
    }
}

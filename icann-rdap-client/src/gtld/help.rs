use super::{GtldParams, ToGtld};
use icann_rdap_common::response::help::Help;

impl ToGtld for Help {
    fn to_gtld(&self, _params: &mut GtldParams) -> String {
        String::new()
    }
}

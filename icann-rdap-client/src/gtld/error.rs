use super::{GtldParams, ToGtld};
use icann_rdap_common::response::error::Error;

impl ToGtld for Error {
    fn to_gtld(&self, _params: &mut GtldParams) -> String {
        String::new()
    }
}

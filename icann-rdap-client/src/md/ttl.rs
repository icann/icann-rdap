//! Display of the TTL0 extension data.

use icann_rdap_common::prelude::ttl::Ttl0Data;

use crate::md::table::ToMpTable;

impl ToMpTable for Ttl0Data {
    fn add_to_mptable(
        &self,
        mut table: super::table::MultiPartTable,
        params: super::MdParams,
    ) -> super::table::MultiPartTable {
        table = table.header_ref(&"TTL Values");
        table = table.and_nv_ref_maybe(&"a", &self.a_value());
        table = table.and_nv_ref_maybe(&"aaaa", &self.aaaa_value());
        table = table.and_nv_ref_maybe(&"ns", &self.ns_value());
        table = table.and_nv_ref_maybe(&"ds", &self.ds_value());
        table = table.and_nv_ref_maybe(&"mx", &self.mx_value());
        table = table.and_nv_ref_maybe(&"ptr", &self.ptr_value());
        table = table.and_nv_ref_maybe(&"cname", &self.cname_value());
        table = table.and_nv_ref_maybe(&"cds", &self.cds_value());
        table = table.and_nv_ref_maybe(&"csync", &self.csync_value());
        table = table.and_nv_ref_maybe(&"caa", &self.caa_value());
        table = table.and_nv_ref_maybe(&"dnskey", &self.dnskey_value());
        table = table.and_nv_ref_maybe(&"cert", &self.cert_value());
        table = table.and_nv_ref_maybe(&"cdnskey", &self.cdnskey_value());
        table = table.and_nv_ref_maybe(&"https", &self.https_value());
        table = table.and_nv_ref_maybe(&"key", &self.key_value());
        table = table.and_nv_ref_maybe(&"naptr", &self.naptr_value());
        table = table.and_nv_ref_maybe(&"srv", &self.srv_value());
        table = table.and_nv_ref_maybe(&"svcb", &self.svcb_value());
        table = table.and_nv_ref_maybe(&"tlsa", &self.tlsa_value());
        table = table.and_nv_ref_maybe(&"txt", &self.txt_value());
        table = table.and_nv_ref_maybe(&"uri", &self.uri_value());
        table = self.remarks().add_to_mptable(table, params);
        table
    }
}

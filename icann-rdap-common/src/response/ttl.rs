//! TTL0 extension.
//!
//! An example of using the builders to create TTLs for
//! a domain:
//!
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//! use icann_rdap_common::response::ttl::Ttl0Data;
//!
//! // Builds TTls.
//! let ttls = Ttl0Data::builder()
//!     .a_value(18640)
//!     .build();
//!
//! // Builds `domain` with ttls.
//! let domain = Domain::builder()
//!     .ldh_name("example.com")
//!     .handle("EXAMPLE-DOMAIN")
//!     .ttl0_data(ttls)
//!     .build();
//! ```
use serde::{Deserialize, Serialize};

use crate::prelude::{to_opt_vec, Remark, Remarks};

/// Represents the TTL values using the "ttl0" extension.
///
/// The following shows how to use the builders to
/// create ttls.
///
/// ```rust
/// use icann_rdap_common::prelude::*;
/// use icann_rdap_common::response::ttl::Ttl0Data;
///
/// // Builds TTls.
/// let ttls = Ttl0Data::builder()
///     .aaaa_value(18640)
///     .build();
///
/// // Builds `nameserver` with ttls.
/// let domain = Nameserver::builder()
///     .ldh_name("example.com")
///     .handle("EXAMPLE-DOMAIN")
///     .ttl0_data(ttls)
///     .build();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Ttl0Data {
    /// The TTL values.
    pub values: Values,

    /// Remarks about the TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remarks: Option<Remarks>,
}

#[buildstructor::buildstructor]
impl Ttl0Data {
    /// Builder for `ttl0_data`.
    #[builder(visibility = "pub")]
    fn new(
        ns_value: Option<u32>,
        ds_value: Option<u32>,
        a_value: Option<u32>,
        aaaa_value: Option<u32>,
        mx_value: Option<u32>,
        ptr_value: Option<u32>,
        cname_value: Option<u32>,
        cds_value: Option<u32>,
        csync_value: Option<u32>,
        caa_value: Option<u32>,
        dnskey_value: Option<u32>,
        cert_value: Option<u32>,
        cdnskey_value: Option<u32>,
        https_value: Option<u32>,
        key_value: Option<u32>,
        naptr_value: Option<u32>,
        srv_value: Option<u32>,
        svcb_value: Option<u32>,
        tlsa_value: Option<u32>,
        txt_value: Option<u32>,
        uri_value: Option<u32>,
        remarks: Vec<Remark>,
    ) -> Self {
        Self {
            values: Values {
                ns: ns_value,
                ds: ds_value,
                a: a_value,
                aaaa: aaaa_value,
                mx: mx_value,
                ptr: ptr_value,
                cname: cname_value,
                cds: cds_value,
                csync: csync_value,
                caa: caa_value,
                dnskey: dnskey_value,
                cert: cert_value,
                cdnskey: cdnskey_value,
                https: https_value,
                key: key_value,
                naptr: naptr_value,
                srv: srv_value,
                svcb: svcb_value,
                tlsa: tlsa_value,
                txt: txt_value,
                uri: uri_value,
            },
            remarks: to_opt_vec(remarks),
        }
    }

    /// Getter for `A` ttl.
    pub fn a_value(&self) -> Option<u32> {
        self.values.a
    }

    /// Getter for `AAAA` ttl.
    pub fn aaaa_value(&self) -> Option<u32> {
        self.values.aaaa
    }

    /// Getter for `NS` ttl.
    pub fn ns_value(&self) -> Option<u32> {
        self.values.ns
    }

    /// Getter for `DS` ttl.
    pub fn ds_value(&self) -> Option<u32> {
        self.values.ds
    }

    /// Getter for `MX` ttl.
    pub fn mx_value(&self) -> Option<u32> {
        self.values.mx
    }

    /// Getter for `PTR` ttl.
    pub fn ptr_value(&self) -> Option<u32> {
        self.values.ptr
    }

    /// Getter for `CNAME` ttl.
    pub fn cname_value(&self) -> Option<u32> {
        self.values.cname
    }

    /// Getter for `CDS` ttl.
    pub fn cds_value(&self) -> Option<u32> {
        self.values.cds
    }

    /// Getter for `CSYNC` ttl.
    pub fn csync_value(&self) -> Option<u32> {
        self.values.csync
    }

    /// Getter for `CAA` ttl.
    pub fn caa_value(&self) -> Option<u32> {
        self.values.caa
    }

    /// Getter for `DNSKEY` ttl.
    pub fn dnskey_value(&self) -> Option<u32> {
        self.values.dnskey
    }

    /// Getter for `CERT` ttl.
    pub fn cert_value(&self) -> Option<u32> {
        self.values.cert
    }

    /// Getter for `CDNSKEY` ttl.
    pub fn cdnskey_value(&self) -> Option<u32> {
        self.values.cdnskey
    }

    /// Getter for `HTTPS` ttl.
    pub fn https_value(&self) -> Option<u32> {
        self.values.https
    }

    /// Getter for `KEY` ttl.
    pub fn key_value(&self) -> Option<u32> {
        self.values.key
    }

    /// Getter for `NAPTR` ttl.
    pub fn naptr_value(&self) -> Option<u32> {
        self.values.naptr
    }

    /// Getter for `SRV` ttl.
    pub fn srv_value(&self) -> Option<u32> {
        self.values.srv
    }

    /// Getter for `SVCB` ttl.
    pub fn svcb_value(&self) -> Option<u32> {
        self.values.svcb
    }

    /// Getter for `TLSA` ttl.
    pub fn tlsa_value(&self) -> Option<u32> {
        self.values.tlsa
    }

    /// Getter for `TXT` ttl.
    pub fn txt_value(&self) -> Option<u32> {
        self.values.txt
    }

    /// Getter for `URI` ttl.
    pub fn uri_value(&self) -> Option<u32> {
        self.values.uri
    }

    /// Getter for remarks.
    pub fn remarks(&self) -> &[Remark] {
        self.remarks.as_deref().unwrap_or_default()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Values {
    /// The TTL value of the NS record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "NS")]
    pub ns: Option<u32>,

    /// The TTL value of the DS record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "DS")]
    pub ds: Option<u32>,

    /// The TTL value of the A record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "A")]
    pub a: Option<u32>,

    /// The TTL value of the AAAA record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "AAAA")]
    pub aaaa: Option<u32>,

    /// The TTL value of the MX record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "MX")]
    pub mx: Option<u32>,

    /// The TTL value of the PTR record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "PTR")]
    pub ptr: Option<u32>,

    /// The TTL value of the CNAME record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CNAME")]
    pub cname: Option<u32>,

    /// The TTL value of the CDS record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CDS")]
    pub cds: Option<u32>,

    /// The TTL value of the CSYNC record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CSYNC")]
    pub csync: Option<u32>,

    /// The TTL value of the CAA record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CAA")]
    pub caa: Option<u32>,

    /// The TTL value of the DNSKEY record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "DNSKEY")]
    pub dnskey: Option<u32>,

    /// The TTL value of the CERT record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CERT")]
    pub cert: Option<u32>,

    /// The TTL value of the CDNSKEY record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CDNSKEY")]
    pub cdnskey: Option<u32>,

    /// The TTL value of the HTTPS record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "HTTPS")]
    pub https: Option<u32>,

    /// The TTL value of the KEY record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "KEY")]
    pub key: Option<u32>,

    /// The TTL value of the NAPTR record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "NAPTR")]
    pub naptr: Option<u32>,

    /// The TTL value of the SRV record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "SRV")]
    pub srv: Option<u32>,

    /// The TTL value of the SVCB record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "SVCB")]
    pub svcb: Option<u32>,

    /// The TTL value of the TLSA record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "TLSA")]
    pub tlsa: Option<u32>,

    /// The TTL value of the TXT record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "TXT")]
    pub txt: Option<u32>,

    /// The TTL value of the URI record.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "URI")]
    pub uri: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::Remark;

    #[test]
    fn test_ttl_builder_with_all_records() {
        // WHEN
        let ttl = Ttl0Data::builder()
            .ns_value(100)
            .ds_value(200)
            .a_value(300)
            .aaaa_value(400)
            .mx_value(500)
            .ptr_value(600)
            .cname_value(700)
            .cds_value(800)
            .csync_value(900)
            .caa_value(1000)
            .dnskey_value(1100)
            .cert_value(1200)
            .cdnskey_value(1300)
            .https_value(1400)
            .key_value(1500)
            .naptr_value(1600)
            .srv_value(1700)
            .svcb_value(1800)
            .tlsa_value(1900)
            .txt_value(2000)
            .uri_value(2100)
            .build();

        // THEN
        assert_eq!(ttl.ns_value(), Some(100));
        assert_eq!(ttl.ds_value(), Some(200));
        assert_eq!(ttl.a_value(), Some(300));
        assert_eq!(ttl.aaaa_value(), Some(400));
        assert_eq!(ttl.mx_value(), Some(500));
        assert_eq!(ttl.ptr_value(), Some(600));
        assert_eq!(ttl.cname_value(), Some(700));
        assert_eq!(ttl.cds_value(), Some(800));
        assert_eq!(ttl.csync_value(), Some(900));
        assert_eq!(ttl.caa_value(), Some(1000));
        assert_eq!(ttl.dnskey_value(), Some(1100));
        assert_eq!(ttl.cert_value(), Some(1200));
        assert_eq!(ttl.cdnskey_value(), Some(1300));
        assert_eq!(ttl.https_value(), Some(1400));
        assert_eq!(ttl.key_value(), Some(1500));
        assert_eq!(ttl.naptr_value(), Some(1600));
        assert_eq!(ttl.srv_value(), Some(1700));
        assert_eq!(ttl.svcb_value(), Some(1800));
        assert_eq!(ttl.tlsa_value(), Some(1900));
        assert_eq!(ttl.txt_value(), Some(2000));
        assert_eq!(ttl.uri_value(), Some(2100));
    }

    #[test]
    fn test_ttl_with_remarks() {
        // GIVEN
        let remark = Remark::builder()
            .description(vec!["Test remark".to_string()])
            .build();

        // WHEN
        let ttl = Ttl0Data::builder()
            .a_value(300)
            .remarks(vec![remark])
            .build();

        // THEN
        assert_eq!(ttl.a_value(), Some(300));
        assert_eq!(ttl.remarks().len(), 1);
        assert!(ttl.remarks()[0].description.is_some());
    }

    #[test]
    fn test_ttl_builder_empty() {
        // WHEN
        let ttl = Ttl0Data::builder().build();

        // THEN
        assert_eq!(ttl.ns_value(), None);
        assert_eq!(ttl.ds_value(), None);
        assert_eq!(ttl.a_value(), None);
        assert_eq!(ttl.aaaa_value(), None);
        assert_eq!(ttl.mx_value(), None);
        assert_eq!(ttl.ptr_value(), None);
        assert_eq!(ttl.cname_value(), None);
        assert_eq!(ttl.cds_value(), None);
        assert_eq!(ttl.csync_value(), None);
        assert_eq!(ttl.caa_value(), None);
        assert_eq!(ttl.dnskey_value(), None);
        assert_eq!(ttl.cert_value(), None);
        assert_eq!(ttl.cdnskey_value(), None);
        assert_eq!(ttl.https_value(), None);
        assert_eq!(ttl.key_value(), None);
        assert_eq!(ttl.naptr_value(), None);
        assert_eq!(ttl.srv_value(), None);
        assert_eq!(ttl.svcb_value(), None);
        assert_eq!(ttl.tlsa_value(), None);
        assert_eq!(ttl.txt_value(), None);
        assert_eq!(ttl.uri_value(), None);
    }

    #[test]
    fn test_ttl_serialization() {
        // GIVEN
        let ttl = Ttl0Data::builder()
            .a_value(300)
            .mx_value(500)
            .txt_value(2000)
            .build();

        // WHEN
        let json = serde_json::to_string(&ttl).unwrap();
        let parsed: Ttl0Data = serde_json::from_str(&json).unwrap();

        // THEN
        assert_eq!(ttl, parsed);
        assert_eq!(parsed.a_value(), Some(300));
        assert_eq!(parsed.mx_value(), Some(500));
        assert_eq!(parsed.txt_value(), Some(2000));
    }

    #[test]
    fn test_json_serialization_format() {
        // GIVEN
        let ttl = Ttl0Data::builder()
            .a_value(300)
            .mx_value(500)
            .txt_value(2000)
            .build();

        // WHEN
        let json = serde_json::to_string_pretty(&ttl).unwrap();

        // THEN
        assert!(json.contains("\"A\": 300"));
        assert!(json.contains("\"MX\": 500"));
        assert!(json.contains("\"TXT\": 2000"));
        assert!(!json.contains("\"NS\""));
        assert!(!json.contains("\"DS\""));
        assert!(!json.contains("\"AAAA\""));
    }
}

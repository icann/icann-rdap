//! DNS and DNSSEC types.

use std::str::{Chars, FromStr};

use idna::domain_to_ascii;
use thiserror::Error;

use crate::check::string::StringCheck;

#[derive(Debug, Error)]
pub enum DnsTypeError {
    #[error("Invalid DNS Algorithm")]
    InvalidAlgorithm,
    #[error("Invalid DNS Digest")]
    InvalidDigest,
}

pub struct DnsAlgorithm {
    pub number: u8,
    pub mnemonic: &'static str,
    pub zone_signing: bool,
    pub transaction_signing: bool,
}

pub enum DnsAlgorithmType {
    DeleteDs(DnsAlgorithm),
    RsaMd5(DnsAlgorithm),
    DiffieHellman(DnsAlgorithm),
    Dsa(DnsAlgorithm),
    RsaSha1(DnsAlgorithm),
    DsaNsec3Sha1(DnsAlgorithm),
    RsaSha1Nsec3Sha1(DnsAlgorithm),
    RsaSha256(DnsAlgorithm),
    RsaSha512(DnsAlgorithm),
    EccGost(DnsAlgorithm),
    EcdsaP256Sha256(DnsAlgorithm),
    EcdsaP384Sha384(DnsAlgorithm),
    Ed25519(DnsAlgorithm),
    Ed448(DnsAlgorithm),
    PrivateDns(DnsAlgorithm),
    PrivateOid(DnsAlgorithm),
}

impl DnsAlgorithmType {
    pub fn from_number(number: u8) -> Result<Self, DnsTypeError> {
        match number {
            0 => Ok(Self::DeleteDs(DnsAlgorithm {
                number: 0,
                mnemonic: "DELETE",
                zone_signing: false,
                transaction_signing: false,
            })),
            1 => Ok(Self::RsaMd5(DnsAlgorithm {
                number: 1,
                mnemonic: "RSAMD5",
                zone_signing: false,
                transaction_signing: true,
            })),
            2 => Ok(Self::DiffieHellman(DnsAlgorithm {
                number: 2,
                mnemonic: "DH",
                zone_signing: false,
                transaction_signing: true,
            })),
            3 => Ok(Self::Dsa(DnsAlgorithm {
                number: 3,
                mnemonic: "DSA",
                zone_signing: true,
                transaction_signing: true,
            })),
            5 => Ok(Self::RsaSha1(DnsAlgorithm {
                number: 5,
                mnemonic: "RSASHA1",
                zone_signing: true,
                transaction_signing: true,
            })),
            6 => Ok(Self::DsaNsec3Sha1(DnsAlgorithm {
                number: 6,
                mnemonic: "DSA-NSEC3-SHA1",
                zone_signing: true,
                transaction_signing: true,
            })),
            7 => Ok(Self::RsaSha1Nsec3Sha1(DnsAlgorithm {
                number: 7,
                mnemonic: "RSA-NSEC3-SHA1",
                zone_signing: true,
                transaction_signing: true,
            })),
            8 => Ok(Self::RsaSha256(DnsAlgorithm {
                number: 8,
                mnemonic: "RSASHA256",
                zone_signing: true,
                transaction_signing: false,
            })),
            10 => Ok(Self::RsaSha512(DnsAlgorithm {
                number: 10,
                mnemonic: "RSASHA512",
                zone_signing: true,
                transaction_signing: false,
            })),
            12 => Ok(Self::EccGost(DnsAlgorithm {
                number: 12,
                mnemonic: "ECC-GOST",
                zone_signing: true,
                transaction_signing: false,
            })),
            13 => Ok(Self::EcdsaP256Sha256(DnsAlgorithm {
                number: 13,
                mnemonic: "ECDSAP256SHA256",
                zone_signing: true,
                transaction_signing: false,
            })),
            14 => Ok(Self::EcdsaP384Sha384(DnsAlgorithm {
                number: 14,
                mnemonic: "ECDSAP384SHA384",
                zone_signing: true,
                transaction_signing: false,
            })),
            15 => Ok(Self::Ed25519(DnsAlgorithm {
                number: 15,
                mnemonic: "ED25519",
                zone_signing: true,
                transaction_signing: false,
            })),
            16 => Ok(Self::Ed448(DnsAlgorithm {
                number: 16,
                mnemonic: "ED448",
                zone_signing: true,
                transaction_signing: false,
            })),
            253 => Ok(Self::PrivateDns(DnsAlgorithm {
                number: 253,
                mnemonic: "PRIVATEDNS",
                zone_signing: true,
                transaction_signing: true,
            })),
            254 => Ok(Self::PrivateOid(DnsAlgorithm {
                number: 254,
                mnemonic: "PRIVATEOID",
                zone_signing: true,
                transaction_signing: true,
            })),
            _ => Err(DnsTypeError::InvalidAlgorithm),
        }
    }

    pub fn mnemonic(number: u8) -> Result<&'static str, DnsTypeError> {
        let alg = Self::from_number(number)?;
        let m = match alg {
            DnsAlgorithmType::DeleteDs(a) => a.mnemonic,
            DnsAlgorithmType::RsaMd5(a) => a.mnemonic,
            DnsAlgorithmType::DiffieHellman(a) => a.mnemonic,
            DnsAlgorithmType::Dsa(a) => a.mnemonic,
            DnsAlgorithmType::RsaSha1(a) => a.mnemonic,
            DnsAlgorithmType::DsaNsec3Sha1(a) => a.mnemonic,
            DnsAlgorithmType::RsaSha1Nsec3Sha1(a) => a.mnemonic,
            DnsAlgorithmType::RsaSha256(a) => a.mnemonic,
            DnsAlgorithmType::RsaSha512(a) => a.mnemonic,
            DnsAlgorithmType::EccGost(a) => a.mnemonic,
            DnsAlgorithmType::EcdsaP256Sha256(a) => a.mnemonic,
            DnsAlgorithmType::EcdsaP384Sha384(a) => a.mnemonic,
            DnsAlgorithmType::Ed25519(a) => a.mnemonic,
            DnsAlgorithmType::Ed448(a) => a.mnemonic,
            DnsAlgorithmType::PrivateDns(a) => a.mnemonic,
            DnsAlgorithmType::PrivateOid(a) => a.mnemonic,
        };
        Ok(m)
    }

    pub fn zone_signing(number: u8) -> Result<bool, DnsTypeError> {
        let alg = Self::from_number(number)?;
        let z = match alg {
            DnsAlgorithmType::DeleteDs(a) => a.zone_signing,
            DnsAlgorithmType::RsaMd5(a) => a.zone_signing,
            DnsAlgorithmType::DiffieHellman(a) => a.zone_signing,
            DnsAlgorithmType::Dsa(a) => a.zone_signing,
            DnsAlgorithmType::RsaSha1(a) => a.zone_signing,
            DnsAlgorithmType::DsaNsec3Sha1(a) => a.zone_signing,
            DnsAlgorithmType::RsaSha1Nsec3Sha1(a) => a.zone_signing,
            DnsAlgorithmType::RsaSha256(a) => a.zone_signing,
            DnsAlgorithmType::RsaSha512(a) => a.zone_signing,
            DnsAlgorithmType::EccGost(a) => a.zone_signing,
            DnsAlgorithmType::EcdsaP256Sha256(a) => a.zone_signing,
            DnsAlgorithmType::EcdsaP384Sha384(a) => a.zone_signing,
            DnsAlgorithmType::Ed25519(a) => a.zone_signing,
            DnsAlgorithmType::Ed448(a) => a.zone_signing,
            DnsAlgorithmType::PrivateDns(a) => a.zone_signing,
            DnsAlgorithmType::PrivateOid(a) => a.zone_signing,
        };
        Ok(z)
    }
}

pub struct DnsDigest {
    pub number: u8,
    pub mnemonic: &'static str,
    pub mandatory: bool,
}

/*

0 	Reserved 	- 	[RFC3658]
1 	SHA-1 	MANDATORY 	[RFC3658]
2 	SHA-256 	MANDATORY 	[RFC4509]
3 	GOST R 34.11-94 	OPTIONAL 	[RFC5933]
4 	SHA-384 	OPTIONAL
*/

pub enum DnsDigestType {
    Sha1(DnsDigest),
    Sha256(DnsDigest),
    Gost(DnsDigest),
    Sha384(DnsDigest),
}

impl DnsDigestType {
    pub fn from_number(number: u8) -> Result<Self, DnsTypeError> {
        match number {
            1 => Ok(DnsDigestType::Sha1(DnsDigest {
                number: 1,
                mnemonic: "SHA1",
                mandatory: true,
            })),
            2 => Ok(DnsDigestType::Sha256(DnsDigest {
                number: 2,
                mnemonic: "SHA256",
                mandatory: true,
            })),
            3 => Ok(DnsDigestType::Gost(DnsDigest {
                number: 3,
                mnemonic: "GOST",
                mandatory: false,
            })),
            4 => Ok(DnsDigestType::Sha384(DnsDigest {
                number: 4,
                mnemonic: "SHA384",
                mandatory: false,
            })),
            _ => Err(DnsTypeError::InvalidDigest),
        }
    }

    pub fn mnemonic(number: u8) -> Result<&'static str, DnsTypeError> {
        let digest = DnsDigestType::from_number(number)?;
        let d = match digest {
            DnsDigestType::Sha1(d) => d.mnemonic,
            DnsDigestType::Sha256(d) => d.mnemonic,
            DnsDigestType::Gost(d) => d.mnemonic,
            DnsDigestType::Sha384(d) => d.mnemonic,
        };
        Ok(d)
    }
}

#[derive(Debug, Error)]
pub enum DomainNameError {
    #[error("Invalid Domain Name")]
    InvalidDomainName,
    #[error(transparent)]
    IdnaError(#[from] idna::Errors),
}

/// Represents a Domain name.
#[derive(Debug)]
pub struct DomainName {
    domain_name: String,
    ascii: String,
}

impl DomainName {
    /// Iterate over the characters of the domain name.
    pub fn chars(&self) -> Chars<'_> {
        self.domain_name.chars()
    }

    /// Is this domain name a TLD.
    pub fn is_tld(&self) -> bool {
        self.domain_name.is_tld()
    }

    /// Gets the ASCII version of the domain, which is different if this is an IDN.
    pub fn to_ascii(&self) -> &str {
        &self.ascii
    }

    /// Is this domain name an IDN.
    pub fn is_idn(&self) -> bool {
        !self.ascii.eq(&self.domain_name)
    }

    /// Is this the DNS root.
    pub fn is_root(&self) -> bool {
        self.domain_name.eq(".")
    }

    /// Get this domain name with a leading dot.
    pub fn with_leading_dot(&self) -> String {
        if !self.is_root() {
            format!(".{}", self.domain_name)
        } else {
            self.domain_name.to_string()
        }
    }

    /// Trim leading dot.
    pub fn trim_leading_dot(&self) -> &str {
        if !self.is_root() {
            self.domain_name.trim_start_matches('.')
        } else {
            &self.domain_name
        }
    }
}

impl FromStr for DomainName {
    type Err = DomainNameError;

    /// Create a new DomainName from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_unicode_domain_name() {
            return Err(DomainNameError::InvalidDomainName);
        }
        let ascii = domain_to_ascii(s)?;
        let retval = DomainName {
            domain_name: s.to_string(),
            ascii,
        };
        Ok(retval)
    }
}

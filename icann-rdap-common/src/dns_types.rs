//! DNS and DNSSEC types.

use std::str::{Chars, FromStr};

use {idna::domain_to_ascii, thiserror::Error};

use crate::check::StringCheck;

/// Errors when determining DNS information.
#[derive(Debug, Error)]
pub enum DnsTypeError {
    #[error("Invalid DNS Algorithm")]
    InvalidAlgorithm,
    #[error("Invalid DNS Digest")]
    InvalidDigest,
}

/// Information about DNSSEC Algorithm.
pub struct DnsAlgorithm {
    pub number: u8,
    pub mnemonic: &'static str,
    pub zone_signing: bool,
    pub transaction_signing: bool,
}

/// DNS Algorithm Variants.
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
    /// Convert an algorithm number to a [DnsAlgorithmType].
    pub fn from_number(number: u8) -> Result<Self, DnsTypeError> {
        Ok(match number {
            0 => Self::DeleteDs(DnsAlgorithm {
                number: 0,
                mnemonic: "DELETE",
                zone_signing: false,
                transaction_signing: false,
            }),
            1 => Self::RsaMd5(DnsAlgorithm {
                number: 1,
                mnemonic: "RSAMD5",
                zone_signing: false,
                transaction_signing: true,
            }),
            2 => Self::DiffieHellman(DnsAlgorithm {
                number: 2,
                mnemonic: "DH",
                zone_signing: false,
                transaction_signing: true,
            }),
            3 => Self::Dsa(DnsAlgorithm {
                number: 3,
                mnemonic: "DSA",
                zone_signing: true,
                transaction_signing: true,
            }),
            5 => Self::RsaSha1(DnsAlgorithm {
                number: 5,
                mnemonic: "RSASHA1",
                zone_signing: true,
                transaction_signing: true,
            }),
            6 => Self::DsaNsec3Sha1(DnsAlgorithm {
                number: 6,
                mnemonic: "DSA-NSEC3-SHA1",
                zone_signing: true,
                transaction_signing: true,
            }),
            7 => Self::RsaSha1Nsec3Sha1(DnsAlgorithm {
                number: 7,
                mnemonic: "RSA-NSEC3-SHA1",
                zone_signing: true,
                transaction_signing: true,
            }),
            8 => Self::RsaSha256(DnsAlgorithm {
                number: 8,
                mnemonic: "RSASHA256",
                zone_signing: true,
                transaction_signing: false,
            }),
            10 => Self::RsaSha512(DnsAlgorithm {
                number: 10,
                mnemonic: "RSASHA512",
                zone_signing: true,
                transaction_signing: false,
            }),
            12 => Self::EccGost(DnsAlgorithm {
                number: 12,
                mnemonic: "ECC-GOST",
                zone_signing: true,
                transaction_signing: false,
            }),
            13 => Self::EcdsaP256Sha256(DnsAlgorithm {
                number: 13,
                mnemonic: "ECDSAP256SHA256",
                zone_signing: true,
                transaction_signing: false,
            }),
            14 => Self::EcdsaP384Sha384(DnsAlgorithm {
                number: 14,
                mnemonic: "ECDSAP384SHA384",
                zone_signing: true,
                transaction_signing: false,
            }),
            15 => Self::Ed25519(DnsAlgorithm {
                number: 15,
                mnemonic: "ED25519",
                zone_signing: true,
                transaction_signing: false,
            }),
            16 => Self::Ed448(DnsAlgorithm {
                number: 16,
                mnemonic: "ED448",
                zone_signing: true,
                transaction_signing: false,
            }),
            253 => Self::PrivateDns(DnsAlgorithm {
                number: 253,
                mnemonic: "PRIVATEDNS",
                zone_signing: true,
                transaction_signing: true,
            }),
            254 => Self::PrivateOid(DnsAlgorithm {
                number: 254,
                mnemonic: "PRIVATEOID",
                zone_signing: true,
                transaction_signing: true,
            }),
            _ => return Err(DnsTypeError::InvalidAlgorithm),
        })
    }

    fn algo(self) -> DnsAlgorithm {
        match self {
            Self::DeleteDs(a)
            | Self::RsaMd5(a)
            | Self::DiffieHellman(a)
            | Self::Dsa(a)
            | Self::RsaSha1(a)
            | Self::DsaNsec3Sha1(a)
            | Self::RsaSha1Nsec3Sha1(a)
            | Self::RsaSha256(a)
            | Self::RsaSha512(a)
            | Self::EccGost(a)
            | Self::EcdsaP256Sha256(a)
            | Self::EcdsaP384Sha384(a)
            | Self::Ed25519(a)
            | Self::Ed448(a)
            | Self::PrivateDns(a)
            | Self::PrivateOid(a) => a,
        }
    }

    /// Get the mnemonic for the algorithm number.
    pub fn mnemonic(number: u8) -> Result<&'static str, DnsTypeError> {
        let alg = Self::from_number(number)?;
        Ok(alg.algo().mnemonic)
    }

    /// True if the DNS Algorithm can sign zones.
    pub fn zone_signing(number: u8) -> Result<bool, DnsTypeError> {
        let alg = Self::from_number(number)?;
        Ok(alg.algo().zone_signing)
    }
}

/// DNS Digest.
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

/// DNS Digest Variants.
pub enum DnsDigestType {
    Sha1(DnsDigest),
    Sha256(DnsDigest),
    Gost(DnsDigest),
    Sha384(DnsDigest),
}

impl DnsDigestType {
    /// Get the [DnsDigestType] from the protocol number.
    pub fn from_number(number: u8) -> Result<Self, DnsTypeError> {
        Ok(match number {
            1 => Self::Sha1(DnsDigest {
                number: 1,
                mnemonic: "SHA1",
                mandatory: true,
            }),
            2 => Self::Sha256(DnsDigest {
                number: 2,
                mnemonic: "SHA256",
                mandatory: true,
            }),
            3 => Self::Gost(DnsDigest {
                number: 3,
                mnemonic: "GOST",
                mandatory: false,
            }),
            4 => Self::Sha384(DnsDigest {
                number: 4,
                mnemonic: "SHA384",
                mandatory: false,
            }),
            _ => return Err(DnsTypeError::InvalidDigest),
        })
    }

    /// Get the mnemonic from the protocol number.
    pub fn mnemonic(number: u8) -> Result<&'static str, DnsTypeError> {
        let digest = Self::from_number(number)?;
        Ok(match digest {
            Self::Sha1(d) | Self::Sha256(d) | Self::Gost(d) | Self::Sha384(d) => d.mnemonic,
        })
    }
}

/// Error specific to processing of domain names.
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
        Ok(Self {
            domain_name: s.to_string(),
            ascii,
        })
    }
}

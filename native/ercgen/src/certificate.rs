use std::collections::HashMap;

use rcgen::string::Ia5String;
use rustler::{ErlOption, NifMap, NifTaggedEnum, NifUnitEnum};
use crate::Error;

#[derive(NifMap, Default)]
pub struct CertificateParams {
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
    serial_number: ErlOption<Vec<u8>>,
    subject_alt_names: Vec<SanType>,
    distinguished_name: HashMap<DnType, String>,
    is_ca: IsCa,
    key_usages: Vec<KeyUsagePurpose>,
    extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    name_constraints: ErlOption<NameConstraints>,
    crl_distribution_points: Vec<Vec<String>>,
    custom_extensions: Vec<CustomExtension>,
    use_authority_key_identifier_extension: bool,
    key_identifier_method: KeyIdMethod,
}

#[derive(NifUnitEnum)]
enum KeyUsagePurpose {
    DigitalSignature,
    ContentCommitment,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

#[derive(NifTaggedEnum, Default)]
enum IsCa {
    #[default]
    NoCa,
    ExplicitNoCa,
    Ca(BasicConstraints),
}

#[derive(NifTaggedEnum)]
enum BasicConstraints {
    Unconstrained,
    Constrained(u8),
}

#[derive(NifTaggedEnum)]
enum SanType {
    Rfc822Name(String),
    DnsName(String),
    Uri(String),
    IpAddress(String),
    OtherName{ oid: Vec<u64>, value: String },
}

#[derive(NifTaggedEnum, PartialEq, Eq, Hash)]
enum DnType {
    CountryName,
    LocalityName,
    StateOrProvinceName,
    OrganizationName,
    OrganizationalUnitName,
    CommonName,
    CustomDnType(Vec<u64>),
}

#[derive(NifTaggedEnum, PartialEq, Eq, Hash)]
enum ExtendedKeyUsagePurpose {
    Any,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    Other(Vec<u64>),
}

#[derive(NifMap)]
struct NameConstraints {
    permitted_subtrees: Vec<GeneralSubtree>,
    excluded_subtrees: Vec<GeneralSubtree>,
}

#[derive(NifTaggedEnum)]
enum GeneralSubtree {
    Rfc822Name(String),
    DnsName(String),
    DirectoryName(HashMap<DnType, String>),
    IpAddress(String), // CIDR notation string
}

#[derive(NifMap)]
struct CustomExtension {
    critical: bool,
    oid: Vec<u64>,
    content: Vec<u8>,
}

#[derive(NifTaggedEnum, Default)]
enum KeyIdMethod {
    #[default]
    Sha256,
    Sha384,
    Sha512,
    PreSpecified(Vec<u8>),
}

impl From<KeyUsagePurpose> for rcgen::KeyUsagePurpose {
    fn from(value: KeyUsagePurpose) -> Self {
        match value {
            KeyUsagePurpose::DigitalSignature => rcgen::KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment => rcgen::KeyUsagePurpose::ContentCommitment,
            KeyUsagePurpose::KeyEncipherment => rcgen::KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::DataEncipherment => rcgen::KeyUsagePurpose::DataEncipherment,
            KeyUsagePurpose::KeyAgreement => rcgen::KeyUsagePurpose::KeyAgreement,
            KeyUsagePurpose::KeyCertSign => rcgen::KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign => rcgen::KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::EncipherOnly => rcgen::KeyUsagePurpose::EncipherOnly,
            KeyUsagePurpose::DecipherOnly => rcgen::KeyUsagePurpose::DecipherOnly,
        }
    }
}

impl From<IsCa> for rcgen::IsCa {
    fn from(is_ca: IsCa) -> Self {
        match is_ca {
            IsCa::NoCa => rcgen::IsCa::NoCa,
            IsCa::ExplicitNoCa => rcgen::IsCa::ExplicitNoCa,
            IsCa::Ca(bc) => rcgen::IsCa::Ca(bc.into()),
        }
    }
}

impl From<BasicConstraints> for rcgen::BasicConstraints {
    fn from(bc: BasicConstraints) -> Self {
        match bc {
            BasicConstraints::Unconstrained => rcgen::BasicConstraints::Unconstrained,
            BasicConstraints::Constrained(path_len) => rcgen::BasicConstraints::Constrained(path_len),
        }
    }
}

impl TryFrom<SanType> for rcgen::SanType {
    type Error = Error;
    fn try_from(san: SanType) -> Result<Self, Self::Error> {
        let san = match san {
            SanType::Rfc822Name(name) => rcgen::SanType::Rfc822Name(Ia5String::try_from(name)?),
            SanType::DnsName(name) => rcgen::SanType::DnsName(Ia5String::try_from(name)?),
            SanType::Uri(name) => rcgen::SanType::URI(Ia5String::try_from(name)?),
            SanType::IpAddress(addr) => rcgen::SanType::IpAddress(addr.parse().map_err(|_| Error::InvalidIpAddress)?),
            SanType::OtherName{ oid, value } => rcgen::SanType::OtherName(( oid, value.into() )),
        };
        Ok(san)
    }
}

impl From<DnType> for rcgen::DnType {
    fn from(dn_type: DnType) -> Self {
        match dn_type {
            DnType::CountryName => rcgen::DnType::CountryName,
            DnType::LocalityName => rcgen::DnType::LocalityName,
            DnType::StateOrProvinceName => rcgen::DnType::StateOrProvinceName,
            DnType::OrganizationName => rcgen::DnType::OrganizationName,
            DnType::OrganizationalUnitName => rcgen::DnType::OrganizationalUnitName,
            DnType::CommonName => rcgen::DnType::CommonName,
            DnType::CustomDnType(oid) => rcgen::DnType::CustomDnType(oid),
        }
    }
}

impl From<ExtendedKeyUsagePurpose> for rcgen::ExtendedKeyUsagePurpose {
    fn from(eku: ExtendedKeyUsagePurpose) -> Self {
        match eku {
            ExtendedKeyUsagePurpose::Any => rcgen::ExtendedKeyUsagePurpose::Any,
            ExtendedKeyUsagePurpose::ServerAuth => rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth => rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::CodeSigning => rcgen::ExtendedKeyUsagePurpose::CodeSigning,
            ExtendedKeyUsagePurpose::EmailProtection => rcgen::ExtendedKeyUsagePurpose::EmailProtection,
            ExtendedKeyUsagePurpose::TimeStamping => rcgen::ExtendedKeyUsagePurpose::TimeStamping,
            ExtendedKeyUsagePurpose::OcspSigning => rcgen::ExtendedKeyUsagePurpose::OcspSigning,
            ExtendedKeyUsagePurpose::Other(oid) => rcgen::ExtendedKeyUsagePurpose::Other(oid),
        }
    }
}

impl TryFrom<GeneralSubtree> for rcgen::GeneralSubtree {
    type Error = Error;
    fn try_from(gs: GeneralSubtree) -> Result<Self, Self::Error> {
        match gs {
            GeneralSubtree::Rfc822Name(name) => Ok(rcgen::GeneralSubtree::Rfc822Name(name)),
            GeneralSubtree::DnsName(name) => Ok(rcgen::GeneralSubtree::DnsName(name)),
            GeneralSubtree::DirectoryName(dn) => {
                let mut rcgen_dn = rcgen::DistinguishedName::new();
                dn.into_iter().for_each(|(dn_type, value)| {
                    rcgen_dn.push(rcgen::DnType::from(dn_type), value);
                });
                Ok(rcgen::GeneralSubtree::DirectoryName(rcgen_dn))
            }
            GeneralSubtree::IpAddress(cidr) => {
                match cidr.split('/').collect::<Vec<&str>>().as_slice() {
                    [ip_str, prefix_len_str] => {
                        let addr = ip_str.parse().map_err(|_| Error::InvalidCidr)?;
                        let prefix_len = prefix_len_str.parse().map_err(|_| Error::InvalidCidr)?;
                        let cidr = rcgen::CidrSubnet::from_addr_prefix(addr, prefix_len);
                        Ok(rcgen::GeneralSubtree::IpAddress(cidr))
                    }
                    _ => {
                        Err(Error::InvalidCidr)
                    }
                }
            }
        }
    }
}

impl TryFrom<NameConstraints> for rcgen::NameConstraints {
    type Error = Error;
    fn try_from(nc: NameConstraints) -> Result<Self, Self::Error> {
        let permitted_subtrees = nc.permitted_subtrees
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        let excluded_subtrees = nc.excluded_subtrees
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rcgen::NameConstraints {
            permitted_subtrees,
            excluded_subtrees,
        })
    }
}

impl From<CustomExtension> for rcgen::CustomExtension {
    fn from(ce: CustomExtension) -> Self {
        let mut e = rcgen::CustomExtension::from_oid_content(&ce.oid, ce.content);
        e.set_criticality(ce.critical);
        e
    }
}

impl From<KeyIdMethod> for rcgen::KeyIdMethod {
    fn from(kid: KeyIdMethod) -> Self {
        match kid {
            KeyIdMethod::Sha256 => rcgen::KeyIdMethod::Sha256,
            KeyIdMethod::Sha384 => rcgen::KeyIdMethod::Sha384,
            KeyIdMethod::Sha512 => rcgen::KeyIdMethod::Sha512,
            KeyIdMethod::PreSpecified(bytes) => rcgen::KeyIdMethod::PreSpecified(bytes),
        }
    }
}

impl TryFrom<CertificateParams> for rcgen::CertificateParams {
    type Error = Error;

    fn try_from(params: CertificateParams) -> Result<Self, Self::Error> {
        let (year, month, day) = params.not_before;
        let mut c = rcgen::CertificateParams::default();
        c.not_before = rcgen::date_time_ymd(year, month, day);
        let (year, month, day) = params.not_after;
        c.not_after = rcgen::date_time_ymd(year, month, day);
        let sn: Option<Vec<u8>> = params.serial_number.into();
        c.serial_number = sn.map(From::from);
        c.subject_alt_names = params.subject_alt_names
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<rcgen::SanType>, _>>()?;
        params.distinguished_name.into_iter().for_each(|(dn_type, value)| {
            c.distinguished_name.push(rcgen::DnType::from(dn_type), value);
        });
        c.is_ca = params.is_ca.into();
        c.key_usages = params.key_usages.into_iter().map(From::from).collect();
        c.extended_key_usages = params.extended_key_usages.into_iter().map(From::from).collect();
        let name_constraints: Option<NameConstraints> = params.name_constraints.into();
        c.name_constraints = name_constraints.map(TryFrom::try_from).transpose()?;
        c.crl_distribution_points = params.crl_distribution_points.into_iter()
            .map(|uris| rcgen::CrlDistributionPoint{uris}).collect();
        c.custom_extensions = params.custom_extensions.into_iter().map(From::from).collect();
        c.use_authority_key_identifier_extension = params.use_authority_key_identifier_extension;
        c.key_identifier_method = params.key_identifier_method.into();
        Ok(c)
    }
}

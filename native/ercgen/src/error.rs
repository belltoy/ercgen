use rustler::NifUnitEnum;
use rustls_pki_types::pem::Error as PemError;

#[derive(NifUnitEnum, Debug)]
pub enum Error {
    // rcgen::Error variants
    CouldNotParseCertificate,
    CouldNotParseCertificationRequest,
    CouldNotParseKeyPair,
    InvalidNameType,
    InvalidAsn1String,
    InvalidIpAddressOctetLength,
    KeyGenerationUnavailable,
    UnsupportedExtension,
    UnsupportedSignatureAlgorithm,
    RingUnspecified,
    RingKeyRejected,
    Time,
    PemError,
    RemoteKeyError,
    UnsupportedInCsr,
    InvalidCrlNextUpdate,
    IssuerNotCrlSigner,
    X509,
    InvalidCidr,
    InvalidIpAddress,

    // PEM error
    PemMissingSectionEnd,
    PemIllegalSectionStart,
    PemBase64Decode,
    PemIo,
    PemNoItemsFound,

    Unknown,
}

impl From<rcgen::Error> for Error {
    fn from(value: rcgen::Error) -> Self {
        match value {
            rcgen::Error::CouldNotParseCertificate => Error::CouldNotParseCertificate,
            rcgen::Error::CouldNotParseCertificationRequest => Error::CouldNotParseCertificationRequest,
            rcgen::Error::CouldNotParseKeyPair => Error::CouldNotParseKeyPair,
            rcgen::Error::InvalidNameType => Error::InvalidNameType,
            rcgen::Error::InvalidAsn1String(_) => Error::InvalidAsn1String,
            rcgen::Error::InvalidIpAddressOctetLength(_) => Error::InvalidIpAddressOctetLength,
            rcgen::Error::KeyGenerationUnavailable => Error::KeyGenerationUnavailable,
            rcgen::Error::UnsupportedExtension => Error::UnsupportedExtension,
            rcgen::Error::UnsupportedSignatureAlgorithm => Error::UnsupportedSignatureAlgorithm,
            rcgen::Error::RingUnspecified => Error::RingUnspecified,
            rcgen::Error::RingKeyRejected(_) => Error::RingKeyRejected,
            rcgen::Error::Time => Error::Time,
            rcgen::Error::PemError(_) => Error::PemError,
            rcgen::Error::RemoteKeyError => Error::RemoteKeyError,
            rcgen::Error::UnsupportedInCsr => Error::UnsupportedInCsr,
            rcgen::Error::InvalidCrlNextUpdate => Error::InvalidCrlNextUpdate,
            rcgen::Error::IssuerNotCrlSigner => Error::IssuerNotCrlSigner,
            rcgen::Error::X509(_) => Error::X509,
            _ => Error::Unknown,
        }
    }
}

impl From<PemError> for Error {
    fn from(value: PemError) -> Self {
        match value {
            PemError::MissingSectionEnd{..} => Error::PemMissingSectionEnd,
            PemError::IllegalSectionStart{..} => Error::PemIllegalSectionStart,
            PemError::Base64Decode(_) => Error::PemBase64Decode,
            PemError::Io(_) => Error::PemIo,
            PemError::NoItemsFound => Error::PemNoItemsFound,
            _ => Error::Unknown,
        }
    }
}

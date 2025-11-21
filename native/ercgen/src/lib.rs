use rcgen::{Issuer, KeyPair, SubjectPublicKeyInfo};
use rustler::Binary;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

mod error;
mod certificate;

use crate::certificate::CertificateParams;
pub use crate::error::Error;

#[rustler::nif]
fn default_certificate_params() -> CertificateParams {
    CertificateParams::default()
}

#[rustler::nif]
fn certificate_params_echo(param: CertificateParams) -> CertificateParams {
    param
}

#[rustler::nif]
fn signed_by(
    cert_params: CertificateParams,
    public_key_pem: &str,
    issuer_cert_pem: Binary<'_>,
    issuer_private_key_pem: Binary<'_>,
) -> Result<String, Error> {
    let issuer_cert_der = CertificateDer::from_pem_slice(&issuer_cert_pem)?;
    let issuer_private_key_der = PrivateKeyDer::from_pem_slice(&issuer_private_key_pem)?;
    let issuer_key_pair = KeyPair::try_from(&issuer_private_key_der)?;
    let issuer = Issuer::from_ca_cert_der(&issuer_cert_der, issuer_key_pair)?;

    let key = SubjectPublicKeyInfo::from_pem(public_key_pem)?;
    let params = rcgen::CertificateParams::try_from(cert_params)?;
    let cert = params.signed_by(&key, &issuer)?;
    Ok(cert.pem())
}

rustler::init!("ercgen");

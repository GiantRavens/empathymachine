use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

// certificate authority management for https interception

pub struct CaStore {
    dir: PathBuf,
    root_pem: String,
    key_pem: String,
}

pub struct IssuedCert {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub private_key_der: Vec<u8>,
    pub private_key_pem: String,
}

#[derive(Debug)]
pub enum CaError {
    Io(io::Error),
    Rcgen(rcgen::Error),
}

impl CaStore {
    pub fn load_or_init<P: AsRef<Path>>(dir: P) -> Result<Self, CaError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let cert_path = dir.join("root_ca.pem");
        let key_path = dir.join("root_ca.key");

        let (root_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            load_existing_material(&cert_path, &key_path)?
        } else {
            let material = generate_root_material()?;
            persist_root_material(&dir, &material.0, &material.1)?;
            material
        };

        Ok(Self {
            dir,
            root_pem,
            key_pem,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }

    pub fn root_pem(&self) -> Result<String, CaError> {
        Ok(self.root_pem.clone())
    }

    pub fn root_key_pem(&self) -> String {
        self.key_pem.clone()
    }

    pub fn root_der(&self) -> Result<Vec<u8>, CaError> {
        Ok(decode_pem_certificate(&self.root_pem)?)
    }

    pub fn issue_leaf(&self, host: &str) -> Result<IssuedCert, CaError> {
        let mut names = vec![host.to_string()];
        if let Some(wildcard) = wildcard_for(host) {
            names.push(wildcard);
        }

        let mut params = CertificateParams::new(names)?;
        params.distinguished_name = distinguished_name(host);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_key = KeyPair::from_pem(&self.key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&self.root_pem, ca_key)?;
        let certificate = params.signed_by(&leaf_key, &issuer)?;

        let cert_der = certificate.der().to_vec();
        let cert_pem = certificate.pem();
        let private_key_der = leaf_key.serialize_der();
        let private_key_pem = leaf_key.serialize_pem();

        Ok(IssuedCert {
            cert_der,
            cert_pem,
            private_key_der,
            private_key_pem,
        })
    }
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaError::Io(err) => write!(f, "io error: {err}"),
            CaError::Rcgen(err) => write!(f, "certificate error: {err}"),
        }
    }
}

impl std::error::Error for CaError {}

impl From<io::Error> for CaError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rcgen::Error> for CaError {
    fn from(value: rcgen::Error) -> Self {
        Self::Rcgen(value)
    }
}

fn load_existing_material(cert_path: &Path, key_path: &Path) -> Result<(String, String), CaError> {
    let cert_pem = fs::read_to_string(cert_path)?;
    let key_pem = fs::read_to_string(key_path)?;

    Ok((cert_pem, key_pem))
}

fn generate_root_material() -> Result<(String, String), CaError> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = distinguished_name("EmpathyMachine Root CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let cert = params.self_signed(&key)?;
    let root_pem = cert.pem();
    let key_pem = key.serialize_pem();

    Ok((root_pem, key_pem))
}

fn persist_root_material(dir: &Path, cert_pem: &str, key_pem: &str) -> Result<(), CaError> {
    let cert_path = dir.join("root_ca.pem");
    let key_path = dir.join("root_ca.key");

    fs::write(cert_path, cert_pem)?;
    fs::write(key_path, key_pem)?;
    Ok(())
}

fn decode_pem_certificate(pem: &str) -> Result<Vec<u8>, CaError> {
    let mut reader = io::Cursor::new(pem.as_bytes());
    let mut certs = rustls_pemfile::certs(&mut reader)?;
    let der = certs
        .pop()
        .ok_or_else(|| rcgen::Error::CouldNotParseCertificate)?;
    Ok(der)
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

fn wildcard_for(host: &str) -> Option<String> {
    if host.split('.').count() < 2 {
        return None;
    }
    Some(format!("*.{}", host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn creates_and_reloads_ca() {
        let dir = tempdir().expect("tempdir");

        let store = CaStore::load_or_init(dir.path()).expect("create ca");
        let pem = store.root_pem().expect("root pem");
        assert!(pem.contains("BEGIN CERTIFICATE"));

        drop(store);

        let store = CaStore::load_or_init(dir.path()).expect("reload ca");
        let pem2 = store.root_pem().expect("root pem reload");
        assert_eq!(pem, pem2);

        let issued = store.issue_leaf("example.com").expect("leaf cert");
        assert!(!issued.cert_der.is_empty());
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!issued.private_key_der.is_empty());
    }
}

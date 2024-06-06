use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

pub struct Cert {
    cert_pem: String,
    key_pair: KeyPair,
}

impl Cert {
    pub fn write(&self, dir: &Path, name: &str) -> anyhow::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(dir)?; //maybe dangerous?

        let key_path = dir.join(format!("{name}.key.pem"));
        let mut key_out = File::create(key_path)?;
        write!(key_out, "{}", self.key_pair.serialize_pem())?;

        let cert_path = dir.join(format!("{name}.pem"));
        let mut cert_out = File::create(cert_path)?;
        write!(cert_out, "{}", self.cert_pem)?;

        Ok(())
    }

    pub fn self_signed_cert(&self) -> anyhow::Result<Certificate> {
        let params = CertificateParams::from_ca_cert_pem(&self.cert_pem)?;
        let cert = params.self_signed(&self.key_pair)?;
        Ok(cert)
    }

    pub fn cert_pem(&self) -> String {
        self.cert_pem.clone()
    }
    pub fn key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    pub fn load(dir: &Path, name: &str) -> anyhow::Result<Cert> {
        let key_path = dir.join(format!("{name}.key.pem"));
        let cert_path = dir.join(format!("{name}.pem"));

        Self::load_from_file(key_path, cert_path)
    }

    fn load_from_file(key_path: PathBuf, cert_path: PathBuf) -> anyhow::Result<Cert> {
        let key_pem = fs::read_to_string(key_path)?;
        let cert_pem = fs::read_to_string(cert_path)?;

        let key_pair = KeyPair::from_pem(&key_pem)?;
        Ok(Cert { cert_pem, key_pair })
    }

    pub fn load_if_exists(dir: &Path, name: &str) -> anyhow::Result<Option<Cert>> {
        let key_path = dir.join(format!("{name}.key.pem"));
        let cert_path = dir.join(format!("{name}.pem"));

        if key_path.exists() && cert_path.exists() {
            let cert = Self::load_from_file(key_path, cert_path)?;
            Ok(Some(cert))
        } else if key_path.exists() || cert_path.exists() {
            Err(anyhow::anyhow!("errr"))
        } else {
            Ok(None)
        }
    }
}

pub fn generate_ca(country: &str, organization: &str) -> anyhow::Result<Cert> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.distinguished_name.push(DnType::CountryName, country);
    params
        .distinguished_name
        .push(DnType::OrganizationName, organization);

    let alg: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key_pair = KeyPair::generate_for(alg)?;

    let cert: Certificate = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    Ok(Cert { cert_pem, key_pair })
}

pub fn generate_cert(ca: &Cert, cn: &str, sans: Vec<SanType>) -> anyhow::Result<Cert> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.distinguished_name.push(DnType::CommonName, cn);
    params.subject_alt_names.extend(sans); // todo: handle empty sans

    let alg: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key_pair = KeyPair::generate_for(alg)?;
    let ca_cert = ca.self_signed_cert()?;
    let cert = params.signed_by(&key_pair, &ca_cert, &ca.key_pair)?;
    let cert_pem = cert.pem();
    Ok(Cert { cert_pem, key_pair })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_gen_and_load_ca() {
        let ca = generate_ca("VN", "Example").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.into_path();
        ca.write(path.as_path(), "unit_test_ca").unwrap();

        let loaded_ca = Cert::load(path.as_path(), "unit_test_ca").unwrap();
        assert_eq!(ca.cert_pem, loaded_ca.cert_pem);
        assert_eq!(
            ca.key_pair.serialize_pem(),
            loaded_ca.key_pair.serialize_pem()
        );
    }

    #[test]
    fn test_gen_and_load_cert() {
        let ca = generate_ca("VN", "Example").unwrap();
        let cert = generate_cert(
            &ca,
            "example.com",
            vec![SanType::DnsName("localhost".try_into().unwrap())],
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.into_path();
        cert.write(path.as_path(), "unit_test_cert").unwrap();

        let loaded_cert = Cert::load(path.as_path(), "unit_test_cert").unwrap();
        assert_eq!(cert.cert_pem, loaded_cert.cert_pem);
        assert_eq!(
            cert.key_pair.serialize_pem(),
            loaded_cert.key_pair.serialize_pem()
        );
    }
}

/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bssl_crypto::digest::Sha256;
use bssl_crypto::ec::{P256, P384};
use bssl_crypto::ecdsa;
use bssl_crypto::rsa::{KeySize as RsaKeySize, PrivateKey as RsaPrivateKey};
use log::{info, warn};
use std::path::Path;
use std::sync::{LazyLock, RwLock};
use std::time::Instant;
use x509_cert::der::{Any, Decode, Encode};
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier};
use x509_cert::Certificate;

pub const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
pub const ID_RSA_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub const EC_SHA256_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const EC_SHA384_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
pub const RSA_SHA256_SIG_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub const P256_CURVE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub const P384_CURVE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

#[path = "keybox_cache.rs"]
mod cache;

/// Supported EC batch signing keys (NIST P-256 or P-384).
#[derive(Clone)]
pub enum EcSigningKey {
    P256(ecdsa::PrivateKey<P256>),
    P384(ecdsa::PrivateKey<P384>),
}

impl EcSigningKey {
    pub fn from_der(priv_der: &[u8]) -> Option<Self> {
        if let Some(k) = ecdsa::PrivateKey::<P256>::from_der_ec_private_key(priv_der)
            .or_else(|| ecdsa::PrivateKey::<P256>::from_der_private_key_info(priv_der))
        {
            return Some(Self::P256(k));
        }
        ecdsa::PrivateKey::<P384>::from_der_ec_private_key(priv_der)
            .or_else(|| ecdsa::PrivateKey::<P384>::from_der_private_key_info(priv_der))
            .map(Self::P384)
    }

    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        match self {
            Self::P256(k) => k.to_der_private_key_info().as_ref().to_vec(),
            Self::P384(k) => k.to_der_private_key_info().as_ref().to_vec(),
        }
    }

    pub fn to_spki_der(&self) -> Vec<u8> {
        match self {
            Self::P256(k) => k.to_der_subject_public_key_info().as_ref().to_vec(),
            Self::P384(k) => k.to_der_subject_public_key_info().as_ref().to_vec(),
        }
    }

    pub fn matches_spki(&self, spki: &[u8]) -> bool {
        match self {
            Self::P256(k) => k.to_der_subject_public_key_info().as_ref() == spki,
            Self::P384(k) => k.to_der_subject_public_key_info().as_ref() == spki,
        }
    }

    pub fn sig_oid(&self) -> ObjectIdentifier {
        match self {
            Self::P256(_) => EC_SHA256_SIG_OID,
            Self::P384(_) => EC_SHA384_SIG_OID,
        }
    }

    pub fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        match self {
            Self::P256(k) => k.sign(tbs),
            Self::P384(k) => k.sign(tbs),
        }
    }
}

/// Unified EC/RSA signing key shared by keybox batch keys and managed `ATTEST_KEY` issuers.
#[derive(Clone)]
pub enum SigningKey {
    Ec(EcSigningKey),
    Rsa(RsaPrivateKey),
}

impl SigningKey {
    pub fn generate_ec_p256() -> Self {
        Self::Ec(EcSigningKey::P256(ecdsa::PrivateKey::<P256>::generate()))
    }

    pub fn generate_ec_p384() -> Self {
        Self::Ec(EcSigningKey::P384(ecdsa::PrivateKey::<P384>::generate()))
    }

    pub fn generate_rsa(bits: i32) -> Option<Self> {
        let size = match bits {
            2048 => RsaKeySize::Rsa2048,
            3072 => RsaKeySize::Rsa3072,
            4096 => RsaKeySize::Rsa4096,
            _ => return None,
        };
        Some(Self::Rsa(RsaPrivateKey::generate(size)))
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        EcSigningKey::from_der(der)
            .map(Self::Ec)
            .or_else(|| RsaPrivateKey::from_der_private_key_info(der).map(Self::Rsa))
    }

    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        match self {
            Self::Ec(k) => k.to_pkcs8_der(),
            Self::Rsa(k) => k.to_der_private_key_info().as_ref().to_vec(),
        }
    }

    pub fn to_spki_der(&self) -> Vec<u8> {
        match self {
            Self::Ec(k) => k.to_spki_der(),
            Self::Rsa(k) => k.as_public().to_der_subject_public_key_info().as_ref().to_vec(),
        }
    }

    pub fn sig_algorithm(&self) -> AlgorithmIdentifierOwned {
        match self {
            Self::Ec(k) => AlgorithmIdentifierOwned { oid: k.sig_oid(), parameters: None },
            Self::Rsa(_) => {
                AlgorithmIdentifierOwned { oid: RSA_SHA256_SIG_OID, parameters: Some(Any::null()) }
            }
        }
    }

    pub fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        match self {
            Self::Ec(k) => k.sign(tbs),
            Self::Rsa(k) => k.sign_pkcs1::<Sha256>(tbs),
        }
    }
}

/// A keybox's batch keys. Each chain is leaf first: [batch, intermediate.., root].
/// RKP keyboxes carry only the EC key; classic ones carry both.
#[derive(Clone)]
pub struct KeyboxEntry {
    pub ec: Option<(EcSigningKey, Vec<Vec<u8>>)>,
    pub rsa: Option<(RsaPrivateKey, Vec<Vec<u8>>)>,
}

impl KeyboxEntry {
    /// Returns the batch signing key matching `want_ec`, falling back to the alternate algorithm
    /// when the configured keybox carries only one key (e.g. EC-only RKP keyboxes).
    pub fn signing_key_for(&self, want_ec: bool) -> Option<(SigningKey, &[Vec<u8>])> {
        match (&self.ec, &self.rsa) {
            (Some((k, chain)), Some(_)) if want_ec => Some((SigningKey::Ec(k.clone()), chain)),
            (Some(_), Some((k, chain))) if !want_ec => Some((SigningKey::Rsa(k.clone()), chain)),
            (Some((k, chain)), _) => Some((SigningKey::Ec(k.clone()), chain)),
            (_, Some((k, chain))) => Some((SigningKey::Rsa(k.clone()), chain)),
            (None, None) => None,
        }
    }
}

static GLOBAL_KEYBOX: LazyLock<RwLock<cache::FileCache<KeyboxEntry>>> =
    LazyLock::new(|| RwLock::new(cache::FileCache::new()));

/// The installed keybox, or None when inaccessible, changing, or invalid.
pub fn current() -> Option<KeyboxEntry> {
    let path = format!("{}/keybox.xml", super::ATTEST_DIR);
    let mut store = match GLOBAL_KEYBOX.write() {
        Ok(s) => s,
        Err(e) => {
            warn!("YasvaraKeybox: lock poisoned: {:?}", e);
            return None;
        }
    };
    let lookup = store.current(Path::new(&path), Instant::now(), parse_keybox_xml);
    if let Some(failure) = lookup.diagnostic {
        warn!(
            "YasvaraKeybox: configured keybox {} unavailable: {}; check provisioning/format, \
             init, file/parent permissions and SELinux labels/AVCs; retrying \
             (failure warnings limited to once per minute)",
            path, failure
        );
    }
    if lookup.loaded {
        if let Some(entry) = lookup.entry {
            info!(
                "YasvaraKeybox: loaded (ec_chain={:?}, rsa_chain={:?})",
                entry.ec.as_ref().map(|e| e.1.len()),
                entry.rsa.as_ref().map(|r| r.1.len())
            );
        }
    }
    lookup.entry.cloned()
}

/// Simple regex-free XML parser for keybox.xml format.
/// Diagnostics stay in current() so retries cannot bypass its warning rate limit.
pub fn parse_keybox_xml(xml: &str) -> Option<KeyboxEntry> {
    let mut entry = KeyboxEntry { ec: None, rsa: None };
    // 1. Find <Key algorithm="..."> block
    let key_start_tag = "<Key ";
    let mut search_idx = 0;
    while let Some(rel_start) = xml[search_idx..].find(key_start_tag) {
        let key_start = search_idx + rel_start;
        let Some(key_close) = xml[key_start..].find('>') else {
            break;
        };
        let tag_header = &xml[key_start..key_start + key_close];

        let algo = if tag_header.contains("algorithm=\"ecdsa\"")
            || tag_header.contains("algorithm='ecdsa'")
        {
            "ecdsa"
        } else if tag_header.contains("algorithm=\"rsa\"") || tag_header.contains("algorithm='rsa'")
        {
            "rsa"
        } else {
            search_idx = key_start + key_close;
            continue;
        };

        let key_end_tag = "</Key>";
        let Some(key_block_end) = xml[key_start..].find(key_end_tag) else {
            break;
        };
        let key_block = &xml[key_start..key_start + key_block_end];
        let next_search_idx = key_start + key_block_end + key_end_tag.len();

        // 2. Extract <PrivateKey>
        let priv_der = (|| -> Option<Vec<u8>> {
            let priv_start = key_block.find("<PrivateKey")?;
            let priv_content_start = key_block[priv_start..].find('>')? + priv_start + 1;
            let priv_content_end =
                key_block[priv_content_start..].find("</PrivateKey>")? + priv_content_start;
            extract_pem_bytes(&key_block[priv_content_start..priv_content_end])
        })();

        let Some(priv_der) = priv_der else {
            warn!("YasvaraKeybox: {} <Key> block missing or invalid <PrivateKey>", algo);
            search_idx = next_search_idx;
            continue;
        };

        // 3. Extract <CertificateChain>
        let certs = (|| -> Option<Vec<Vec<u8>>> {
            let chain_tag_start = key_block.find("<CertificateChain")?;
            let chain_content_start = key_block[chain_tag_start..].find('>')? + chain_tag_start + 1;
            let chain_content_end =
                key_block[chain_content_start..].find("</CertificateChain>")? + chain_content_start;
            let chain_block = &key_block[chain_content_start..chain_content_end];

            let mut certs: Vec<Vec<u8>> = Vec::new();
            let mut c_search = 0;
            while let Some(c_rel) = chain_block[c_search..].find("<Certificate") {
                let c_start = c_search + c_rel;
                let c_content_start = chain_block[c_start..].find('>')? + c_start + 1;
                let c_content_end =
                    chain_block[c_content_start..].find("</Certificate>")? + c_content_start;
                let cert_pem = &chain_block[c_content_start..c_content_end];
                if let Some(der) = extract_pem_bytes(cert_pem) {
                    certs.push(der);
                }
                c_search = c_content_end;
            }
            Some(certs)
        })();

        let Some(certs) = certs else {
            warn!("YasvaraKeybox: {} <Key> block missing or invalid <CertificateChain>", algo);
            search_idx = next_search_idx;
            continue;
        };

        if certs.is_empty() {
            warn!("YasvaraKeybox: {} <Key> block contains no valid certificates", algo);
            search_idx = next_search_idx;
            continue;
        }
        if !validate_chain(&certs) {
            warn!("YasvaraKeybox: rejecting {} key with an invalid certificate chain", algo);
            search_idx = next_search_idx;
            continue;
        }
        let leaf = match Certificate::from_der(&certs[0]) {
            Ok(c) => c,
            Err(e) => {
                warn!("YasvaraKeybox: failed to parse leaf certificate: {:?}", e);
                search_idx = next_search_idx;
                continue;
            }
        };
        let leaf_spki = match leaf.tbs_certificate.subject_public_key_info.to_der() {
            Ok(d) => d,
            Err(e) => {
                warn!("YasvaraKeybox: failed to encode leaf public key: {:?}", e);
                search_idx = next_search_idx;
                continue;
            }
        };
        let leaf_is_ec =
            leaf.tbs_certificate.subject_public_key_info.algorithm.oid == ID_EC_PUBLIC_KEY;

        // Parse private key and require it to match the first certificate.
        if algo == "ecdsa" {
            if !leaf_is_ec {
                warn!("YasvaraKeybox: ecdsa keybox contains a non-EC leaf certificate");
                search_idx = next_search_idx;
                continue;
            }
            match EcSigningKey::from_der(&priv_der) {
                Some(k) if k.matches_spki(leaf_spki.as_slice()) => {
                    entry.ec.get_or_insert((k, certs));
                }
                Some(_) => warn!("YasvaraKeybox: EC private key does not match leaf certificate"),
                None => warn!("YasvaraKeybox: failed to parse EC private key"),
            }
        } else {
            if leaf_is_ec {
                warn!("YasvaraKeybox: rsa keybox contains an EC leaf certificate");
                search_idx = next_search_idx;
                continue;
            }
            let rsa_key = bssl_crypto::rsa::PrivateKey::from_der_rsa_private_key(&priv_der)
                .or_else(|| bssl_crypto::rsa::PrivateKey::from_der_private_key_info(&priv_der));
            match rsa_key {
                Some(k)
                    if k.as_public().to_der_subject_public_key_info().as_ref()
                        == leaf_spki.as_slice() =>
                {
                    entry.rsa.get_or_insert((k, certs));
                }
                Some(_) => warn!("YasvaraKeybox: RSA private key does not match leaf certificate"),
                None => warn!("YasvaraKeybox: failed to parse RSA private key"),
            }
        }

        search_idx = next_search_idx;
    }
    (entry.ec.is_some() || entry.rsa.is_some()).then_some(entry)
}

/// Each certificate must be signed by the next one. Validity dates are deliberately
/// not enforced so an expired keybox keeps loading. Uses BoringSSL `X509_verify` so
/// cross-curve/digest issuer signatures (e.g. P-384 TEE intermediate signing a P-256
/// batch cert with `ecdsa-with-SHA256`) verify accurately.
fn validate_chain(chain: &[Vec<u8>]) -> bool {
    if chain.len() < 2 {
        return false;
    }
    let mut certs = Vec::with_capacity(chain.len());
    for der in chain {
        match Certificate::from_der(der) {
            Ok(cert) => certs.push(cert),
            Err(e) => {
                warn!("YasvaraKeybox: failed to parse chain certificate: {:?}", e);
                return false;
            }
        }
    }
    for i in 0..certs.len() - 1 {
        let cert = &certs[i];
        let issuer = &certs[i + 1];
        if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
            warn!("YasvaraKeybox: chain issuer mismatch at index {}", i);
            return false;
        }
        if cert.signature.raw_bytes().is_empty() {
            warn!("YasvaraKeybox: empty signature at index {}", i);
            return false;
        }
        if !keystore2_crypto::verify_x509_signature(&chain[i], &chain[i + 1]) {
            warn!("YasvaraKeybox: chain signature invalid at index {}", i);
            return false;
        }
    }
    if let (Some(last_cert), Some(last_der)) = (certs.last(), chain.last()) {
        if last_cert.tbs_certificate.issuer == last_cert.tbs_certificate.subject
            && !keystore2_crypto::verify_x509_signature(last_der, last_der)
        {
            warn!("YasvaraKeybox: self-signed root signature invalid");
            return false;
        }
    }
    true
}

fn extract_pem_bytes(pem: &str) -> Option<Vec<u8>> {
    let mut b64 = String::with_capacity(pem.len());
    let mut in_body = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if t.starts_with("-----END") {
            break;
        }
        if in_body {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        // Maybe it's raw base64 without headers
        b64 = pem.chars().filter(|c| !c.is_whitespace()).collect();
    }
    BASE64_STANDARD.decode(b64.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Throwaway test chain: RSA-2048 self-signed root -> EC P-384 intermediate ->
    /// EC P-256 batch leaf signed with `ecdsa-with-SHA256` (exact Google TEE RKP/keybox topology).
    const TEST_KEYBOX_XML: &str = r#"<?xml version="1.0"?>
<AndroidAttestation>
<Keybox DeviceID="test">
<Key algorithm="ecdsa">
<PrivateKey format="pem">
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFcEqNaXTiwRIDlFL1DpWG36lD9VxcZbNllNW2zrNOvooAoGCCqGSM49
AwEHoUQDQgAEQXAPcWmgxa9kVauxxI7LyxPQGQPCIWksSpGzWK4R5lsP/o1PSs7x
dEX+vqYjcxIzO8QDQiStzZOIspoVO/cONQ==
-----END EC PRIVATE KEY-----
</PrivateKey>
<CertificateChain>
<NumberOfCertificates>3</NumberOfCertificates>
<Certificate format="pem">
-----BEGIN CERTIFICATE-----
MIIBoDCCASWgAwIBAgIUQu3dUezMEEsZdW6YPjZ5wkTkLKYwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWVGVzdCBQMzg0IEludGVybWVkaWF0ZTAeFw0yNjExMDUxODQ4
MDhaFw0zNjExMDIxODQ4MDhaMBoxGDAWBgNVBAMMD1Rlc3QgUDI1NiBCYXRjaDBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABEFwD3FpoMWvZFWrscSOy8sT0BkDwiFp
LEqRs1iuEeZbD/6NT0rO8XRF/r6mI3MSMzvEA0Ikrc2TiLKaFTv3DjWjQjBAMB0G
A1UdDgQWBBQfBk/X4kCV3wkVmgAXQg5s8nr0ijAfBgNVHSMEGDAWgBQT9nsYMaEI
wxK9sytBRQSf29Mu7DAKBggqhkjOPQQDAgNpADBmAjEA+qTXB8R9SNjs+GIJ0M+P
H/JIwv2CSeabODDjIVAZKkThPZyYuFX5z5PEejS386p2AjEAyIxZT2oZElVrGtZ8
6w+4+w3miVuwUKgArp2FkcvANBANomLogRp1pJRtNfPmlD7H
-----END CERTIFICATE-----
</Certificate>
<Certificate format="pem">
-----BEGIN CERTIFICATE-----
MIICWjCCAUKgAwIBAgIUN2nfl/JRZHjFEWXkxb4S7C3DN4cwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MTEwNTE4NDgwOFoXDTM2
MTEwMjE4NDgwOFowITEfMB0GA1UEAwwWVGVzdCBQMzg0IEludGVybWVkaWF0ZTB2
MBAGByqGSM49AgEGBSuBBAAiA2IABJPafUOebpYSlAKXukuHOJakGPGeiQ8bpHaB
wT0svVAt9Z5wMPfDfkjw6UAmA8oLXC2pfrJYi1+/pctyoWF4scOXDrW79YWjEvfU
JYkRgXk8jGnlW3TRiVeYYNQSJnh/36NCMEAwHQYDVR0OBBYEFBP2exgxoQjDEr2z
K0FFBJ/b0y7sMB8GA1UdIwQYMBaAFNvJCrMrCyaaou1sKckF7i6KuF9dMA0GCSqG
SIb3DQEBCwUAA4IBAQBrx3xZxiA49jhVX1dkNmEv7kGICMgvF94PjNbIZ3Cpac7Z
fvda1CotKsWf+LYrpC8ayc5xSPOmG5UP4uukK9s44JRUzVEM86/WtMfT6JoeK3wX
Ndx3NhDUHDqs2lEcR6bqP/r6JrMPeDClwijC1UWqq2wWIJz8E2sNAkiVGl2XTR41
t2eIiv2oHWyPYTGZWLIg3hum3JrTlOnX2Fex5muaJCIZFi5xeSQ1l7RtTKHr9r5r
jB+UYkZ8gyyQ10q1osKK8CsMweSzjywWXhzpF/fUwqQcOHCdYGlnoX8/7vqVtjSw
pxrI0ELPlW76nS2OZRQwQhgERwT06IRAWXwShln3
-----END CERTIFICATE-----
</Certificate>
<Certificate format="pem">
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUcmGyoWgiIE6/yIyDbNeZxTk6c9MwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MTEwNTE4NDgwOFoXDTM2
MTEwMjE4NDgwOFowFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqTsDLjNIfH2HzNl/p9fJlvhswWlGW42W0aC
OpRCIcgzJ/TVg3NEScxcDVmZ5I+I4J/ZEEonqVAo/cesPhhJUJNi9htBTxUA46GP
BtyX19XH3cspo6sbRObjGYQLUYFf77JKkJIXTMbS8Q7Ju8PnpS7Ihv1CMnyJY6a0
bDfcPuCOYCFKV/xDz/xsWLMdVNoNhC+LFAuuhzS3q+nAebzzNgymknESsx5EIN7r
SHSwCIn3E8HRpUv8+YVxTUgS/ZqAfVGXcn5RYWbauC1yHkYpTW6q0EEaPkuFzkrv
Jmi2uj3oJWzAeeNW2V/PzoPw26Gt0k0XaGj1Hd5TikMqE3lh/QIDAQABo1MwUTAd
BgNVHQ4EFgQU28kKsysLJpqi7WwpyQXuLoq4X10wHwYDVR0jBBgwFoAU28kKsysL
Jpqi7WwpyQXuLoq4X10wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAPm3o2orIIPzyLx2XRjLPbrLtsECtcjFX9hhvaIH5nRqzob2dkM4mP7VjnThx
u5+OsMCrlWpcK/XdoJ6xhCuPYV6VTdiTYiQ83mnnc08ZfXSE5wu94AJZkwzBlVlx
0SBzHuXT8aBsMAy/frSbi9xP3oxe7IjP1iSipo6/0jPsB9w/15z3JYvO43mknmQq
1MSiCKsQj5deTKLDqEZwUmalBXhzkOtgz8K68itbwIg5NbA8Oq9PSav4ipWjGl+D
7HzQxRz8wJpUVPP3QdcBLrVwIMhH6vai+wnCVCqn4qqzgXsFayXqPWy9l9CmZ64R
dT7JMOep8FMzb5dkJ1jc2+XGVw==
-----END CERTIFICATE-----
</Certificate>
</CertificateChain>
</Key>
</Keybox>
</AndroidAttestation>"#;

    #[test]
    fn accepts_p384_sha256_cross_curve_ecdsa_chain_and_rejects_tampering() {
        let parsed = parse_keybox_xml(TEST_KEYBOX_XML).expect("P-384 -> P-256 SHA256 chain must load");
        let (ec_key, mut chain) = parsed.ec.expect("EC keybox entry must be present");
        assert_eq!(chain.len(), 3);
        assert_eq!(ec_key.sig_oid(), EC_SHA256_SIG_OID);

        // Corrupting 1 bit of the leaf signature must cause validate_chain to reject.
        let last_byte = chain[0].len() - 1;
        chain[0][last_byte] ^= 0x01;
        assert!(!validate_chain(&chain));
    }
}

/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

use log::{error, info, warn};
use x509_cert::der::asn1::{BitString, OctetString};
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::{Certificate, TbsCertificate};

use super::attestation::patch_key_description;
use super::keybox::{
    KeyboxEntry, SigningKey, ID_EC_PUBLIC_KEY, ID_RSA_PUBLIC_KEY, P256_CURVE_OID, P384_CURVE_OID,
};

pub use super::attestation::{
    DeviceIdOverrides, PatchConfig, TAG_ATTESTATION_ID_BRAND, TAG_ATTESTATION_ID_DEVICE,
    TAG_ATTESTATION_ID_IMEI, TAG_ATTESTATION_ID_MANUFACTURER, TAG_ATTESTATION_ID_MEID,
    TAG_ATTESTATION_ID_MODEL, TAG_ATTESTATION_ID_PRODUCT, TAG_ATTESTATION_ID_SERIAL,
    TAG_BOOT_PATCHLEVEL, TAG_OS_PATCHLEVEL, TAG_OS_VERSION, TAG_ROOT_OF_TRUST,
    TAG_VENDOR_PATCHLEVEL,
};

pub const ATTESTATION_EXT_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
pub const SUBJECT_KEY_ID_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
pub const AUTHORITY_KEY_ID_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

fn strip_extension_oids(cert: &mut Certificate, oids: &[ObjectIdentifier]) {
    if let Some(exts) = cert.tbs_certificate.extensions.as_mut() {
        exts.retain(|e| !oids.contains(&e.extn_id));
        if exts.is_empty() {
            cert.tbs_certificate.extensions = None;
        }
    }
}

fn replace_spki(cert: &mut Certificate, spki_der: &[u8]) -> Option<()> {
    let spki = match SubjectPublicKeyInfoOwned::from_der(spki_der) {
        Ok(s) => s,
        Err(e) => {
            warn!("YasvaraPatcher: failed to parse replacement SPKI: {:?}", e);
            return None;
        }
    };
    cert.tbs_certificate.subject_public_key_info = spki;
    // Drop key identifiers derived from the discarded hardware public key so X.509 validators do
    // not observe a stale SKI/AKI mismatch.
    strip_extension_oids(cert, &[SUBJECT_KEY_ID_OID, AUTHORITY_KEY_ID_OID]);
    Some(())
}

fn apply_key_description_patch(cert: &mut Certificate, config: &PatchConfig) -> Option<()> {
    let exts = match cert.tbs_certificate.extensions.as_mut() {
        Some(exts) => exts,
        None => {
            warn!("YasvaraPatcher: no attestation extensions; check raw KeyMint output; preserving hardware chain");
            return None;
        }
    };
    if exts.iter().filter(|e| e.extn_id == ATTESTATION_EXT_OID).count() != 1 {
        warn!("YasvaraPatcher: missing/duplicate KeyDescription extension; check raw KeyMint output; preserving hardware chain");
        return None;
    }
    let ext = exts.iter_mut().find(|e| e.extn_id == ATTESTATION_EXT_OID)?;
    let patched_key_desc = match patch_key_description(ext.extn_value.as_bytes(), config) {
        Ok(d) => d,
        Err(e) => {
            warn!("YasvaraPatcher: refusing to re-sign: {}; check raw KeyMint RootOfTrust and boot digest publication; preserving hardware chain", e);
            return None;
        }
    };
    info!(
        "YasvaraPatcher: real leaf attestationVersion={} attestSecLevel={} keymasterSecLevel={}",
        patched_key_desc.attestation_version,
        patched_key_desc.attestation_security_level,
        patched_key_desc.keymaster_security_level
    );
    ext.extn_value = match OctetString::new(patched_key_desc.der) {
        Ok(o) => o,
        Err(e) => {
            warn!("YasvaraPatcher: failed to rewrap KeyDescription into OctetString: {:?}", e);
            return None;
        }
    };
    // Strip stale AuthorityKeyIdentifier pointing at the hardware/RKP issuer before re-signing.
    strip_extension_oids(cert, &[AUTHORITY_KEY_ID_OID]);
    Some(())
}

fn sign_tbs_and_encode(mut tbs: TbsCertificate, signer: &SigningKey) -> Option<Vec<u8>> {
    let sig_alg = signer.sig_algorithm();
    tbs.signature = sig_alg.clone();
    let tbs_der = match tbs.to_der() {
        Ok(d) => d,
        Err(e) => {
            warn!("YasvaraPatcher: failed to encode TBS cert: {:?}", e);
            return None;
        }
    };
    let sig_bytes = signer.sign(&tbs_der);
    let bit_string_sig = match BitString::from_bytes(&sig_bytes) {
        Ok(b) => b,
        Err(e) => {
            warn!("YasvaraPatcher: failed to create BitString signature: {:?}", e);
            return None;
        }
    };
    let signed = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: bit_string_sig,
    };
    match signed.to_der() {
        Ok(d) => Some(d),
        Err(e) => {
            warn!("YasvaraPatcher: failed to encode signed cert: {:?}", e);
            None
        }
    }
}

/// Generates a software `SigningKey` matching the algorithm and parameters of `leaf_der`.
/// Returns `None` for unsupported curves/sizes so the caller preserves unmodified hardware output.
pub fn generate_matching_signing_key(
    leaf_der: &[u8],
    rsa_bits_hint: Option<i32>,
    ec_is_p384_hint: Option<bool>,
) -> Option<SigningKey> {
    let cert = match Certificate::from_der(leaf_der) {
        Ok(c) => c,
        Err(e) => {
            warn!("YasvaraPatcher: failed to parse leaf cert for ATTEST_KEY matching: {:?}", e);
            return None;
        }
    };
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid == ID_EC_PUBLIC_KEY {
        let curve_oid = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        match curve_oid {
            Some(oid) if oid == P256_CURVE_OID => Some(SigningKey::generate_ec_p256()),
            Some(oid) if oid == P384_CURVE_OID => Some(SigningKey::generate_ec_p384()),
            None => match ec_is_p384_hint {
                Some(false) => Some(SigningKey::generate_ec_p256()),
                Some(true) => Some(SigningKey::generate_ec_p384()),
                None => None,
            },
            Some(other) => {
                warn!("YasvaraPatcher: unsupported EC curve {} for software ATTEST_KEY", other);
                None
            }
        }
    } else if spki.algorithm.oid == ID_RSA_PUBLIC_KEY {
        let bits = rsa_bits_hint?;
        let key = SigningKey::generate_rsa(bits);
        if key.is_none() {
            warn!("YasvaraPatcher: unsupported RSA key size {} for software ATTEST_KEY", bits);
        }
        key
    } else {
        warn!(
            "YasvaraPatcher: unsupported key algorithm {} for software ATTEST_KEY",
            spki.algorithm.oid
        );
        None
    }
}

/// Re-signs a real leaf certificate only after validating and preserving its measured boot truth.
pub fn patch_leaf_and_chain(
    leaf_der: &[u8],
    keybox: &KeyboxEntry,
    config: &PatchConfig,
) -> Option<Vec<Vec<u8>>> {
    patch_leaf_and_chain_with_spki(leaf_der, keybox, config, None)
}

/// Same as `patch_leaf_and_chain`, optionally substituting `SubjectPublicKeyInfo` first when
/// provisioning a challenged `PURPOSE_ATTEST_KEY` backed by a managed software issuer key.
pub fn patch_leaf_and_chain_with_spki(
    leaf_der: &[u8],
    keybox: &KeyboxEntry,
    config: &PatchConfig,
    replacement_spki: Option<&[u8]>,
) -> Option<Vec<Vec<u8>>> {
    let mut cert = match Certificate::from_der(leaf_der) {
        Ok(c) => c,
        Err(e) => {
            warn!("YasvaraPatcher: failed to parse real leaf cert: {:?}", e);
            return None;
        }
    };

    if let Some(spki_der) = replacement_spki {
        replace_spki(&mut cert, spki_der)?;
    }
    apply_key_description_patch(&mut cert, config)?;

    // Sign with the batch key matching the attested key's algorithm;
    // fall back to the other key when the keybox lacks it (EC-only RKP keyboxes).
    let want_ec = cert.tbs_certificate.subject_public_key_info.algorithm.oid == ID_EC_PUBLIC_KEY;
    let Some((signer, chain)) = keybox.signing_key_for(want_ec) else {
        error!("YasvaraPatcher: no private key in keybox");
        return None;
    };
    let batch_leaf_der = chain.first()?;
    let batch_cert = match Certificate::from_der(batch_leaf_der) {
        Ok(c) => c,
        Err(e) => {
            warn!("YasvaraPatcher: failed to parse keybox batch cert: {:?}", e);
            return None;
        }
    };

    // Re-root the leaf at the keybox.
    cert.tbs_certificate.issuer = batch_cert.tbs_certificate.subject.clone();
    let new_leaf_der = sign_tbs_and_encode(cert.tbs_certificate, &signer)?;

    let mut new_chain = Vec::with_capacity(1 + chain.len());
    new_chain.push(new_leaf_der);
    new_chain.extend(chain.iter().cloned());
    info!(
        "YasvaraPatcher: successfully re-signed attestation leaf, total chain={}",
        new_chain.len()
    );
    Some(new_chain)
}

/// Replaces `SubjectPublicKeyInfo` on a self-signed `PURPOSE_ATTEST_KEY` certificate and re-signs
/// it with `signer` while preserving KeyMint's subject, serial, validity, and other extensions.
pub fn resign_self_signed_leaf_with_spki(leaf_der: &[u8], signer: &SigningKey) -> Option<Vec<u8>> {
    let mut cert = match Certificate::from_der(leaf_der) {
        Ok(c) => c,
        Err(e) => {
            warn!("YasvaraPatcher: failed to parse self-signed ATTEST_KEY cert: {:?}", e);
            return None;
        }
    };
    let spki_der = signer.to_spki_der();
    replace_spki(&mut cert, &spki_der)?;
    cert.tbs_certificate.issuer = cert.tbs_certificate.subject.clone();
    let out = sign_tbs_and_encode(cert.tbs_certificate, signer)?;
    info!("YasvaraPatcher: provisioned software-backed self-signed ATTEST_KEY leaf");
    Some(out)
}

/// Patches a child attestation leaf generated under a `UserGenerated` `PURPOSE_ATTEST_KEY` and
/// signs it with `issuer_signer`, keeping a single-certificate chain rooted at `attest_cert_der`.
pub fn patch_user_attested_leaf(
    leaf_der: &[u8],
    attest_cert_der: &[u8],
    issuer_signer: &SigningKey,
    config: &PatchConfig,
    replacement_spki: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let mut cert = match Certificate::from_der(leaf_der) {
        Ok(c) => c,
        Err(e) => {
            warn!("YasvaraPatcher: failed to parse user-attested leaf cert: {:?}", e);
            return None;
        }
    };
    let attest_cert = match Certificate::from_der(attest_cert_der) {
        Ok(c) => c,
        Err(e) => {
            warn!("YasvaraPatcher: failed to parse attest key cert: {:?}", e);
            return None;
        }
    };
    let attest_spki = match attest_cert.tbs_certificate.subject_public_key_info.to_der() {
        Ok(d) => d,
        Err(e) => {
            warn!("YasvaraPatcher: failed to encode attest key SPKI: {:?}", e);
            return None;
        }
    };
    if attest_spki != issuer_signer.to_spki_der() {
        warn!("YasvaraPatcher: attest key cert SPKI differs from stored signing key; preserving hardware cert");
        return None;
    }

    if let Some(spki_der) = replacement_spki {
        replace_spki(&mut cert, spki_der)?;
    }
    apply_key_description_patch(&mut cert, config)?;
    cert.tbs_certificate.issuer = attest_cert.tbs_certificate.subject.clone();
    let new_leaf_der = sign_tbs_and_encode(cert.tbs_certificate, issuer_signer)?;
    info!("YasvaraPatcher: successfully re-signed ATTEST_KEY child leaf");
    Some(new_leaf_der)
}

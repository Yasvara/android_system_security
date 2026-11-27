/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

use super::*;
use yasvara_integrity_core::der::{tlv, PatchConfig};

fn build_aaid(pkgs: &[&[u8]], sigs: &[&[u8]]) -> Vec<u8> {
    let mut pkg_set = Vec::new();
    for p in pkgs {
        let mut info = tlv(&[0x04], p);
        info.extend_from_slice(&tlv(&[0x02], &[0x01]));
        pkg_set.extend_from_slice(&tlv(&[0x30], &info));
    }
    let mut sig_set = Vec::new();
    for s in sigs {
        sig_set.extend_from_slice(&tlv(&[0x04], s));
    }
    let mut body = tlv(&[0x31], &pkg_set);
    body.extend_from_slice(&tlv(&[0x31], &sig_set));
    tlv(&[0x30], &body)
}

fn collector_params() -> Vec<KeyParameter> {
    let aaid = build_aaid(&[b"com.google.android.gms"], &[&[0xaa; 32]]);
    let mut params = vec![
        KeyParameter {
            tag: Tag::ATTESTATION_CHALLENGE,
            value: KeyParameterValue::Blob(b"test challenge".to_vec()),
        },
        KeyParameter { tag: Tag::ATTESTATION_APPLICATION_ID, value: KeyParameterValue::Blob(aaid) },
    ];
    for tag in [
        Tag::ATTESTATION_ID_BRAND,
        Tag::ATTESTATION_ID_DEVICE,
        Tag::ATTESTATION_ID_PRODUCT,
        Tag::ATTESTATION_ID_MANUFACTURER,
        Tag::ATTESTATION_ID_MODEL,
        Tag::ATTESTATION_ID_SERIAL,
        Tag::ATTESTATION_ID_IMEI,
        Tag::ATTESTATION_ID_MEID,
        Tag::ATTESTATION_ID_SECOND_IMEI,
    ] {
        params.push(KeyParameter { tag, value: KeyParameterValue::Blob(b"test value".to_vec()) });
    }
    params
}

fn ready_policy() -> RequestPolicy {
    RequestPolicy {
        snapshot: None,
        patch: Some(AttestationContext {
            canonical_boot_digest: vec![1; 32],
            keybox: KeyboxEntry { ec: None, rsa: None, rkp_manufacturer: None },
            managed_issuer: None,
        }),
    }
}

#[test]
fn disabled_unavailable_and_explicit_signer_policies_preserve_request_and_response() {
    let params = collector_params();
    assert!(is_pif_collector_caller(&params));
    // Forged signature digest carrying "com.google.android.gms" must NOT match collector!
    let forged = vec![KeyParameter {
        tag: Tag::ATTESTATION_APPLICATION_ID,
        value: KeyParameterValue::Blob(build_aaid(
            &[b"com.example.attacker"],
            &[b"com.google.android.gms"],
        )),
    }];
    assert!(!is_pif_collector_caller(&forged));

    for (uid, master, explicit_key) in [
        (10_000, Some("0"), false),
        (10_000, None, false),
        (10_000, Some("invalid"), false),
        (10_000, Some("1"), true),
        (1000, Some("1"), false),
        (101_000, Some("1"), false),
    ] {
        assert!(!should_modify_attestation(uid, master, explicit_key));
        let policy = RequestPolicy { snapshot: None, patch: None };
        assert_eq!(prepare_keymint_params(&params, &policy), params);
        let original = KeyCreationResult {
            keyBlob: vec![1, 2, 3],
            certificateChain: vec![KeyMintCert { encodedCertificate: vec![4, 5, 6] }],
            ..Default::default()
        };
        let result = maybe_patch_generated_key(&params, original, uid, &policy).result;
        assert_eq!(result.keyBlob, vec![1, 2, 3]);
        assert_eq!(result.certificateChain.len(), 1);
        assert_eq!(result.certificateChain[0].encodedCertificate, vec![4, 5, 6]);
    }
}

#[test]
fn preparation_preserves_non_attestation_and_non_collector_requests() {
    let policy = ready_policy();
    let mut params = collector_params();
    params.retain(|kp| kp.tag != Tag::ATTESTATION_CHALLENGE);
    assert_eq!(prepare_keymint_params(&params, &policy), params);
    params = collector_params();
    params.retain(|kp| kp.tag != Tag::ATTESTATION_APPLICATION_ID);
    assert_eq!(prepare_keymint_params(&params, &policy), params);
}

#[test]
fn unmanaged_rkp_manufacturer_rewrites_only_matching_spoofed_value() {
    let params = vec![
        KeyParameter {
            tag: Tag::ATTESTATION_ID_BRAND,
            value: KeyParameterValue::Blob(b"POCO".to_vec()),
        },
        KeyParameter {
            tag: Tag::ATTESTATION_ID_MANUFACTURER,
            value: KeyParameterValue::Blob(b"nubia".to_vec()),
        },
    ];
    let healed = rewrite_matching_rkp_manufacturer(&params, "nubia", "Xiaomi");
    assert_eq!(
        healed[1].value,
        KeyParameterValue::Blob(b"Xiaomi".to_vec())
    );
    assert_eq!(healed[0].value, KeyParameterValue::Blob(b"POCO".to_vec()));

    // Non-matching manufacturer must be left untouched.
    let untouched = rewrite_matching_rkp_manufacturer(&params, "Google", "Xiaomi");
    assert_eq!(untouched, params);
}

fn synthetic_key_description(challenge: &[u8], boot_digest: &[u8]) -> Vec<u8> {
    let rot_fields = [
        tlv(&[0x04], &[0u8; 32]),
        vec![0x01, 0x01, 0x00],
        vec![0x0a, 0x01, 0x02],
        tlv(&[0x04], boot_digest),
    ]
    .concat();
    let rot_seq = tlv(&[0x30], &rot_fields);
    let hw_rot = [vec![0xbf, 0x85, 0x40, rot_seq.len() as u8], rot_seq].concat();
    let hw_list = tlv(&[0x30], &hw_rot);
    let sw_list = tlv(&[0x30], &[]);
    let body = [
        vec![0x02, 0x02, 0x01, 0x2c],
        vec![0x0a, 0x01, 0x01],
        vec![0x02, 0x02, 0x01, 0x2c],
        vec![0x0a, 0x01, 0x01],
        tlv(&[0x04], challenge),
        tlv(&[0x04], &[]),
        sw_list,
        hw_list,
    ]
    .concat();
    tlv(&[0x30], &body)
}

fn synthetic_x509_from_spki(
    template_der: &[u8],
    spki_der: &[u8],
    signer: &SigningKey,
    key_desc_der: Option<&[u8]>,
) -> Vec<u8> {
    use yasvara_integrity_core::x509::{X509Cert, X509Extension};

    let mut cert = X509Cert::from_der(template_der).unwrap();
    cert.tbs.spki_tlv = spki_der.to_vec();
    cert.tbs.issuer_tlv = cert.tbs.subject_tlv.clone();
    let sig_alg = signer.sig_alg_tlv();
    cert.tbs.sig_alg_tlv = sig_alg.clone();
    if let Some(kd) = key_desc_der {
        let mut exts = cert.tbs.extensions.take().unwrap_or_default();
        exts.push(X509Extension {
            oid: patcher::ATTESTATION_EXT_OID.to_vec(),
            critical: false,
            value: kd.to_vec(),
        });
        cert.tbs.extensions = Some(exts);
    }
    let tbs_der = cert.tbs.to_der();
    let sig = signer.sign(&tbs_der);
    X509Cert::encode_signed(&tbs_der, &sig_alg, &sig)
}

#[test]
fn attest_key_and_child_leaf_match_rkp_root_of_trust_and_verify() {
    use yasvara_integrity_core::x509::X509Cert;

    let batch_key = SigningKey::generate_ec_p256();
    let digest = vec![0x42u8; 32];
    let hw_attest_key = SigningKey::generate_ec_p256();
    let hw_child_key = SigningKey::generate_ec_p256();

    let xml = format!(
        r#"<?xml version="1.0"?><AndroidAttestation><Keybox DeviceID="t"><Key algorithm="ecdsa"><PrivateKey format="pem">{}</PrivateKey><CertificateChain><NumberOfCertificates>2</NumberOfCertificates><Certificate format="pem">-----BEGIN CERTIFICATE-----
MIIBoDCCASWgAwIBAgIUQu3dUezMEEsZdW6YPjZ5wkTkLKYwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWVGVzdCBQMzg0IEludGVybWVkaWF0ZTAeFw0yNjExMDUxODQ4
MDhaFw0zNjExMDIxODQ4MDhaMBoxGDAWBgNVBAMMD1Rlc3QgUDI1NiBCYXRjaDBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABEFwD3FpoMWvZFWrscSOy8sT0BkDwiFp
LEqRs1iuEeZbD/6NT0rO8XRF/r6mI3MSMzvEA0Ikrc2TiLKaFTv3DjWjQjBAMB0G
A1UdDgQWBBQfBk/X4kCV3wkVmgAXQg5s8nr0ijAfBgNVHSMEGDAWgBQT9nsYMaEI
wxK9sytBRQSf29Mu7DAKBggqhkjOPQQDAgNpADBmAjEA+qTXB8R9SNjs+GIJ0M+P
H/JIwv2CSeabODDjIVAZKkThPZyYuFX5z5PEejS386p2AjEAyIxZT2oZElVrGtZ8
6w+4+w3miVuwUKgArp2FkcvANBANomLogRp1pJRtNfPmlD7H
-----END CERTIFICATE-----</Certificate><Certificate format="pem">-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----</Certificate></CertificateChain></Key></Keybox></AndroidAttestation>"#,
        "MHcCAQEEIFcEqNaXTiwRIDlFL1DpWG36lD9VxcZbNllNW2zrNOvooAoGCCqGSM49AwEHoUQDQgAEQXAPcWmgxa9kVauxxI7LyxPQGQPCIWksSpGzWK4R5lsP/o1PSs7xdEX+vqYjcxIzO8QDQiStzZOIspoVO/cONQ=="
    );
    let parsed_kb = keybox::parse_keybox_xml(&xml).unwrap();
    let template_der = parsed_kb.ec.as_ref().unwrap().1[0].clone();

    let raw_attest_leaf =
        synthetic_x509_from_spki(&template_der, &hw_attest_key.to_spki_der(), &hw_attest_key, None);
    assert!(yasvara_integrity_attest::verify_x509_signature(&raw_attest_leaf, &raw_attest_leaf));

    let attest_params = vec![KeyParameter {
        tag: Tag::PURPOSE,
        value: KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY),
    }];
    let mut policy = ready_policy();
    policy.patch.as_mut().unwrap().canonical_boot_digest = digest.clone();
    policy.patch.as_mut().unwrap().keybox = parsed_kb.clone();

    let attest_created = maybe_patch_generated_key(
        &attest_params,
        KeyCreationResult {
            keyBlob: vec![7],
            certificateChain: vec![KeyMintCert { encodedCertificate: raw_attest_leaf }],
            ..Default::default()
        },
        10_000,
        &policy,
    );
    let sw_pkcs8 = attest_created.sw_attest_key.expect("software ATTEST_KEY must be returned");
    let managed_attest_cert = &attest_created.result.certificateChain[0].encodedCertificate;
    assert!(yasvara_integrity_attest::verify_x509_signature(
        managed_attest_cert,
        managed_attest_cert
    ));

    let child_params = collector_params();
    let kd = synthetic_key_description(b"test challenge", &digest);
    let raw_rkp_leaf =
        synthetic_x509_from_spki(&template_der, &hw_child_key.to_spki_der(), &batch_key, Some(&kd));
    let raw_child_leaf =
        synthetic_x509_from_spki(&template_der, &hw_child_key.to_spki_der(), &hw_attest_key, Some(&kd));

    let rkp_result = maybe_patch_generated_key(
        &child_params,
        KeyCreationResult {
            keyBlob: vec![8],
            certificateChain: vec![KeyMintCert { encodedCertificate: raw_rkp_leaf }],
            ..Default::default()
        },
        10_000,
        &policy,
    );
    assert_eq!(rkp_result.result.certificateChain.len(), 3);

    policy.patch.as_mut().unwrap().managed_issuer =
        Some((managed_attest_cert.clone(), SigningKey::from_pkcs8_der(&sw_pkcs8).unwrap()));
    let child_result = maybe_patch_generated_key(
        &child_params,
        KeyCreationResult {
            keyBlob: vec![9],
            certificateChain: vec![KeyMintCert { encodedCertificate: raw_child_leaf.clone() }],
            ..Default::default()
        },
        10_000,
        &policy,
    );
    let patched_child_cert = &child_result.result.certificateChain[0].encodedCertificate;
    assert!(yasvara_integrity_attest::verify_x509_signature(
        patched_child_cert,
        managed_attest_cert
    ));

    let rkp_parsed =
        X509Cert::from_der(&rkp_result.result.certificateChain[0].encodedCertificate).unwrap();
    let child_parsed = X509Cert::from_der(patched_child_cert).unwrap();
    assert_eq!(
        rkp_parsed.find_extension(patcher::ATTESTATION_EXT_OID).unwrap().value,
        child_parsed.find_extension(patcher::ATTESTATION_EXT_OID).unwrap().value
    );

    assert!(validated_imported_attest_key(10_000, &attest_params, &sw_pkcs8).is_some());
    assert!(validated_imported_attest_key(10_000, &child_params, &sw_pkcs8).is_none());
    assert!(validated_imported_attest_key(1000, &attest_params, &sw_pkcs8).is_none());

    assert!(patcher::patch_user_attested_leaf(
        &raw_child_leaf,
        &template_der,
        &SigningKey::from_pkcs8_der(&sw_pkcs8).unwrap(),
        &PatchConfig {
            canonical_boot_digest: &digest,
            boot_key: Some(&[0x11; 32]),
            id_overrides: None,
            os_version: None,
            os_patchlevel: None,
            vendor_patchlevel: None,
            boot_patchlevel: None,
        },
        None,
    )
    .is_none());
}

/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

use super::*;

fn collector_params() -> Vec<KeyParameter> {
    let package = b"com.google.android.gms";
    let mut aaid = vec![0x04, package.len() as u8];
    aaid.extend_from_slice(package);
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
        patch: Some(AttestationContext {
            canonical_boot_digest: vec![1; 32],
            keybox: keybox::KeyboxEntry { ec: None, rsa: None },
            managed_issuer: None,
        }),
    }
}

#[test]
fn disabled_unavailable_and_explicit_signer_policies_preserve_request_and_response() {
    let params = collector_params();
    assert!(is_pif_collector_caller(&params));
    for (uid, master, explicit_key) in [
        (10_000, Some("0"), false),
        (10_000, None, false),
        (10_000, Some("invalid"), false),
        (10_000, Some("1"), true),
        (1000, Some("1"), false),
        (101_000, Some("1"), false),
    ] {
        assert!(!should_modify_attestation(uid, master, explicit_key));
        let policy = RequestPolicy { patch: None };
        assert_eq!(prepare_keymint_params(&params, &policy), params);
        // Opaque bytes suffice: bypass must occur before any DER parsing or keybox access.
        let original = KeyCreationResult {
            keyBlob: vec![1, 2, 3],
            certificateChain: vec![KeyMintCert { encodedCertificate: vec![4, 5, 6] }],
            ..Default::default()
        };
        let result = maybe_patch_creation_result(&params, original, uid, &policy);
        assert_eq!(result.keyBlob, vec![1, 2, 3]);
        assert!(result.keyCharacteristics.is_empty());
        assert_eq!(result.certificateChain.len(), 1);
        assert_eq!(result.certificateChain[0].encodedCertificate, vec![4, 5, 6]);
    }
}

#[test]
fn unavailable_prerequisites_preserve_an_enabled_collectors_request_and_response() {
    let params = collector_params();
    assert!(should_modify_attestation(10_000, Some("1"), false));
    let policy = RequestPolicy { patch: None };
    assert_eq!(prepare_keymint_params(&params, &policy), params);
    let original = KeyCreationResult {
        keyBlob: vec![1, 2, 3],
        certificateChain: vec![KeyMintCert { encodedCertificate: vec![4, 5, 6] }],
        ..Default::default()
    };
    let result = maybe_patch_creation_result(&params, original, 10_000, &policy);
    assert_eq!(result.keyBlob, vec![1, 2, 3]);
    assert!(result.keyCharacteristics.is_empty());
    assert_eq!(result.certificateChain.len(), 1);
    assert_eq!(result.certificateChain[0].encodedCertificate, vec![4, 5, 6]);
}

#[test]
fn enabled_collector_preparation_keeps_existing_unique_id_privacy_policy() {
    let params = collector_params();
    let policy = ready_policy();
    let prepared = prepare_keymint_params(&params, &policy);
    assert_eq!(&prepared[..2], &params[..2]);
    assert_eq!(prepared.len(), params.len() - 4);
    for tag in [
        Tag::ATTESTATION_ID_BRAND,
        Tag::ATTESTATION_ID_DEVICE,
        Tag::ATTESTATION_ID_PRODUCT,
        Tag::ATTESTATION_ID_MANUFACTURER,
        Tag::ATTESTATION_ID_MODEL,
    ] {
        assert!(prepared.iter().any(|kp| kp.tag == tag));
    }
    for tag in [
        Tag::ATTESTATION_ID_SERIAL,
        Tag::ATTESTATION_ID_IMEI,
        Tag::ATTESTATION_ID_MEID,
        Tag::ATTESTATION_ID_SECOND_IMEI,
    ] {
        assert!(!prepared.iter().any(|kp| kp.tag == tag));
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
fn parse_version_number_standard_numeric() {
    assert_eq!(parse_version_number("14"), Some(140000));
    assert_eq!(parse_version_number("14.0"), Some(140000));
    assert_eq!(parse_version_number("14.0.0"), Some(140000));
    assert_eq!(parse_version_number("15"), Some(150000));
    assert_eq!(parse_version_number("15.1"), Some(150100));
    assert_eq!(parse_version_number("15.1.2"), Some(150102));
    assert_eq!(parse_version_number("16"), Some(160000));
    assert_eq!(parse_version_number("17"), Some(170000));
    assert_eq!(parse_version_number("  14  "), Some(140000));
}

#[test]
fn parse_version_number_non_numeric_returns_none() {
    assert_eq!(parse_version_number("CANARY"), None);
    assert_eq!(parse_version_number("Baklava"), None);
    assert_eq!(parse_version_number("VanillaIceCream"), None);
    assert_eq!(parse_version_number(""), None);
    assert_eq!(parse_version_number("   "), None);
    assert_eq!(parse_version_number("abc.1"), None);
}

#[test]
fn infer_version_from_build_id_google_trunk_stable() {
    // Android 17 (CP2 / CP3 / CP4 / DP1 / 2026 Canary ZP11.26*)
    assert_eq!(infer_version_from_build_id("CP2A.260101.001"), Some(170000));
    assert_eq!(infer_version_from_build_id("CP3A.260201.001"), Some(170000));
    assert_eq!(infer_version_from_build_id("CP4A.260301.001"), Some(170000));
    assert_eq!(infer_version_from_build_id("DP1A.260401.001"), Some(170000));
    assert_eq!(infer_version_from_build_id("ZP11.261016.008"), Some(170000));

    // Android 16 (Baklava: 2025 Canary ZP11.25* or Trunk Stable BP2/BP3/BP4/BD/CP1)
    assert_eq!(infer_version_from_build_id("ZP11.250711.001"), Some(160000));
    assert_eq!(infer_version_from_build_id("BP2A.250305.002"), Some(160000));
    assert_eq!(infer_version_from_build_id("BP3A.250505.001"), Some(160000));
    assert_eq!(infer_version_from_build_id("BP4A.250805.001"), Some(160000));
    assert_eq!(infer_version_from_build_id("BD1A.250101.001"), Some(160000));
    assert_eq!(infer_version_from_build_id("CP1A.251001.001"), Some(160000));

    // Android 15 (Vanilla Ice Cream: AP3/AP4/AD/BP1)
    assert_eq!(infer_version_from_build_id("AP3A.241105.008"), Some(150000));
    assert_eq!(infer_version_from_build_id("AP4A.241205.013"), Some(150000));
    assert_eq!(infer_version_from_build_id("AD1A.240901.001"), Some(150000));
    assert_eq!(infer_version_from_build_id("BP1A.250305.001"), Some(150000));

    // Android 14 (Upside Down Cake: AP1/AP2)
    assert_eq!(infer_version_from_build_id("AP1A.240305.019.A1"), Some(140000));
    assert_eq!(infer_version_from_build_id("AP2A.240605.024"), Some(140000));
}

#[test]
fn infer_version_from_build_id_oem_first_letter() {
    // Android 14 (U): OnePlus 12R CPH2585, Samsung, Xiaomi
    assert_eq!(infer_version_from_build_id("UKQ1.230924.001"), Some(140000));
    assert_eq!(infer_version_from_build_id("UP1A.231005.007"), Some(140000));

    // Android 13 (T): Xiaomi TKQ1, Pixel TP1A
    assert_eq!(infer_version_from_build_id("TKQ1.220829.002"), Some(130000));
    assert_eq!(infer_version_from_build_id("TP1A.220905.001"), Some(130000));

    // Android 12 (S): Xiaomi SKQ1, Pixel SP1A
    assert_eq!(infer_version_from_build_id("SKQ1.210908.001"), Some(120000));
    assert_eq!(infer_version_from_build_id("SP1A.210812.016"), Some(120000));

    // Android 11 (R): RQ3A
    assert_eq!(infer_version_from_build_id("RQ3A.211001.001"), Some(110000));

    // Android 10 (Q): QQ3A
    assert_eq!(infer_version_from_build_id("QQ3A.200805.001"), Some(100000));
}

#[test]
fn infer_version_from_build_id_invalid_returns_none() {
    assert_eq!(infer_version_from_build_id(""), None);
    assert_eq!(infer_version_from_build_id("   "), None);
    assert_eq!(infer_version_from_build_id("XYZ1.234567.001"), None);
    assert_eq!(infer_version_from_build_id("123456"), None);
}

#[test]
fn resolve_os_version_pif_active_never_leaks_host() {
    let host_release = Some("17");

    // Active PIF with numeric release (e.g. OnePlus 12R Android 14)
    assert_eq!(
        resolve_os_version_internal(Some("14"), Some("UKQ1.230924.001"), true, host_release),
        Some(140000),
        "Must use PIF release version, not host release"
    );

    // Active PIF with Canary release and Canary build ID (2025 -> A16, 2026 -> A17)
    assert_eq!(
        resolve_os_version_internal(Some("CANARY"), Some("ZP11.250711.001"), true, host_release),
        Some(160000),
        "Must infer Android 16 from 2025 ZP11 build ID, not leak host release"
    );
    assert_eq!(
        resolve_os_version_internal(Some("CANARY"), Some("ZP11.261016.008"), true, host_release),
        Some(170000),
        "Must infer Android 17 from 2026 ZP11 build ID"
    );

    // Active PIF with Baklava release and OEM build ID
    assert_eq!(
        resolve_os_version_internal(Some("Baklava"), Some("UKQ1.230924.001"), true, host_release),
        Some(140000),
        "Must infer Android 14 from UKQ1 build ID"
    );

    // Active PIF with unversioned codename and unrecognized build ID
    assert_eq!(
        resolve_os_version_internal(Some("CANARY"), Some("CUSTOM_ENG_BUILD"), true, host_release),
        Some(0),
        "Pure codename must default to 0 per AOSP Keymaster, not leak host release"
    );

    // Active PIF with empty release and build ID
    assert_eq!(
        resolve_os_version_internal(None, None, true, host_release),
        Some(0),
        "Active PIF without release info must default to 0 to preserve host isolation"
    );
}

#[test]
fn resolve_os_version_pif_inactive_uses_host_rom() {
    assert_eq!(resolve_os_version_internal(None, None, false, Some("17")), Some(170000));
    assert_eq!(resolve_os_version_internal(None, None, false, Some("16.0")), Some(160000));
    assert_eq!(resolve_os_version_internal(None, None, false, None), None);
}

#[test]
fn parse_os_patchlevel_cases() {
    assert_eq!(parse_os_patchlevel("2026-09-05"), Some(202609));
    assert_eq!(parse_os_patchlevel("2024-04-01"), Some(202404));
    assert_eq!(parse_os_patchlevel("  2024-04-01  "), Some(202404));
    assert_eq!(parse_os_patchlevel(""), None);
    assert_eq!(parse_os_patchlevel("invalid-patch"), None);
}

#[test]
fn parse_long_patch_cases() {
    assert_eq!(parse_long_patch("2026-09-05"), Some(20260905));
    assert_eq!(parse_long_patch("2024-04-01"), Some(20240401));
    assert_eq!(parse_long_patch("2024-04"), Some(20240401));
    assert_eq!(parse_long_patch(""), None);
}

#[test]
fn droidguard_play_integrity_attestation_correlation() {
    // DroidGuard / Play Integrity verification simulation on certified OnePlus 12R profile
    let pif_release = "14";
    let pif_build_id = "UKQ1.230924.001";
    let pif_patch = "2024-04-01";
    let host_release = "17";

    let os_version = resolve_os_version_internal(
        Some(pif_release),
        Some(pif_build_id),
        true,
        Some(host_release),
    )
    .expect("os_version must resolve");

    let os_patchlevel = parse_os_patchlevel(pif_patch).expect("os_patchlevel must resolve");
    let long_patch = parse_long_patch(pif_patch).expect("long_patch must resolve");

    // DroidGuard checks:
    // 1. Tag 705 (OS_VERSION): major version == 14
    assert_eq!(os_version / 10000, 14, "Major OS version must match PIF Android 14");
    assert_eq!(os_version, 140000);

    // 2. Tag 706 (OS_PATCHLEVEL): YYYYMM == 202404
    assert_eq!(os_patchlevel, 202404, "Tag 706 must match PIF security patch YYYYMM");

    // 3. Tags 718/719 (VENDOR_PATCHLEVEL / BOOT_PATCHLEVEL): YYYYMMDD == 20240401
    assert_eq!(long_patch, 20240401, "Tags 718/719 must match PIF security patch YYYYMMDD");
}

#[test]
fn resolve_os_version_prefers_staged_ssot_over_fallback() {
    assert_eq!(
        resolve_os_version_with_staged(
            Some("160000"),
            Some("CANARY"),
            Some("CUSTOM"),
            true,
            Some("17")
        ),
        Some(160000)
    );
    // Explicit "0" staged for unrecognized Canary codenames must win over host 17.
    assert_eq!(
        resolve_os_version_with_staged(Some("0"), Some("14"), Some("UKQ1"), true, Some("17")),
        Some(0)
    );
    // Absent or invalid staged os_version falls back cleanly.
    assert_eq!(
        resolve_os_version_with_staged(None, Some("15"), None, true, Some("17")),
        Some(150000)
    );
    assert_eq!(
        resolve_os_version_with_staged(Some("bad"), None, None, false, Some("17")),
        Some(170000)
    );
}

fn synthetic_key_description(challenge: &[u8], boot_digest: &[u8]) -> Vec<u8> {
    fn der_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = val.len();
        if n < 0x80 {
            out.push(n as u8);
        } else if n <= 0xff {
            out.extend_from_slice(&[0x81, n as u8]);
        } else {
            out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(val);
        out
    }
    let rot_fields = [
        der_tlv(0x04, &[0u8; 32]),      // verifiedBootKey (all zero = unlocked)
        vec![0x01, 0x01, 0x00],         // deviceLocked = FALSE
        vec![0x0a, 0x01, 0x02],         // verifiedBootState = Unverified(2)
        der_tlv(0x04, boot_digest),     // verifiedBootHash
    ]
    .concat();
    let rot_seq = der_tlv(0x30, &rot_fields);
    // Tag::ROOT_OF_TRUST (704) -> 0xbf 0x85 0x40
    let hw_rot = [vec![0xbf, 0x85, 0x40, rot_seq.len() as u8], rot_seq].concat();
    let hw_list = der_tlv(0x30, &hw_rot);
    let sw_list = der_tlv(0x30, &[]);
    let body = [
        vec![0x02, 0x02, 0x01, 0x2c], // attestationVersion = 300
        vec![0x0a, 0x01, 0x01],       // attestationSecurityLevel = TEE(1)
        vec![0x02, 0x02, 0x01, 0x2c], // keymasterVersion = 300
        vec![0x0a, 0x01, 0x01],       // keymasterSecurityLevel = TEE(1)
        der_tlv(0x04, challenge),
        der_tlv(0x04, &[]),
        sw_list,
        hw_list,
    ]
    .concat();
    der_tlv(0x30, &body)
}

fn synthetic_x509_from_spki(
    template_der: &[u8],
    spki_der: &[u8],
    signer: &keybox::SigningKey,
    key_desc_der: Option<&[u8]>,
) -> Vec<u8> {
    use x509_cert::der::asn1::{BitString, OctetString};
    use x509_cert::der::{Decode, Encode};
    use x509_cert::ext::Extension;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::Certificate;

    let mut cert = Certificate::from_der(template_der).unwrap();
    cert.tbs_certificate.subject_public_key_info =
        SubjectPublicKeyInfoOwned::from_der(spki_der).unwrap();
    cert.tbs_certificate.issuer = cert.tbs_certificate.subject.clone();
    let sig_alg = signer.sig_algorithm();
    cert.tbs_certificate.signature = sig_alg.clone();
    if let Some(kd) = key_desc_der {
        let mut exts = cert.tbs_certificate.extensions.take().unwrap_or_default();
        exts.push(Extension {
            extn_id: patcher::ATTESTATION_EXT_OID,
            critical: false,
            extn_value: OctetString::new(kd).unwrap(),
        });
        cert.tbs_certificate.extensions = Some(exts);
    }
    let tbs_der = cert.tbs_certificate.to_der().unwrap();
    let sig = BitString::from_bytes(&signer.sign(&tbs_der)).unwrap();
    Certificate { tbs_certificate: cert.tbs_certificate, signature_algorithm: sig_alg, signature: sig }
        .to_der()
        .unwrap()
}

#[test]
fn attest_key_and_child_leaf_match_rkp_root_of_trust_and_verify() {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // Minimal self-signed P-256 cert template borrowed from standard X.509 fixture.
    let batch_key = keybox::SigningKey::generate_ec_p256();
    let digest = vec![0x42u8; 32];
    let hw_attest_key = keybox::SigningKey::generate_ec_p256();
    let hw_child_key = keybox::SigningKey::generate_ec_p256();

    // Bootstrap template cert via existing patch_leaf fixture? Construct from keybox cert DER.
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

    // 1. Provision an unchallenged PURPOSE_ATTEST_KEY -> must swap SPKI, drop stale SKI/AKI, self-sign.
    let raw_attest_leaf =
        synthetic_x509_from_spki(&template_der, &hw_attest_key.to_spki_der(), &hw_attest_key, None);
    assert!(keystore2_crypto::verify_x509_signature(&raw_attest_leaf, &raw_attest_leaf));

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
    assert_eq!(attest_created.result.certificateChain.len(), 1);
    let managed_attest_cert = &attest_created.result.certificateChain[0].encodedCertificate;
    assert!(
        keystore2_crypto::verify_x509_signature(managed_attest_cert, managed_attest_cert),
        "managed ATTEST_KEY self-signed cert must verify under its swapped public key"
    );
    let parsed_attest = Certificate::from_der(managed_attest_cert).unwrap();
    assert_ne!(
        parsed_attest.tbs_certificate.subject_public_key_info,
        Certificate::from_der(&template_der).unwrap().tbs_certificate.subject_public_key_info
    );
    assert!(
        parsed_attest.tbs_certificate.extensions.as_ref().is_none_or(|exts| exts
            .iter()
            .all(|e| e.extn_id != patcher::SUBJECT_KEY_ID_OID
                && e.extn_id != patcher::AUTHORITY_KEY_ID_OID)),
        "managed ATTEST_KEY cert must not carry stale SKI/AKI from discarded hardware key"
    );

    // 2. Attest a child key on BOTH paths (RKP vs UserGenerated managed ATTEST_KEY).
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

    policy.patch.as_mut().unwrap().managed_issuer = Some((
        managed_attest_cert.clone(),
        keybox::SigningKey::from_pkcs8_der(&sw_pkcs8).unwrap(),
    ));
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
    assert!(child_result.sw_attest_key.is_none());
    assert_eq!(child_result.result.certificateChain.len(), 1);
    let patched_child_cert = &child_result.result.certificateChain[0].encodedCertificate;
    assert!(
        keystore2_crypto::verify_x509_signature(patched_child_cert, managed_attest_cert),
        "ATTEST_KEY child cert must verify cryptographically against the managed ATTEST_KEY cert"
    );

    // Both paths must emit the exact same patched KeyDescription (RootOfTrust + OS/patch/IDs).
    let rkp_parsed =
        Certificate::from_der(&rkp_result.result.certificateChain[0].encodedCertificate).unwrap();
    let child_parsed = Certificate::from_der(patched_child_cert).unwrap();
    let find_kd = |c: &Certificate| {
        c.tbs_certificate
            .extensions
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.extn_id == patcher::ATTESTATION_EXT_OID)
            .unwrap()
            .extn_value
            .as_bytes()
            .to_vec()
    };
    assert_eq!(
        find_kd(&rkp_parsed),
        find_kd(&child_parsed),
        "RKP and ATTEST_KEY paths must produce identical RootOfTrust / KeyDescription"
    );
    assert_eq!(child_parsed.tbs_certificate.issuer, parsed_attest.tbs_certificate.subject);

    // 3. Import validation accepts PKCS#8 with PURPOSE_ATTEST_KEY for apps, rejects otherwise.
    assert!(validated_imported_attest_key(10_000, &attest_params, &sw_pkcs8).is_some());
    assert!(validated_imported_attest_key(10_000, &child_params, &sw_pkcs8).is_none());
    assert!(validated_imported_attest_key(1000, &attest_params, &sw_pkcs8).is_none());

    // 4. Mismatched issuer SPKI vs stored signing key preserves original hardware cert.
    assert!(patcher::patch_user_attested_leaf(
        &raw_child_leaf,
        &template_der,
        &keybox::SigningKey::from_pkcs8_der(&sw_pkcs8).unwrap(),
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

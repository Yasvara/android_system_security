/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

use super::*;

fn config(digest: &[u8]) -> PatchConfig<'_> {
    PatchConfig {
        canonical_boot_digest: digest,
        boot_key: None,
        id_overrides: None,
        os_version: None,
        os_patchlevel: None,
        vendor_patchlevel: None,
        boot_patchlevel: None,
    }
}

fn root_fields(key: &[u8], digest: &[u8]) -> Vec<Vec<u8>> {
    vec![
        tlv(&[0x04], key),
        vec![0x01, 0x01, 0x00], // Original unlocked device.
        vec![0x0a, 0x01, 0x02], // Original Unverified state.
        tlv(&[0x04], digest),
    ]
}

fn root(fields: &[Vec<u8>]) -> Vec<u8> {
    tlv(&context_tag(TAG_ROOT_OF_TRUST), &tlv(&[0x30], &fields.concat()))
}

fn description(sw: &[u8], hw: &[u8], attest_level: u8, keymaster_level: u8) -> Vec<u8> {
    tlv(
        &[0x30],
        &[
            tlv(&[0x02], &der_uint(400)),
            vec![0x0a, 0x01, attest_level],
            tlv(&[0x02], &der_uint(300)),
            vec![0x0a, 0x01, keymaster_level],
            tlv(&[0x04], b"test challenge"),
            tlv(&[0x04], b"test unique ID"),
            tlv(&[0x30], sw),
            tlv(&[0x30], hw),
        ]
        .concat(),
    )
}

fn description_fields(raw: &[u8]) -> Vec<&[u8]> {
    split_elems(read_single(raw).unwrap().value, 8).unwrap()
}

fn authorization(list: &[u8], tag: u32) -> Option<&[u8]> {
    split_elems(read_list(list).unwrap(), MAX_AUTHORIZATION_FIELDS)
        .unwrap()
        .into_iter()
        .find(|field| context_tag_number(read_single(field).unwrap().tag) == Some(tag))
}

#[test]
fn modification_policy_requires_enabled_master_and_preserves_explicit_signers() {
    for uid in [10_000, 110_000] {
        assert!(should_modify_attestation(uid, Some("1"), false));
        for master in [None, Some("0"), Some(""), Some("false"), Some("garbage"), Some("2")] {
            assert!(!should_modify_attestation(uid, master, false));
            assert!(!should_modify_attestation(uid, master, true));
        }
        assert!(!should_modify_attestation(uid, Some("1"), true));
    }
    for uid in [0, 1000, 9999, 101_000] {
        assert!(!should_modify_attestation(uid, Some("1"), false));
    }
}

#[test]
fn patch_parsers_preserve_valid_dates_and_month_only_inputs() {
    for (input, long, short) in [
        ("2026-09-05", 20260905, 202609),
        (" 2024-04-01 ", 20240401, 202404),
        ("2024-04", 20240401, 202404),
        ("2024-02-29", 20240229, 202402),
        ("2000-02-29", 20000229, 200002),
        ("0001-01-01", 10101, 101),
        ("9999-12-31", 99991231, 999912),
    ] {
        assert_eq!(parse_long_patch(input), Some(long), "{}", input);
        assert_eq!(parse_os_patchlevel(input), Some(short), "{}", input);
    }
}

#[test]
fn patch_parsers_reject_malformed_out_of_range_and_overflowing_dates() {
    for input in [
        "",
        "2024",
        "2024-",
        "2024-04-",
        "2024-04-bad",
        "2024-04-01-extra",
        "2024-04-01-",
        "2024-00-01",
        "2024-13-01",
        "2024-01-00",
        "2024-01-32",
        "2024-04-31",
        "2023-02-29",
        "1900-02-29",
        "2024-02-30",
        "0000-01-01",
        "2024-4-01",
        "2024-04-1",
        "24-04-01",
        "+024-04-01",
        "2024-+4-01",
        "2024-04-+1",
        "2024- 4-01",
        "2024-04-01junk",
        "２０２４-04-01",
        "4294967295-12-31",
        "4294967296-12-31",
        "429497-01-01",
        "42949673-01",
        "2024-4294967295-01",
        "2024-04-4294967295",
        "18446744073709551616-01-01",
    ] {
        assert_eq!(parse_long_patch(input), None, "accepted long patch {:?}", input);
        assert_eq!(parse_os_patchlevel(input), None, "accepted OS patch {:?}", input);
    }
}

#[test]
fn version_parser_preserves_optional_components_and_valid_boundaries() {
    for (input, expected) in [
        ("0", 0),
        ("14", 140000),
        ("14.0", 140000),
        ("15.1.2", 150102),
        (" 17.0.0 ", 170000),
        ("99.99.99", 999999),
        ("01.02.03", 10203),
    ] {
        assert_eq!(parse_version_number(input), Some(expected), "{}", input);
    }
}

#[test]
fn version_parser_rejects_malformed_out_of_range_and_overflowing_components() {
    for input in [
        "",
        "CANARY",
        "14.",
        "14..1",
        "14.0.",
        "14.bad",
        "14.0.bad",
        "14.0.0.1",
        "14.0.0.",
        "14.0.0junk",
        "+14",
        "-14",
        "14.+1",
        "14.0.-1",
        "14. 1",
        "１４",
        "100",
        "14.100",
        "14.0.100",
        "000",
        "14.000",
        "14.0.000",
        "4294967295",
        "4294967296",
        "429497",
        "14.42949673",
        "14.0.4294967295",
        "18446744073709551616.0.0",
    ] {
        assert_eq!(parse_version_number(input), None, "accepted version {:?}", input);
    }
}

#[test]
fn decimal_parser_uses_checked_arithmetic() {
    assert_eq!(parse_decimal("4294967295"), Some(u32::MAX));
    assert_eq!(parse_decimal("4294967296"), None);
    assert_eq!(parse_decimal("18446744073709551616"), None);
    assert_eq!(parse_decimal("+1"), None);
    assert_eq!(parse_decimal(""), None);
}

#[test]
fn canonical_digest_accepts_lowercase_sha256_and_sha512() {
    let sha256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    assert_eq!(parse_boot_digest(Some(sha256)).unwrap(), (0u8..32).collect::<Vec<_>>());
    assert_eq!(parse_boot_digest(Some(&"ab".repeat(64))).unwrap(), vec![0xab; 64]);
    assert_eq!(parse_boot_digest(Some(&"00".repeat(32))).unwrap(), vec![0; 32]);
}

#[test]
fn canonical_digest_rejects_missing_malformed_uppercase_and_whitespace() {
    assert!(parse_boot_digest(None).is_err());
    for value in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "a".repeat(127),
        "a".repeat(129),
        "AB".repeat(32),
        "ag".repeat(32),
        " a".repeat(32),
        "é".repeat(32),
        format!(" {}", "ab".repeat(32)),
        format!("{}\n", "ab".repeat(32)),
        format!("0x{}", "ab".repeat(32)),
    ] {
        assert!(parse_boot_digest(Some(&value)).is_err(), "accepted invalid digest");
    }
}

#[test]
fn original_caller_guard_uses_android_app_id_in_every_user() {
    for uid in [0, 1000, 1017, 9999, 100_000, 101_000, 109_999, 201_000] {
        assert!(!is_app_uid(uid), "non-app uid {} must keep raw attestations", uid);
    }
    for uid in [10_000, 19_999, 99_000, 110_000, 199_999, 210_000] {
        assert!(is_app_uid(uid), "app uid {} should pass the UID guard", uid);
    }
}

#[test]
fn original_unverified_allzero_key_and_unlocked_state_are_preserved_verbatim() {
    let digest = [0x56; 32];
    let original_root = root(&root_fields(&[0; 32], &digest));
    let original = description(&[], &original_root, 0, 2);
    let patched = patch_key_description(&original, &config(&digest)).unwrap();
    // RootOfTrust is now spoofed, so patched != original
    assert_ne!(patched.der, original);
    // Boot key and hash are preserved, but locked/state are spoofed
    let hw = description_fields(&patched.der)[7];
    let rot_field = authorization(hw, TAG_ROOT_OF_TRUST).unwrap();
    let rot_elem = read_single(rot_field).unwrap();
    let rot_seq = read_single(rot_elem.value).unwrap();
    let rot_fields = split_elems(rot_seq.value, 4).unwrap();
    // Boot key preserved
    assert_eq!(read_single(rot_fields[0]).unwrap().value, [0u8; 32]);
    // deviceLocked spoofed to TRUE
    assert_eq!(rot_fields[1], [0x01, 0x01, 0xff]);
    // verifiedBootState spoofed to Verified(0)
    assert_eq!(rot_fields[2], [0x0a, 0x01, 0x00]);
    // Boot hash preserved
    assert_eq!(read_single(rot_fields[3]).unwrap().value, digest);
}

#[test]
fn original_boot_key_is_not_hashed_normalized_or_replaced() {
    let digest = [0x31; 32];
    for key in [Vec::new(), vec![0; 32], (0u8..80).collect()] {
        let original = description(&[], &root(&root_fields(&key, &digest)), 1, 1);
        let patched = patch_key_description(&original, &config(&digest)).unwrap();
        let hw = description_fields(&patched.der)[7];
        let rot_field = authorization(hw, TAG_ROOT_OF_TRUST).unwrap();
        let rot_elem = read_single(rot_field).unwrap();
        let rot_seq = read_single(rot_elem.value).unwrap();
        let rot_fields = split_elems(rot_seq.value, 4).unwrap();
        assert_eq!(read_single(rot_fields[0]).unwrap().value, key.as_slice());
    }
}

#[test]
fn zero_boot_key_is_replaced_when_fallback_is_configured() {
    let digest = [0x31; 32];
    let fallback = [0x5a; 32];
    for key in [Vec::new(), vec![0; 32]] {
        let original = description(&[], &root(&root_fields(&key, &digest)), 1, 1);
        let mut cfg = config(&digest);
        cfg.boot_key = Some(&fallback);
        let patched = patch_key_description(&original, &cfg).unwrap();
        let hw = description_fields(&patched.der)[7];
        let rot_elem = read_single(authorization(hw, TAG_ROOT_OF_TRUST).unwrap()).unwrap();
        let rot_seq = read_single(rot_elem.value).unwrap();
        let rot_fields = split_elems(rot_seq.value, 4).unwrap();
        assert_eq!(read_single(rot_fields[0]).unwrap().value, fallback);
    }
}

#[test]
fn all_original_boot_states_and_security_levels_are_preserved() {
    let digest = [0x71; 32];
    for state in 0..=3 {
        for locked in [0x00, 0xff] {
            for attest_level in 0..=2 {
                for keymaster_level in 0..=2 {
                    let mut fields = root_fields(&[0; 32], &digest);
                    fields[1] = vec![0x01, 0x01, locked];
                    fields[2] = vec![0x0a, 0x01, state];
                    let original = description(&[], &root(&fields), attest_level, keymaster_level);
                    let patched = patch_key_description(&original, &config(&digest)).unwrap();
                    assert_eq!(patched.attestation_version, 400);
                    assert_eq!(patched.attestation_security_level, u32::from(attest_level));
                    assert_eq!(patched.keymaster_security_level, u32::from(keymaster_level));
                    // RootOfTrust always spoofed to locked + Verified
                    let hw = description_fields(&patched.der)[7];
                    let rot_field = authorization(hw, TAG_ROOT_OF_TRUST).unwrap();
                    let rot_elem = read_single(rot_field).unwrap();
                    let rot_seq = read_single(rot_elem.value).unwrap();
                    let rot_fields = split_elems(rot_seq.value, 4).unwrap();
                    assert_eq!(
                        rot_fields[1],
                        [0x01, 0x01, 0xff],
                        "deviceLocked must be spoofed to TRUE"
                    );
                    assert_eq!(
                        rot_fields[2],
                        [0x0a, 0x01, 0x00],
                        "verifiedBootState must be spoofed to Verified"
                    );
                }
            }
        }
    }
}

#[test]
fn matching_sha512_hash_is_preserved_without_truncation() {
    let digest = parse_boot_digest(Some(&"ba".repeat(64))).unwrap();
    let original = description(&[], &root(&root_fields(&[0; 32], &digest)), 2, 2);
    let patched = patch_key_description(&original, &config(&digest)).unwrap();
    // RootOfTrust is spoofed so full DER differs; but the hash must survive intact.
    let hw = description_fields(&patched.der)[7];
    let rot_field = authorization(hw, TAG_ROOT_OF_TRUST).unwrap();
    let rot_elem = read_single(rot_field).unwrap();
    let rot_seq = read_single(rot_elem.value).unwrap();
    let rot_fields = split_elems(rot_seq.value, 4).unwrap();
    assert_eq!(read_single(rot_fields[3]).unwrap().value, digest.as_slice());
}

#[test]
fn mismatching_sha256_sha512_and_cross_algorithm_hashes_refuse_patch() {
    for size in [32, 64] {
        let digest = vec![0x12; size];
        let original = description(&[], &root(&root_fields(&[0; 32], &digest)), 1, 1);
        let mut mismatch = digest.clone();
        mismatch[size - 1] ^= 1;
        let error = patch_key_description(&original, &config(&mismatch)).err().unwrap();
        assert!(error.contains("verifiedBootHash disagrees with ro.yasvara.boot.digest"));
        let other_algorithm = vec![0x12; if size == 32 { 64 } else { 32 }];
        assert!(patch_key_description(&original, &config(&other_algorithm)).is_err());
    }
}

#[test]
fn invalid_binary_canonical_digest_refuses_patch() {
    let digest = [0x12; 32];
    let original = description(&[], &root(&root_fields(&[0; 32], &digest)), 1, 1);
    for size in [0, 1, 31, 33, 63, 65] {
        assert!(patch_key_description(&original, &config(&vec![0x12; size])).is_err());
    }
}

#[test]
fn missing_software_only_and_duplicate_roots_refuse_patch() {
    let digest = [0x12; 32];
    let original_root = root(&root_fields(&[0; 32], &digest));
    for (sw, hw, expected) in [
        (vec![], vec![], "missing"),
        (original_root.clone(), vec![], "software-enforced"),
        (original_root.clone(), original_root.clone(), "software-enforced"),
        (vec![], [original_root.clone(), original_root.clone()].concat(), "duplicate"),
    ] {
        let original = description(&sw, &hw, 1, 1);
        let error = patch_key_description(&original, &config(&digest)).err().unwrap();
        assert!(error.contains(expected), "{}", error);
    }
}

#[test]
fn malformed_root_fields_refuse_patch() {
    let digest = [0x12; 32];
    let fields = root_fields(&[0; 32], &digest);
    let mut bad_roots = vec![fields[..3].to_vec(), [fields.clone(), vec![vec![0x05, 0]]].concat()];
    for (index, replacement) in [
        (0, vec![0x05, 0]),
        (1, vec![0x01, 0x01, 0x01]),
        (1, vec![0x01, 0x00]),
        (1, vec![0x04, 0x01, 0x00]),
        (2, vec![0x0a, 0x01, 0x04]),
        (2, vec![0x0a, 0x01, 0xff]),
        (2, vec![0x0a, 0x00]),
        (2, vec![0x0a, 0x02, 0x00, 0x02]),
        (2, vec![0x02, 0x01, 0x02]),
        (3, vec![0x05, 0]),
        (3, tlv(&[0x04], &[0x12; 31])),
        (3, tlv(&[0x04], &[0x12; 33])),
        (3, tlv(&[0x04], &[0x12; 63])),
    ] {
        let mut malformed = fields.clone();
        malformed[index] = replacement;
        bad_roots.push(malformed);
    }
    for malformed in bad_roots {
        let original = description(&[], &root(&malformed), 1, 1);
        assert!(patch_key_description(&original, &config(&digest)).is_err());
    }
    let malformed = tlv(&context_tag(TAG_ROOT_OF_TRUST), &[0x04, 0]);
    assert!(patch_key_description(&description(&[], &malformed, 1, 1), &config(&digest)).is_err());
}

#[test]
fn nonboot_overrides_still_apply_without_changing_root_or_security_levels() {
    let digest = [0x12; 32];
    let original_root = root(&root_fields(&[0; 32], &digest));
    let sw =
        [explicit_integer(TAG_OS_VERSION, 130000), explicit_integer(TAG_OS_PATCHLEVEL, 202601)]
            .concat();
    let id_values = [
        (TAG_ATTESTATION_ID_BRAND, "brand"),
        (TAG_ATTESTATION_ID_DEVICE, "device"),
        (TAG_ATTESTATION_ID_PRODUCT, "product"),
        (TAG_ATTESTATION_ID_MANUFACTURER, "manufacturer"),
        (TAG_ATTESTATION_ID_MODEL, "model"),
    ];
    let mut hw = original_root.clone();
    for (tag, _) in id_values {
        hw.extend_from_slice(&explicit_octet_string(tag, b"old"));
    }
    let original_serial = explicit_octet_string(TAG_ATTESTATION_ID_SERIAL, b"unchanged serial");
    let original_imei = explicit_octet_string(TAG_ATTESTATION_ID_IMEI, b"862948071104480");
    let original_imei2 = explicit_octet_string(TAG_ATTESTATION_ID_SECOND_IMEI, b"862948071104498");
    hw.extend_from_slice(&original_serial);
    hw.extend_from_slice(&original_imei);
    hw.extend_from_slice(&explicit_integer(TAG_BOOT_PATCHLEVEL, 20260105));
    hw.extend_from_slice(&original_imei2);
    let original = description(&sw, &hw, 0, 2);
    let ids = DeviceIdOverrides {
        brand: "brand".into(),
        device: "device".into(),
        product: "product".into(),
        manufacturer: "manufacturer".into(),
        model: "model".into(),
    };
    let mut overrides = config(&digest);
    overrides.id_overrides = Some(&ids);
    overrides.os_version = Some(170000);
    overrides.os_patchlevel = Some(202610);
    overrides.vendor_patchlevel = Some(20261005);
    overrides.boot_patchlevel = Some(20261005);
    let patched = patch_key_description(&original, &overrides).unwrap();
    let before = description_fields(&original);
    let after = description_fields(&patched.der);
    assert_eq!(&after[..6], &before[..6]);
    // RootOfTrust is spoofed: locked + Verified, but key/hash preserved.
    let rot_field = authorization(after[7], TAG_ROOT_OF_TRUST).unwrap();
    let rot_elem = read_single(rot_field).unwrap();
    let rot_seq = read_single(rot_elem.value).unwrap();
    let rot_fields = split_elems(rot_seq.value, 4).unwrap();
    assert_eq!(read_single(rot_fields[0]).unwrap().value, [0u8; 32]);
    assert_eq!(rot_fields[1], [0x01, 0x01, 0xff]);
    assert_eq!(rot_fields[2], [0x0a, 0x01, 0x00]);
    assert_eq!(read_single(rot_fields[3]).unwrap().value, digest);
    assert_eq!(authorization(after[6], TAG_ROOT_OF_TRUST), None);
    assert_eq!(
        authorization(after[6], TAG_OS_VERSION),
        Some(explicit_integer(TAG_OS_VERSION, 170000).as_slice())
    );
    assert_eq!(
        authorization(after[6], TAG_OS_PATCHLEVEL),
        Some(explicit_integer(TAG_OS_PATCHLEVEL, 202610).as_slice())
    );
    for (tag, value) in id_values {
        assert_eq!(
            authorization(after[7], tag),
            Some(explicit_octet_string(tag, value.as_bytes()).as_slice())
        );
    }
    // When PIF id_overrides are active, hardware-unique identifiers (SERIAL/IMEI/SECOND_IMEI)
    // must be stripped so the real device TAC/serial never contradicts the PIF model.
    assert_eq!(authorization(after[7], TAG_ATTESTATION_ID_SERIAL), None);
    assert_eq!(authorization(after[7], TAG_ATTESTATION_ID_IMEI), None);
    assert_eq!(authorization(after[7], TAG_ATTESTATION_ID_SECOND_IMEI), None);
    for tag in [TAG_VENDOR_PATCHLEVEL, TAG_BOOT_PATCHLEVEL] {
        assert_eq!(authorization(after[7], tag), Some(explicit_integer(tag, 20261005).as_slice()));
    }

    // Without PIF id_overrides, hardware serial/IMEI are preserved as-is.
    let mut no_id_overrides = config(&digest);
    no_id_overrides.id_overrides = None;
    let patched_no_pif = patch_key_description(&original, &no_id_overrides).unwrap();
    let after_no_pif = description_fields(&patched_no_pif.der);
    assert_eq!(
        authorization(after_no_pif[7], TAG_ATTESTATION_ID_SERIAL),
        Some(original_serial.as_slice())
    );
    assert_eq!(
        authorization(after_no_pif[7], TAG_ATTESTATION_ID_IMEI),
        Some(original_imei.as_slice())
    );
    assert_eq!(
        authorization(after_no_pif[7], TAG_ATTESTATION_ID_SECOND_IMEI),
        Some(original_imei2.as_slice())
    );
}

#[test]
fn der_reader_rejects_unbounded_tags_and_noncanonical_or_truncated_lengths() {
    for malformed in [
        &[][..],
        &[0x00, 0x00],
        &[0xbf],
        &[0xbf, 0x81],
        &[0xbf, 0x80, 0x1f, 0x00],
        &[0xbf, 0x1e, 0x00],
        &[0xbf, 0x90, 0x80, 0x80, 0x80, 0x00, 0x00],
        &[0xbf, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00, 0x00],
        &[0x30],
        &[0x30, 0x80, 0x00, 0x00],
        &[0x04, 0x81],
        &[0x04, 0x81, 0x01, 0x00],
        &[0x04, 0x82, 0x00, 0x80],
        &[0x04, 0x82, 0x01],
        &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff],
        &[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
        &[0x04, 0x02, 0x00],
    ] {
        assert!(read_elem(malformed).is_err(), "accepted malformed DER: {:x?}", malformed);
    }
}

#[test]
fn trailing_der_at_top_and_inside_root_refuses_patch() {
    let digest = [0x12; 32];
    let original_root = root(&root_fields(&[0; 32], &digest));
    let mut original = description(&[], &original_root, 1, 1);
    original.extend_from_slice(&[0x05, 0x00]);
    assert!(patch_key_description(&original, &config(&digest)).is_err());

    let mut root_value = read_single(&original_root).unwrap().value.to_vec();
    root_value.extend_from_slice(&[0x05, 0]);
    let malformed = tlv(&context_tag(TAG_ROOT_OF_TRUST), &root_value);
    assert!(patch_key_description(&description(&[], &malformed, 1, 1), &config(&digest)).is_err());
}

#[test]
fn der_size_and_authorization_count_are_bounded() {
    let digest = [0x12; 32];
    assert!(patch_key_description(&vec![0; MAX_KEY_DESCRIPTION_LEN + 1], &config(&digest)).is_err());
    let mut hw = tlv(&context_tag(1), &[0x05, 0]).repeat(MAX_AUTHORIZATION_FIELDS);
    hw.extend_from_slice(&root(&root_fields(&[0; 32], &digest)));
    let original = description(&[], &hw, 1, 1);
    let error = patch_key_description(&original, &config(&digest)).err().unwrap();
    assert!(error.contains("field count exceeds bound"));
}

#[test]
fn every_truncation_is_rejected_and_single_byte_mutations_do_not_panic() {
    let digest = [0x12; 64];
    let original = description(&[], &root(&root_fields(&[0; 32], &digest)), 1, 2);
    for end in 0..original.len() {
        assert!(patch_key_description(&original[..end], &config(&digest)).is_err());
    }
    for index in 0..original.len() {
        for byte in [0x00, 0x7f, 0x80, 0xff] {
            let mut mutated = original.clone();
            mutated[index] = byte;
            let _ = patch_key_description(&mutated, &config(&digest));
        }
    }
}

#[test]
fn all_zero_hardware_boot_hash_is_replaced_with_canonical_digest() {
    let canonical = [0x30; 32];
    let zero_hw_hash = [0x00; 32];
    let original = description(&[], &root(&root_fields(&[0; 32], &zero_hw_hash)), 1, 1);
    let patched = patch_key_description(&original, &config(&canonical)).unwrap();
    let hw = description_fields(&patched.der)[7];
    let rot_elem = read_single(authorization(hw, TAG_ROOT_OF_TRUST).unwrap()).unwrap();
    let rot_seq = read_single(rot_elem.value).unwrap();
    let rot_fields = split_elems(rot_seq.value, 4).unwrap();
    assert_eq!(read_single(rot_fields[3]).unwrap().value, canonical);
}

#[test]
fn oversized_attestation_challenges_are_rejected() {
    let digest = [0x12; 32];
    for size in [129usize, 256, 512, 4096] {
        let raw = tlv(
            &[0x30],
            &[
                tlv(&[0x02], &der_uint(300)),
                vec![0x0a, 0x01, 1],
                tlv(&[0x02], &der_uint(300)),
                vec![0x0a, 0x01, 1],
                tlv(&[0x04], &vec![0x41; size]),
                tlv(&[0x04], b"test unique ID"),
                tlv(&[0x30], &[]),
                tlv(&[0x30], &root(&root_fields(&[0; 32], &digest))),
            ]
            .concat(),
        );
        assert!(
            patch_key_description(&raw, &config(&digest)).is_err(),
            "accepted oversized challenge of {} bytes",
            size
        );
    }
}

/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

//! Razor-thin KeyMint AIDL adapter for Yasvara attestation protection.
//!
//! All pure DER/AAID/digest/version/patch-override logic lives in `yasvara_integrity_core`,
//! and all BoringSSL X.509/keybox/re-signing logic lives in `yasvara_integrity_attest`.

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Certificate::Certificate as KeyMintCert, EcCurve::EcCurve,
    KeyCharacteristics::KeyCharacteristics, KeyCreationResult::KeyCreationResult,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
    Tag::Tag,
};
use log::{info, warn};
use rustutils::android::system_properties;

use yasvara_integrity_attest::keybox::{self, KeyboxEntry, SigningKey};
use yasvara_integrity_attest::patcher;
use yasvara_integrity_attest::policy as attest_policy;
use yasvara_integrity_core::contract::{
    ATTEST_DIR, BASE_ATTEST_TARGETS, PATCH_OVERRIDE_FILENAME, PROP_BOOT_DIGEST,
    PROP_BOOT_VBMETA_PUBKEY_DIGEST, PROP_PATCH_OVERRIDE, PROP_PIF_ENABLED, PROP_PIF_PREFIX,
    PROP_RKP_MANUFACTURER, PROP_TRICKY_ENABLED, TARGETS_FILENAME,
};
use yasvara_integrity_core::der::{
    aaid_has_package, for_each_aaid_package, is_app_uid, should_modify_attestation,
    DeviceIdOverrides, PatchConfig,
};
use yasvara_integrity_core::digest::parse_boot_digest;
use yasvara_integrity_core::patch_override::resolve_patch_override_for_packages;
use yasvara_integrity_core::policy::PolicySnapshot;
use yasvara_integrity_core::version::{
    parse_long_patch, parse_os_patchlevel, parse_version_number, resolve_os_version_with_staged,
};

/// Caller-supplied explicit attestation key state for `RequestPolicy::for_request`.
pub enum ExplicitSigner<'a> {
    /// No explicit attestation key (standard RKP/factory path or standalone key generation).
    None,
    /// User-generated or imported `PURPOSE_ATTEST_KEY` managed by Yasvara's software key store.
    Managed {
        /// DER-encoded certificate of the attestation key.
        attest_cert: &'a [u8],
        /// PKCS#8 DER bytes of Yasvara's software signing keypair.
        sw_pkcs8: &'a [u8],
    },
    /// Unmanaged external/hardware `ATTEST_KEY` whose signing key Yasvara does not hold.
    Unmanaged,
}

/// A single policy snapshot shared by request preparation and response handling.
pub struct RequestPolicy {
    snapshot: Option<PolicySnapshot>,
    patch: Option<AttestationContext>,
}

struct AttestationContext {
    canonical_boot_digest: Vec<u8>,
    keybox: KeyboxEntry,
    managed_issuer: Option<(Vec<u8>, SigningKey)>,
}

/// Output of post-KeyMint Yasvara certificate handling, plus optional software `ATTEST_KEY`
/// private key material (PKCS#8 DER) to persist alongside the new entry.
pub struct PatchedCreation {
    /// Potentially modified `KeyCreationResult` to store in Keystore2's database.
    pub result: KeyCreationResult,
    /// PKCS#8 DER signing key when `PURPOSE_ATTEST_KEY` provisioning replaced SPKI.
    pub sw_attest_key: Option<Vec<u8>>,
}

impl RequestPolicy {
    /// Missing or invalid prerequisites preserve both the original request and response.
    pub fn for_request(
        params: &[KeyParameter],
        caller_uid: u32,
        explicit_signer: ExplicitSigner<'_>,
    ) -> Self {
        let snapshot = attest_policy::current();
        let mut policy = Self { snapshot, patch: None };
        let (managed_issuer, has_unmanaged) = match explicit_signer {
            ExplicitSigner::None => (None, false),
            ExplicitSigner::Unmanaged => (None, true),
            ExplicitSigner::Managed { attest_cert, sw_pkcs8 } => {
                match SigningKey::from_pkcs8_der(sw_pkcs8) {
                    Some(signer) => (Some((attest_cert.to_vec(), signer)), false),
                    None => {
                        warn!(
                            "Yasvara: invalid managed ATTEST_KEY PKCS#8 (uid={}); preserving hardware chain",
                            caller_uid
                        );
                        (None, true)
                    }
                }
            }
        };

        let master_prop;
        let master = match policy.snapshot.as_ref() {
            Some(snap) => Some(if snap.is_tricky_enabled() { "1" } else { "0" }),
            None => {
                master_prop = system_properties::read(PROP_TRICKY_ENABLED).ok().flatten();
                master_prop.as_deref()
            }
        };
        let has_challenge = has_attestation_challenge(params);
        let is_attest_key = has_purpose_attest_key(params);
        if !should_modify_attestation(caller_uid, master, has_unmanaged)
            || (!has_challenge && !is_attest_key)
            || !is_target_request(params, caller_uid, has_challenge, policy.snapshot.as_ref())
        {
            return policy;
        }

        let canonical_value = match system_properties::read(PROP_BOOT_DIGEST) {
            Ok(value) => value,
            Err(e) => {
                warn!(
                    "Yasvara: cannot read {} (uid={}): {}; preserving original request and hardware chain",
                    PROP_BOOT_DIGEST, caller_uid, e
                );
                return policy;
            }
        };
        let canonical_boot_digest = match parse_boot_digest(canonical_value.as_deref()) {
            Ok(digest) => digest,
            Err(reason) => {
                warn!(
                    "Yasvara: {}: {} (uid={}); preserving original request and hardware chain",
                    PROP_BOOT_DIGEST, reason, caller_uid
                );
                return policy;
            }
        };
        let Some(keybox) = keybox::current() else {
            warn!(
                "Yasvara: no valid keybox for target app (uid={}); preserving original request and hardware chain",
                caller_uid
            );
            return policy;
        };
        policy.patch = Some(AttestationContext { canonical_boot_digest, keybox, managed_issuer });
        policy
    }
}

/// Returns true when the KeyMint parameters include `KeyPurpose::ATTEST_KEY`.
pub fn has_purpose_attest_key(params: &[KeyParameter]) -> bool {
    params.iter().any(|kp| {
        kp.tag == Tag::PURPOSE
            && matches!(kp.value, KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY))
    })
}

fn has_attestation_challenge(params: &[KeyParameter]) -> bool {
    params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE)
}

/// Validates and normalizes an imported PKCS#8 `PURPOSE_ATTEST_KEY` private key.
pub fn validated_imported_attest_key(
    caller_uid: u32,
    params: &[KeyParameter],
    key_data: &[u8],
) -> Option<Vec<u8>> {
    if !is_app_uid(caller_uid) || !has_purpose_attest_key(params) {
        return None;
    }
    SigningKey::from_pkcs8_der(key_data).map(|k| k.to_pkcs8_der())
}

fn is_builtin_pif_enabled(snapshot: Option<&PolicySnapshot>) -> bool {
    if let Some(snap) = snapshot {
        return snap.is_pif_enabled();
    }
    match system_properties::read(PROP_PIF_ENABLED).ok().flatten() {
        Some(v) if v.trim() == "0" || v.trim().eq_ignore_ascii_case("false") => false,
        Some(v) if v.trim() == "1" || v.trim().eq_ignore_ascii_case("true") => true,
        _ => pif_prop("brand").is_some() || pif_prop("model").is_some(),
    }
}

/// Rewrites caller-supplied `ATTESTATION_ID_*` parameters back to real hardware vendor properties
/// before calling `IKeyMintDevice::generateKey`, and strips hardware-unique IDs (IMEI/MEID/SERIAL).
///
/// Also heals `ATTESTATION_ID_MANUFACTURER` when `policy.patch` is `None` (e.g. an app calling
/// KeyMint with a pre-existing unmanaged `PURPOSE_ATTEST_KEY` while `YasvaraSpoofEngine` aligned
/// its `Build.MANUFACTURER` to the installed RKP keybox manufacturer), preventing `CANNOT_ATTEST_IDS`.
pub fn prepare_keymint_params(
    params: &[KeyParameter],
    policy: &RequestPolicy,
) -> Vec<KeyParameter> {
    if !has_attestation_challenge(params) {
        return params.to_vec();
    }
    let Some(context) = policy.patch.as_ref() else {
        if params.iter().any(|kp| kp.tag == Tag::ATTESTATION_ID_MANUFACTURER) {
            let staged_mfg = policy
                .snapshot
                .as_ref()
                .map(|s| s.rkp_manufacturer.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| system_properties::read(PROP_RKP_MANUFACTURER).ok().flatten());
            if let Some(staged) = staged_mfg {
                let spoofed = staged.trim();
                if !spoofed.is_empty() {
                    if let Some(hw_mfg) =
                        hw_prop(&["ro.product.vendor.manufacturer", "ro.product.manufacturer"])
                    {
                        return rewrite_matching_rkp_manufacturer(params, spoofed, &hw_mfg);
                    }
                }
            }
        }
        return params.to_vec();
    };
    if is_builtin_pif_enabled(policy.snapshot.as_ref()) && is_pif_collector_caller(params) {
        return params
            .iter()
            .filter(|kp| {
                !matches!(
                    kp.tag,
                    Tag::ATTESTATION_ID_SERIAL
                        | Tag::ATTESTATION_ID_IMEI
                        | Tag::ATTESTATION_ID_MEID
                        | Tag::ATTESTATION_ID_SECOND_IMEI
                )
            })
            .map(|kp| {
                let hw_val = match kp.tag {
                    Tag::ATTESTATION_ID_BRAND => {
                        hw_prop(&["ro.product.vendor.brand", "ro.product.brand"])
                    }
                    Tag::ATTESTATION_ID_DEVICE => {
                        hw_prop(&["ro.product.vendor.device", "ro.product.device"])
                    }
                    Tag::ATTESTATION_ID_PRODUCT => {
                        hw_prop(&["ro.product.vendor.name", "ro.product.name"])
                    }
                    Tag::ATTESTATION_ID_MANUFACTURER => {
                        hw_prop(&["ro.product.vendor.manufacturer", "ro.product.manufacturer"])
                    }
                    Tag::ATTESTATION_ID_MODEL => {
                        hw_prop(&["ro.product.vendor.model", "ro.product.model"])
                    }
                    _ => None,
                };
                match hw_val {
                    Some(v) => {
                        KeyParameter { tag: kp.tag, value: KeyParameterValue::Blob(v.into_bytes()) }
                    }
                    None => kp.clone(),
                }
            })
            .collect();
    }
    if context.keybox.rkp_manufacturer.is_some()
        && params.iter().any(|kp| kp.tag == Tag::ATTESTATION_ID_MANUFACTURER)
    {
        if let Some(hw_mfg) = hw_prop(&["ro.product.vendor.manufacturer", "ro.product.manufacturer"])
        {
            return rewrite_manufacturer_param(params, &hw_mfg);
        }
    }
    params.to_vec()
}

fn rewrite_manufacturer_param(params: &[KeyParameter], hw_mfg: &str) -> Vec<KeyParameter> {
    params
        .iter()
        .map(|kp| {
            if kp.tag == Tag::ATTESTATION_ID_MANUFACTURER {
                KeyParameter { tag: kp.tag, value: KeyParameterValue::Blob(hw_mfg.as_bytes().to_vec()) }
            } else {
                kp.clone()
            }
        })
        .collect()
}

fn rewrite_matching_rkp_manufacturer(
    params: &[KeyParameter],
    spoofed_mfg: &str,
    hw_mfg: &str,
) -> Vec<KeyParameter> {
    params
        .iter()
        .map(|kp| match (&kp.tag, &kp.value) {
            (&Tag::ATTESTATION_ID_MANUFACTURER, KeyParameterValue::Blob(b))
                if b.as_slice() == spoofed_mfg.as_bytes() =>
            {
                KeyParameter { tag: kp.tag, value: KeyParameterValue::Blob(hw_mfg.as_bytes().to_vec()) }
            }
            _ => kp.clone(),
        })
        .collect()
}

/// Post-KeyMint certificate patching for RKP/factory leaves and managed `PURPOSE_ATTEST_KEY`.
pub fn maybe_patch_generated_key(
    params: &[KeyParameter],
    mut creation_result: KeyCreationResult,
    caller_uid: u32,
    policy: &RequestPolicy,
) -> PatchedCreation {
    let Some(context) = policy.patch.as_ref() else {
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    };
    let has_challenge = has_attestation_challenge(params);
    let is_attest_key = has_purpose_attest_key(params);
    if (!has_challenge && !is_attest_key) || creation_result.certificateChain.is_empty() {
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    }

    let leaf_der = &creation_result.certificateChain[0].encodedCertificate;
    let sw_signer = if is_attest_key {
        let (rsa_bits, ec_is_p384) =
            extract_key_hints(params, &creation_result.keyCharacteristics);
        let Some(signer) =
            patcher::generate_matching_signing_key(leaf_der, rsa_bits, ec_is_p384)
        else {
            warn!(
                "Yasvara: cannot match software ATTEST_KEY parameters (uid={}); preserving hardware cert",
                caller_uid
            );
            return PatchedCreation { result: creation_result, sw_attest_key: None };
        };
        Some(signer)
    } else {
        None
    };

    if !has_challenge && is_attest_key && context.managed_issuer.is_none() {
        let Some(signer) = sw_signer.as_ref() else {
            return PatchedCreation { result: creation_result, sw_attest_key: None };
        };
        if let Some(new_leaf_der) = patcher::resign_self_signed_leaf_with_spki(leaf_der, signer) {
            creation_result.certificateChain[0].encodedCertificate = new_leaf_der;
            info!("Yasvara: provisioned software ATTEST_KEY cert (uid={})", caller_uid);
            return PatchedCreation {
                result: creation_result,
                sw_attest_key: Some(signer.to_pkcs8_der()),
            };
        }
        warn!("Yasvara: failed to resign self-signed ATTEST_KEY cert (uid={})", caller_uid);
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    }

    if !has_challenge {
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    }

    let inputs = PatchInputs::from_request(params, context, policy.snapshot.as_ref());
    let patch_config = inputs.as_config(&context.canonical_boot_digest);
    let replacement_spki = sw_signer.as_ref().map(|k| k.to_spki_der());

    if let Some((ref attest_cert_der, ref issuer_signer)) = context.managed_issuer {
        if let Some(new_leaf_der) = patcher::patch_user_attested_leaf(
            leaf_der,
            attest_cert_der,
            issuer_signer,
            &patch_config,
            replacement_spki.as_deref(),
        ) {
            creation_result.certificateChain[0].encodedCertificate = new_leaf_der;
            info!("Yasvara: patched ATTEST_KEY child cert (uid={})", caller_uid);
            return PatchedCreation {
                result: creation_result,
                sw_attest_key: sw_signer.map(|k| k.to_pkcs8_der()),
            };
        }
        warn!("Yasvara: failed to patch ATTEST_KEY child cert; preserving hardware cert");
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    }

    match patcher::patch_leaf_and_chain_with_spki(
        leaf_der,
        &context.keybox,
        &patch_config,
        replacement_spki.as_deref(),
    ) {
        Some(new_chain) => {
            creation_result.certificateChain = new_chain
                .into_iter()
                .map(|cert| KeyMintCert { encodedCertificate: cert })
                .collect();
            info!("Yasvara: patched attestation chain (uid={})", caller_uid);
            PatchedCreation {
                result: creation_result,
                sw_attest_key: sw_signer.map(|k| k.to_pkcs8_der()),
            }
        }
        None => {
            warn!("Yasvara: failed to patch attestation chain; preserving hardware chain");
            PatchedCreation { result: creation_result, sw_attest_key: None }
        }
    }
}

struct PatchInputs {
    boot_key: Vec<u8>,
    id_overrides: Option<DeviceIdOverrides>,
    os_version: Option<u32>,
    os_patchlevel: Option<u32>,
    long_patch: Option<u32>,
}

impl PatchInputs {
    fn from_request(
        params: &[KeyParameter],
        context: &AttestationContext,
        snapshot: Option<&PolicySnapshot>,
    ) -> Self {
        let is_collector = is_pif_collector_caller(params);
        let use_pif = is_builtin_pif_enabled(snapshot) && is_collector;
        let id_overrides = if use_pif {
            snapshot
                .and_then(PolicySnapshot::pif_id_overrides)
                .or_else(resolve_pif_id_overrides)
        } else if !is_collector {
            resolve_rkp_id_overrides(&context.keybox)
        } else {
            None
        };
        let app_patch_override = resolve_patch_override_for_request(params, snapshot);
        let host_release = system_properties::read("ro.build.version.release").ok().flatten();
        let host_patch = system_properties::read("ro.build.version.security_patch").ok().flatten();

        let (os_version, os_patchlevel, long_patch) = if use_pif {
            let (os_ver, pif_patch) = if let Some(snap) = snapshot {
                let staged_os = (snap.os_version > 0).then(|| snap.os_version.to_string());
                let pif_release = (!snap.pif_release.is_empty()).then_some(snap.pif_release.as_str());
                let pif_build_id =
                    (!snap.pif_build_id.is_empty()).then_some(snap.pif_build_id.as_str());
                let os_ver = resolve_os_version_with_staged(
                    staged_os.as_deref(),
                    pif_release,
                    pif_build_id,
                    snap.has_pif_profile(),
                    host_release.as_deref(),
                );
                let patch = (!snap.pif_security_patch.is_empty())
                    .then(|| snap.pif_security_patch.clone());
                (os_ver, patch)
            } else {
                let staged_os = pif_prop("os_version");
                let pif_release = pif_prop("release");
                let pif_build_id = pif_prop("build_id");
                let pif_active = staged_os.is_some()
                    || pif_release.is_some()
                    || pif_build_id.is_some()
                    || pif_prop("brand").is_some()
                    || pif_prop("model").is_some();
                let os_ver = resolve_os_version_with_staged(
                    staged_os.as_deref(),
                    pif_release.as_deref(),
                    pif_build_id.as_deref(),
                    pif_active,
                    host_release.as_deref(),
                );
                (os_ver, pif_prop("security_patch"))
            };
            let active_patch = app_patch_override.or(pif_patch);
            let os_pl = active_patch
                .as_deref()
                .or(host_patch.as_deref())
                .and_then(parse_os_patchlevel);
            let long_pl = active_patch.as_deref().and_then(parse_long_patch);
            (os_ver, os_pl, long_pl)
        } else {
            let os_ver = host_release.as_deref().and_then(parse_version_number);
            let os_pl = app_patch_override
                .as_deref()
                .or(host_patch.as_deref())
                .and_then(parse_os_patchlevel);
            let long_pl = app_patch_override.as_deref().and_then(parse_long_patch);
            (os_ver, os_pl, long_pl)
        };

        let boot_key = resolve_boot_key(&context.canonical_boot_digest);
        Self { boot_key, id_overrides, os_version, os_patchlevel, long_patch }
    }

    fn as_config<'a>(&'a self, canonical_boot_digest: &'a [u8]) -> PatchConfig<'a> {
        PatchConfig {
            canonical_boot_digest,
            boot_key: Some(&self.boot_key),
            id_overrides: self.id_overrides.as_ref(),
            os_version: self.os_version,
            os_patchlevel: self.os_patchlevel,
            vendor_patchlevel: self.long_patch,
            boot_patchlevel: self.long_patch,
        }
    }
}

fn aaid_blob(params: &[KeyParameter]) -> Option<&[u8]> {
    params.iter().find_map(|kp| match (&kp.tag, &kp.value) {
        (&Tag::ATTESTATION_APPLICATION_ID, KeyParameterValue::Blob(b)) => Some(b.as_slice()),
        _ => None,
    })
}

fn is_pif_collector_caller(params: &[KeyParameter]) -> bool {
    let Some(aaid) = aaid_blob(params) else {
        return false;
    };
    BASE_ATTEST_TARGETS.iter().any(|pkg| aaid_has_package(aaid, pkg.as_bytes()))
}

/// Security fix: `security_level.rs` only sets authoritative `ATTESTATION_APPLICATION_ID` when
/// `has_challenge` is true. For non-challenged `PURPOSE_ATTEST_KEY`, ALWAYS resolve the caller's
/// authoritative AAID via `keystore2_aaid::get_aaid(caller_uid)` rather than trusting caller params.
fn is_target_request(
    params: &[KeyParameter],
    caller_uid: u32,
    has_challenge: bool,
    snapshot: Option<&PolicySnapshot>,
) -> bool {
    if has_challenge {
        if let Some(aaid) = aaid_blob(params) {
            return is_target_aaid(aaid, snapshot);
        }
        return false;
    }
    match keystore2_aaid::get_aaid(caller_uid) {
        Ok(aaid) => is_target_aaid(&aaid, snapshot),
        Err(e) => {
            warn!("Yasvara: get_aaid({}) failed during ATTEST_KEY check: {}", caller_uid, e);
            false
        }
    }
}

fn is_target_aaid(aaid: &[u8], snapshot: Option<&PolicySnapshot>) -> bool {
    if let Some(snap) = snapshot {
        return snap.is_target_aaid(aaid);
    }
    if BASE_ATTEST_TARGETS.iter().any(|pkg| aaid_has_package(aaid, pkg.as_bytes())) {
        return true;
    }
    match std::fs::read_to_string(format!("{ATTEST_DIR}/{TARGETS_FILENAME}")) {
        Ok(published) => published
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .any(|pkg| aaid_has_package(aaid, pkg.as_bytes())),
        Err(_) => false,
    }
}

/// Resolves per-app (or wildcard `"*"`) security patch override from the cached binary
/// `policy.bin` snapshot (zero disk I/O / JSON parsing on steady state), falling back to legacy
/// `patch_override` / `persist.sys.yasvara.trickystore.patch_override` only before `policy.bin`
/// is published.
fn resolve_patch_override_for_request(
    params: &[KeyParameter],
    snapshot: Option<&PolicySnapshot>,
) -> Option<String> {
    if let Some(snap) = snapshot {
        let mut pkgs: Vec<String> = Vec::new();
        if let Some(aaid) = aaid_blob(params) {
            for_each_aaid_package(aaid, |pkg| {
                if let Ok(s) = core::str::from_utf8(pkg) {
                    pkgs.push(s.to_owned());
                }
                false
            });
        }
        let refs: Vec<&str> = pkgs.iter().map(String::as_str).collect();
        return snap.resolve_patch_override(&refs).map(str::to_owned);
    }
    if let Some(aaid) = aaid_blob(params) {
        if let Ok(raw_json) =
            std::fs::read_to_string(format!("{ATTEST_DIR}/{PATCH_OVERRIDE_FILENAME}"))
        {
            let mut pkgs: Vec<String> = Vec::new();
            for_each_aaid_package(aaid, |pkg| {
                if let Ok(s) = core::str::from_utf8(pkg) {
                    pkgs.push(s.to_owned());
                }
                false
            });
            let refs: Vec<&str> = pkgs.iter().map(String::as_str).collect();
            if let Some(matched) = resolve_patch_override_for_packages(&raw_json, &refs) {
                return Some(matched);
            }
        }
    }
    system_properties::read(PROP_PATCH_OVERRIDE)
        .ok()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn hw_prop(keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Ok(Some(v)) = system_properties::read(k) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn pif_prop(key: &str) -> Option<String> {
    system_properties::read(&format!("{PROP_PIF_PREFIX}{key}"))
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
}

fn resolve_rkp_id_overrides(keybox: &KeyboxEntry) -> Option<DeviceIdOverrides> {
    let manufacturer = keybox.rkp_manufacturer.as_deref()?.trim();
    if manufacturer.is_empty() {
        return None;
    }
    Some(DeviceIdOverrides {
        brand: String::new(),
        device: String::new(),
        product: String::new(),
        manufacturer: manufacturer.to_string(),
        model: String::new(),
    })
}

fn resolve_pif_id_overrides() -> Option<DeviceIdOverrides> {
    let brand = pif_prop("brand");
    let model = pif_prop("model");
    if brand.is_none() && model.is_none() {
        return None;
    }
    Some(DeviceIdOverrides {
        brand: brand.unwrap_or_default(),
        device: pif_prop("device").unwrap_or_default(),
        product: pif_prop("name").unwrap_or_default(),
        manufacturer: pif_prop("manufacturer").unwrap_or_default(),
        model: model.unwrap_or_default(),
    })
}

fn extract_key_hints(
    params: &[KeyParameter],
    characteristics: &[KeyCharacteristics],
) -> (Option<i32>, Option<bool>) {
    let mut rsa_bits = None;
    let mut ec_is_p384 = None;
    for kp in characteristics.iter().flat_map(|c| c.authorizations.iter()).chain(params.iter()) {
        match (&kp.tag, &kp.value) {
            (&Tag::KEY_SIZE, KeyParameterValue::Integer(bits)) if rsa_bits.is_none() => {
                rsa_bits = Some(*bits);
            }
            (&Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256))
                if ec_is_p384.is_none() =>
            {
                ec_is_p384 = Some(false);
            }
            (&Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_384))
                if ec_is_p384.is_none() =>
            {
                ec_is_p384 = Some(true);
            }
            _ => {}
        }
    }
    (rsa_bits, ec_is_p384)
}

fn resolve_boot_key(boot_digest: &[u8]) -> Vec<u8> {
    let published = system_properties::read(PROP_BOOT_VBMETA_PUBKEY_DIGEST)
        .ok()
        .flatten()
        .and_then(|v| parse_boot_digest(Some(v.trim().to_ascii_lowercase().as_str())).ok())
        .filter(|k| k.len() == 32);
    published.unwrap_or_else(|| {
        let mut seed = b"yasvara.verified-boot-key".to_vec();
        seed.extend_from_slice(boot_digest);
        bssl_crypto::digest::Sha256::hash(&seed).to_vec()
    })
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

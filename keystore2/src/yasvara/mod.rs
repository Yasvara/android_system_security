/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

/// Pure attestation policy and DER helpers, also testable without Android dependencies.
#[allow(missing_docs)]
mod attestation;

/// Yasvara native keystore attestation re-signing module.
#[allow(missing_docs)]
pub mod keybox;
/// Yasvara attestation certificate patcher.
#[allow(missing_docs)]
pub mod patcher;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Certificate::Certificate as KeyMintCert, EcCurve::EcCurve,
    KeyCharacteristics::KeyCharacteristics, KeyCreationResult::KeyCreationResult,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
    Tag::Tag,
};
use log::{info, warn};
use rustutils::android::system_properties;

use attestation::{
    parse_boot_digest, parse_long_patch, parse_os_patchlevel, parse_version_number,
    should_modify_attestation, BOOT_DIGEST_PROPERTY,
};
use patcher::{DeviceIdOverrides, PatchConfig};

/// Directory system_server publishes the keybox and target list into (yasvara_attest_data_file).
pub const ATTEST_DIR: &str = "/data/misc/yasvara_attest";

/// Used only until system_server has published `ATTEST_DIR/targets`, which is the full
/// effective list (user choices plus the always-covered packages) from the same settings
/// the Java hooks read.
const BASE_TARGETS: &[&str] = &[
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
    "org.yasvara.laras",
];

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
/// Toggle and credential changes take effect on the next operation; unmanaged signers bypass both.
pub struct RequestPolicy {
    patch: Option<AttestationContext>,
}

struct AttestationContext {
    canonical_boot_digest: Vec<u8>,
    keybox: keybox::KeyboxEntry,
    managed_issuer: Option<(Vec<u8>, keybox::SigningKey)>,
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
        let mut policy = Self { patch: None };
        let (managed_issuer, has_unmanaged) = match explicit_signer {
            ExplicitSigner::None => (None, false),
            ExplicitSigner::Unmanaged => (None, true),
            ExplicitSigner::Managed { attest_cert, sw_pkcs8 } => {
                match keybox::SigningKey::from_pkcs8_der(sw_pkcs8) {
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

        let master = system_properties::read("persist.sys.yasvara.trickystore").ok().flatten();
        let has_challenge = has_attestation_challenge(params);
        let is_attest_key = has_purpose_attest_key(params);
        if !should_modify_attestation(caller_uid, master.as_deref(), has_unmanaged)
            || (!has_challenge && !is_attest_key)
            || !is_target_request(params, caller_uid, is_attest_key)
        {
            return policy;
        }

        let canonical_value = match system_properties::read(BOOT_DIGEST_PROPERTY) {
            Ok(value) => value,
            Err(e) => {
                warn!("Yasvara: cannot read {} (uid={}): {}; preserving original request and hardware chain", BOOT_DIGEST_PROPERTY, caller_uid, e);
                return policy;
            }
        };
        let canonical_boot_digest = match parse_boot_digest(canonical_value.as_deref()) {
            Ok(digest) => digest,
            Err(reason) => {
                warn!("Yasvara: {}: {} (uid={}); check service per-boot publication; preserving original request and hardware chain", BOOT_DIGEST_PROPERTY, reason, caller_uid);
                return policy;
            }
        };
        let Some(keybox) = keybox::current() else {
            warn!("Yasvara: no valid keybox for target app (uid={}); preserving original request and hardware chain", caller_uid);
            return policy;
        };
        policy.patch = Some(AttestationContext { canonical_boot_digest, keybox, managed_issuer });
        policy
    }
}

/// Returns true when the KeyMint parameters include `KeyPurpose::ATTEST_KEY`.
pub fn has_purpose_attest_key(params: &[KeyParameter]) -> bool {
    params.iter().any(|kp| {
        kp.tag == Tag::PURPOSE && matches!(kp.value, KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY))
    })
}

fn has_attestation_challenge(params: &[KeyParameter]) -> bool {
    params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE)
}

/// Validates and normalizes an imported PKCS#8 `PURPOSE_ATTEST_KEY` private key without altering
/// its certificates, allowing child attestations using the imported key to stay aligned later.
pub fn validated_imported_attest_key(
    caller_uid: u32,
    params: &[KeyParameter],
    key_data: &[u8],
) -> Option<Vec<u8>> {
    if !attestation::is_app_uid(caller_uid) || !has_purpose_attest_key(params) {
        return None;
    }
    keybox::SigningKey::from_pkcs8_der(key_data).map(|k| k.to_pkcs8_der())
}

/// Returns true only when built-in Yasvara PIF spoofing is explicitly enabled (and not
/// yielded to an external Akar/Zygisk PIF module). When false, Keystore2 becomes a pure
/// pass-through for `ATTESTATION_ID_*` and OS/device overrides (Audit F1-F3 fix).
fn is_builtin_pif_enabled() -> bool {
    match system_properties::read("persist.sys.yasvara.pif.enabled").ok().flatten() {
        Some(v) if v.trim() == "0" || v.trim().eq_ignore_ascii_case("false") => false,
        Some(v) if v.trim() == "1" || v.trim().eq_ignore_ascii_case("true") => true,
        _ => pif_prop("brand").is_some() || pif_prop("model").is_some(),
    }
}

/// Rewrites caller-supplied `ATTESTATION_ID_*` parameters (which carry PIF-spoofed `Build.*`
/// values in GMS / Play Store) back to the real hardware vendor properties before calling
/// `IKeyMintDevice::generateKey`, preventing `ErrorCode::CANNOT_ATTEST_IDS` from TrustZone,
/// and strips hardware-unique identifiers (IMEI/MEID/SERIAL) so they never leak into PIF certs.
pub fn prepare_keymint_params(
    params: &[KeyParameter],
    policy: &RequestPolicy,
) -> Vec<KeyParameter> {
    if policy.patch.is_none()
        || !is_builtin_pif_enabled()
        || !params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE)
        || !is_pif_collector_caller(params)
    {
        return params.to_vec();
    }
    params
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
        .collect()
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

struct PatchInputs {
    boot_key: Vec<u8>,
    id_overrides: Option<DeviceIdOverrides>,
    os_version: Option<u32>,
    os_patchlevel: Option<u32>,
    long_patch: Option<u32>,
}

impl PatchInputs {
    fn from_request(params: &[KeyParameter], context: &AttestationContext) -> Self {
        // Apply PIF identity/OS overrides only to PIF-spoofed collector packages when built-in
        // PIF is enabled; other target apps (and external PIF modules) keep clean host values.
        let use_pif = is_builtin_pif_enabled() && is_pif_collector_caller(params);
        let id_overrides = if use_pif { resolve_id_overrides() } else { None };
        let (os_version, os_patchlevel) =
            if use_pif { resolve_os_values() } else { resolve_host_os_values() };
        let long_patch = if use_pif { resolve_long_patch() } else { resolve_host_long_patch() };
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

/// Intercepts key creation in Keystore2, covering:
/// - `PURPOSE_ATTEST_KEY` provisioning (self-signed or RKP-attested) with a software signing key
///   matching TrustZone's algorithm/curve/size so later child attestations share RootOfTrust truth.
/// - Child attestations signed by a Yasvara-managed `UserGenerated` `PURPOSE_ATTEST_KEY`.
/// - Standard RKP/factory attestations re-signed with the installed keybox.
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
                "Yasvara: cannot match software ATTEST_KEY parameters (uid={}); preserving hardware key/cert",
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
            info!(
                "Yasvara: provisioned software ATTEST_KEY cert for target app (uid={})",
                caller_uid
            );
            return PatchedCreation {
                result: creation_result,
                sw_attest_key: Some(signer.to_pkcs8_der()),
            };
        }
        warn!(
            "Yasvara: failed to resign self-signed ATTEST_KEY cert (uid={}), preserving hardware cert",
            caller_uid
        );
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    }

    if !has_challenge {
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    }

    let patch_inputs = PatchInputs::from_request(params, context);
    let patch_config = patch_inputs.as_config(&context.canonical_boot_digest);
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
            info!(
                "Yasvara: successfully patched ATTEST_KEY child cert for target app (uid={})",
                caller_uid
            );
            return PatchedCreation {
                result: creation_result,
                sw_attest_key: sw_signer.map(|k| k.to_pkcs8_der()),
            };
        }
        warn!("Yasvara: failed to patch ATTEST_KEY child cert, preserving original hardware cert");
        return PatchedCreation { result: creation_result, sw_attest_key: None };
    }

    match patcher::patch_leaf_and_chain_with_spki(
        leaf_der,
        &context.keybox,
        &patch_config,
        replacement_spki.as_deref(),
    ) {
        Some(new_chain) => {
            let mut aidl_chain = Vec::with_capacity(new_chain.len());
            for cert_der in new_chain {
                aidl_chain.push(KeyMintCert { encodedCertificate: cert_der });
            }
            creation_result.certificateChain = aidl_chain;
            info!(
                "Yasvara: successfully patched attestation chain for target app (uid={})",
                caller_uid
            );
            PatchedCreation {
                result: creation_result,
                sw_attest_key: sw_signer.map(|k| k.to_pkcs8_der()),
            }
        }
        None => {
            warn!("Yasvara: failed to patch attestation chain, preserving original hardware chain");
            PatchedCreation { result: creation_result, sw_attest_key: None }
        }
    }
}

/// Convenience wrapper around `maybe_patch_generated_key` returning only the patched result.
pub fn maybe_patch_creation_result(
    params: &[KeyParameter],
    creation_result: KeyCreationResult,
    caller_uid: u32,
    policy: &RequestPolicy,
) -> KeyCreationResult {
    maybe_patch_generated_key(params, creation_result, caller_uid, policy).result
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

fn is_pif_collector_caller(params: &[KeyParameter]) -> bool {
    let Some(aaid) = params.iter().find_map(|kp| match (&kp.tag, &kp.value) {
        (&Tag::ATTESTATION_APPLICATION_ID, KeyParameterValue::Blob(b)) => Some(b),
        _ => None,
    }) else {
        return false;
    };
    BASE_TARGETS.iter().any(|pkg| aaid_has_package(aaid, pkg.as_bytes()))
}

fn is_target_request(params: &[KeyParameter], caller_uid: u32, allow_uid_lookup: bool) -> bool {
    if let Some(aaid) = params.iter().find_map(|kp| match (&kp.tag, &kp.value) {
        (&Tag::ATTESTATION_APPLICATION_ID, KeyParameterValue::Blob(b)) => Some(b.as_slice()),
        _ => None,
    }) {
        return is_target_aaid(aaid);
    }
    if !allow_uid_lookup {
        return false;
    }
    match keystore2_aaid::get_aaid(caller_uid) {
        Ok(aaid) => is_target_aaid(&aaid),
        Err(e) => {
            warn!("Yasvara: get_aaid({}) failed during ATTEST_KEY check: {}", caller_uid, e);
            false
        }
    }
}

fn is_target_aaid(aaid: &[u8]) -> bool {
    // Fast-path in RAM for GMS, Play Store, and Laras (zero disk I/O).
    if BASE_TARGETS.iter().any(|pkg| aaid_has_package(aaid, pkg.as_bytes())) {
        return true;
    }
    match std::fs::read_to_string(format!("{}/targets", ATTEST_DIR)) {
        Ok(published) => published
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .any(|pkg| aaid_has_package(aaid, pkg.as_bytes())),
        Err(_) => false,
    }
}

/// The AAID DER carries each package name as an OCTET STRING; match whole names only, so
/// "com.google.android.gms" does not also match "com.google.android.gmsx".
fn aaid_has_package(aaid: &[u8], pkg: &[u8]) -> bool {
    aaid.windows(pkg.len() + 2)
        .any(|w| w[0] == 0x04 && w[1] as usize == pkg.len() && &w[2..] == pkg)
}

/// A nonboot ID/OS override staged by the framework (`persist.sys.yasvara.pif.<key>`).
/// Boot digest and RootOfTrust must never be resolved through this persisted configuration.
fn pif_prop(key: &str) -> Option<String> {
    system_properties::read(&format!("persist.sys.yasvara.pif.{}", key))
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
}

fn resolve_id_overrides() -> Option<DeviceIdOverrides> {
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

/// OS version (KeyMint tag 705) and patch level (tag 706) from active PIF / override.
/// Reads pre-resolved `persist.sys.yasvara.pif.os_version` staged by YasvaraAttestationService
/// first (SSOT with YasvaraSpoofEngine.resolvePifOsVersion), falling back to release/ID inference.
fn resolve_os_values() -> (Option<u32>, Option<u32>) {
    let staged_os_version = pif_prop("os_version");
    let pif_release = pif_prop("release");
    let pif_build_id = pif_prop("build_id");
    let is_pif_active = staged_os_version.is_some()
        || pif_release.is_some()
        || pif_build_id.is_some()
        || pif_prop("brand").is_some()
        || pif_prop("model").is_some();

    let host_release = system_properties::read("ro.build.version.release").ok().flatten();

    let os_version = resolve_os_version_with_staged(
        staged_os_version.as_deref(),
        pif_release.as_deref(),
        pif_build_id.as_deref(),
        is_pif_active,
        host_release.as_deref(),
    );
    let os_patchlevel = resolve_patch_prop().and_then(|sp| parse_os_patchlevel(&sp));
    (os_version, os_patchlevel)
}

fn resolve_os_version_with_staged(
    staged_os_version: Option<&str>,
    pif_release: Option<&str>,
    pif_build_id: Option<&str>,
    is_pif_active: bool,
    host_release: Option<&str>,
) -> Option<u32> {
    if let Some(staged) = staged_os_version.and_then(|s| s.trim().parse::<u32>().ok()) {
        return Some(staged);
    }
    resolve_os_version_internal(pif_release, pif_build_id, is_pif_active, host_release)
}

fn resolve_host_os_values() -> (Option<u32>, Option<u32>) {
    let host_release = system_properties::read("ro.build.version.release").ok().flatten();
    let os_version = host_release.as_deref().and_then(parse_version_number);
    let host_patch = system_properties::read("ro.build.version.security_patch").ok().flatten();
    let os_patchlevel = host_patch.as_deref().and_then(parse_os_patchlevel);
    (os_version, os_patchlevel)
}

fn resolve_os_version_internal(
    pif_release: Option<&str>,
    pif_build_id: Option<&str>,
    is_pif_active: bool,
    host_release: Option<&str>,
) -> Option<u32> {
    if is_pif_active {
        // Active PIF: never fallback to host ro.build.version.release to prevent
        // host OS version leaks (e.g. 170000) into attestation certificates.
        pif_release
            .and_then(parse_version_number)
            .or_else(|| pif_build_id.and_then(infer_version_from_build_id))
            .or(Some(0)) // Pure codenames without numeric info default to 0 (AOSP Keymaster)
    } else {
        // PIF inactive: use host ROM release version.
        host_release.and_then(parse_version_number)
    }
}

/// Optional explicit TrickyStore patch override, else active PIF security patch.
fn resolve_active_override_patch_prop() -> Option<String> {
    system_properties::read("persist.sys.yasvara.trickystore.patch_override")
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| pif_prop("security_patch"))
}

/// Optional explicit TrickyStore patch override, else active PIF security patch, else system patch.
fn resolve_patch_prop() -> Option<String> {
    resolve_active_override_patch_prop().or_else(|| {
        system_properties::read("ro.build.version.security_patch")
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty())
    })
}

/// Full YYYYMMDD patch level from active override / PIF, for KeyMint tags 718/719.
/// Left as `None` when neither override nor PIF is active so KeyMint's real vendor/boot
/// patch levels stay aligned with `ro.vendor.build.security_patch`.
fn resolve_long_patch() -> Option<u32> {
    let sp = resolve_active_override_patch_prop()?;
    parse_long_patch(&sp)
}

fn resolve_host_long_patch() -> Option<u32> {
    let sp = system_properties::read("persist.sys.yasvara.trickystore.patch_override")
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())?;
    parse_long_patch(&sp)
}

/// Infer OS version from build_id when release is a non-numeric codename (e.g. "CANARY").
fn infer_version_from_build_id(build_id: &str) -> Option<u32> {
    let build_id = build_id.trim();
    if build_id.is_empty() {
        return None;
    }

    // Google Trunk Stable & Pixel Canary
    // Android 17: CP2 / CP3 / CP4 / DP1
    if build_id.starts_with("CP2")
        || build_id.starts_with("CP3")
        || build_id.starts_with("CP4")
        || build_id.starts_with("DP1")
    {
        return Some(170000);
    }

    // Rolling Android Canary: ZP11.25* = Android 16 (2025), ZP11.26* = Android 17 (2026)+
    if let Some(rest) = build_id.strip_prefix("ZP11.") {
        if rest.len() >= 2 {
            if let Ok(yy) = rest[..2].parse::<u32>() {
                if yy >= 26 {
                    return Some((yy - 9) * 10000);
                }
            }
        }
        return Some(160000);
    }

    // Android 16 (Baklava): Trunk Stable BP2 / BP3 / BP4 / BD / CP1
    if build_id.starts_with("BP2")
        || build_id.starts_with("BP3")
        || build_id.starts_with("BP4")
        || build_id.starts_with("BD")
        || build_id.starts_with("CP1")
    {
        return Some(160000);
    }

    // Android 15 (Vanilla Ice Cream): AP3 / AP4 / AD / BP1 (A15 QPR2)
    if build_id.starts_with("AP3")
        || build_id.starts_with("AP4")
        || build_id.starts_with("AD")
        || build_id.starts_with("BP1")
    {
        return Some(150000);
    }

    // Android 14 (Upside Down Cake): AP1 (A14 QPR2) / AP2 (A14 QPR3)
    if build_id.starts_with("AP1") || build_id.starts_with("AP2") {
        return Some(140000);
    }

    // Standard AOSP / OEM build ID prefixes (OnePlus UKQ1, Xiaomi TKQ1, Samsung UP1A/TP1A, etc.)
    match build_id.as_bytes()[0] {
        b'U' => Some(140000), // Android 14 (Upside Down Cake)
        b'T' => Some(130000), // Android 13 (Tiramisu)
        b'S' => Some(120000), // Android 12 (Snow Cone)
        b'R' => Some(110000), // Android 11 (Red Velvet Cake)
        b'Q' => Some(100000), // Android 10 (Quince Tart)
        _ => None,
    }
}

/// verifiedBootKey for devices whose hardware attests an all-zero key: the bootloader's
/// published vbmeta key digest when present, else a stable value derived from the boot digest.
fn resolve_boot_key(boot_digest: &[u8]) -> Vec<u8> {
    let published = system_properties::read("ro.boot.vbmeta.public_key_digest")
        .ok()
        .flatten()
        .and_then(|v| parse_boot_digest(Some(v.trim().to_lowercase().as_str())).ok())
        .filter(|k| k.len() == 32 && k.iter().any(|b| *b != 0));
    published.unwrap_or_else(|| {
        let mut seed = b"yasvara.verified-boot-key".to_vec();
        seed.extend_from_slice(boot_digest);
        bssl_crypto::digest::Sha256::hash(&seed).to_vec()
    })
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

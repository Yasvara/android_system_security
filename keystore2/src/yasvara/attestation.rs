/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Keep this module independent of Android and signing dependencies so the same policy and
// DER transformation used in production can be tested on a host with rustc --test.
pub const BOOT_DIGEST_PROPERTY: &str = "ro.yasvara.boot.digest";

pub const TAG_ROOT_OF_TRUST: u32 = 704;
pub const TAG_OS_VERSION: u32 = 705;
pub const TAG_OS_PATCHLEVEL: u32 = 706;
pub const TAG_ATTESTATION_ID_BRAND: u32 = 710;
pub const TAG_ATTESTATION_ID_DEVICE: u32 = 711;
pub const TAG_ATTESTATION_ID_PRODUCT: u32 = 712;
pub const TAG_ATTESTATION_ID_SERIAL: u32 = 713;
pub const TAG_ATTESTATION_ID_IMEI: u32 = 714;
pub const TAG_ATTESTATION_ID_MEID: u32 = 715;
pub const TAG_ATTESTATION_ID_MANUFACTURER: u32 = 716;
pub const TAG_ATTESTATION_ID_MODEL: u32 = 717;
pub const TAG_VENDOR_PATCHLEVEL: u32 = 718;
pub const TAG_BOOT_PATCHLEVEL: u32 = 719;
pub const TAG_ATTESTATION_ID_SECOND_IMEI: u32 = 723;

const MAX_KEY_DESCRIPTION_LEN: usize = 64 * 1024;
const MAX_AUTHORIZATION_FIELDS: usize = 256;

pub struct DeviceIdOverrides {
    pub brand: String,
    pub device: String,
    pub product: String,
    pub manufacturer: String,
    pub model: String,
}

pub struct PatchConfig<'a> {
    pub canonical_boot_digest: &'a [u8],
    /// Non-zero 32-byte verifiedBootKey substituted when the hardware reports an empty or
    /// all-zero key (unlocked bootloader); a locked device never attests a zero key.
    pub boot_key: Option<&'a [u8]>,
    pub id_overrides: Option<&'a DeviceIdOverrides>,
    pub os_version: Option<u32>,
    pub os_patchlevel: Option<u32>,
    pub vendor_patchlevel: Option<u32>,
    pub boot_patchlevel: Option<u32>,
}

pub struct PatchedKeyDescription {
    pub der: Vec<u8>,
    pub attestation_version: u32,
    pub attestation_security_level: u32,
    pub keymaster_security_level: u32,
}

pub fn is_app_uid(caller_uid: u32) -> bool {
    // Android UIDs include a user/profile component; system appIds must bypass patching
    // in every user, even when their full UID is greater than FIRST_APPLICATION_UID.
    caller_uid % 100_000 >= 10_000
}

pub fn should_modify_attestation(
    caller_uid: u32,
    master: Option<&str>,
    has_unmanaged_attestation_key: bool,
) -> bool {
    is_app_uid(caller_uid) && master == Some("1") && !has_unmanaged_attestation_key
}

fn parse_decimal(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }
    value.bytes().try_fold(0u32, |n, b| {
        if !b.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add(u32::from(b - b'0'))
    })
}

// Keep YYYY-MM compatibility: only an omitted day defaults to 01, never a malformed day.
fn parse_patch_date(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.trim().split('-');
    let year = parts.next()?;
    let month = parts.next()?;
    let day = parts.next().unwrap_or("01");
    if parts.next().is_some() || year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    let year = parse_decimal(year)?;
    let month = parse_decimal(month)?;
    let day = parse_decimal(day)?;
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let days_in_month = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

pub fn parse_long_patch(value: &str) -> Option<u32> {
    let (year, month, day) = parse_patch_date(value)?;
    year.checked_mul(10000)?.checked_add(month.checked_mul(100)?)?.checked_add(day)
}

pub fn parse_os_patchlevel(value: &str) -> Option<u32> {
    let (year, month, _) = parse_patch_date(value)?;
    year.checked_mul(100)?.checked_add(month)
}

pub fn parse_version_number(value: &str) -> Option<u32> {
    let mut parts = value.trim().split('.');
    let component = |s: &str| {
        let n = parse_decimal(s)?;
        (s.len() <= 2 && n <= 99).then_some(n)
    };
    let major = component(parts.next()?)?;
    let minor = parts.next().map(component).unwrap_or(Some(0))?;
    let sub = parts.next().map(component).unwrap_or(Some(0))?;
    if parts.next().is_some() {
        return None;
    }
    major.checked_mul(10000)?.checked_add(minor.checked_mul(100)?)?.checked_add(sub)
}

pub fn parse_boot_digest(value: Option<&str>) -> Result<Vec<u8>, &'static str> {
    let value = value.ok_or("canonical boot digest is missing")?;
    if !matches!(value.len(), 64 | 128) {
        return Err("canonical boot digest must be 64 or 128 lowercase hex characters");
    }
    let nibble = |b| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            Ok((nibble(pair[0]).ok_or("canonical boot digest is not lowercase hex")? << 4)
                | nibble(pair[1]).ok_or("canonical boot digest is not lowercase hex")?)
        })
        .collect()
}

pub fn patch_key_description(
    raw: &[u8],
    config: &PatchConfig,
) -> Result<PatchedKeyDescription, String> {
    if raw.len() > MAX_KEY_DESCRIPTION_LEN {
        return Err("KeyDescription exceeds 64 KiB bound".into());
    }
    if !matches!(config.canonical_boot_digest.len(), 32 | 64) {
        return Err("canonical boot digest must be SHA-256 or SHA-512".into());
    }
    let top = read_single(raw)?;
    if top.tag != [0x30] {
        return Err("KeyDescription is not a SEQUENCE".into());
    }
    let fields = split_elems(top.value, 8)?;
    if fields.len() != 8 {
        return Err(format!("KeyDescription expected 8 fields, got {}", fields.len()));
    }
    let attestation_version = read_uint(fields[0], 0x02)?;
    let attestation_security_level = read_security_level(fields[1])?;
    read_uint(fields[2], 0x02)?;
    let keymaster_security_level = read_security_level(fields[3])?;
    let challenge_elem = read_single(fields[4])?;
    if challenge_elem.tag != [0x04] || challenge_elem.value.len() > 128 {
        return Err("KeyDescription challenge is not a valid <=128B OCTET STRING".into());
    }
    if read_single(fields[5])?.tag != [0x04] {
        return Err("KeyDescription unique ID is not an OCTET STRING".into());
    }
    let sw = read_list(fields[6])?;
    let hw = read_list(fields[7])?;
    let (mut boot_key, boot_hash) =
        validate_original_root_of_trust(sw, hw, config.canonical_boot_digest)?;
    if boot_key.iter().all(|b| *b == 0) {
        if let Some(key) = config.boot_key.filter(|k| k.len() == 32 && k.iter().any(|b| *b != 0)) {
            boot_key = key.to_vec();
        }
    }

    // Spoof RootOfTrust: preserve original boot hash, set locked + Verified; a zero boot key
    // is replaced because it contradicts a Verified state.
    let mut overrides = Vec::new();
    let spoofed_rot_seq = {
        let mut body = Vec::new();
        body.extend_from_slice(&tlv(&[0x04], &boot_key)); // verifiedBootKey
        body.extend_from_slice(&[0x01, 0x01, 0xff]); // deviceLocked = TRUE
        body.extend_from_slice(&[0x0a, 0x01, 0x00]); // verifiedBootState = Verified(0)
        body.extend_from_slice(&tlv(&[0x04], &boot_hash)); // verifiedBootHash
        tlv(&[0x30], &body)
    };
    let spoofed_rot = tlv(&context_tag(TAG_ROOT_OF_TRUST), &spoofed_rot_seq);
    overrides.push((TAG_ROOT_OF_TRUST, spoofed_rot));
    if let Some(os_ver) = config.os_version {
        overrides.push((TAG_OS_VERSION, explicit_integer(TAG_OS_VERSION, os_ver)));
    }
    if let Some(os_patch) = config.os_patchlevel {
        overrides.push((TAG_OS_PATCHLEVEL, explicit_integer(TAG_OS_PATCHLEVEL, os_patch)));
    }
    if let Some(ids) = config.id_overrides {
        let id_list: &[(u32, &str)] = &[
            (TAG_ATTESTATION_ID_BRAND, &ids.brand),
            (TAG_ATTESTATION_ID_DEVICE, &ids.device),
            (TAG_ATTESTATION_ID_PRODUCT, &ids.product),
            (TAG_ATTESTATION_ID_MANUFACTURER, &ids.manufacturer),
            (TAG_ATTESTATION_ID_MODEL, &ids.model),
        ];
        for (tag, val) in id_list {
            if !val.is_empty() {
                overrides.push((*tag, explicit_octet_string(*tag, val.as_bytes())));
            }
        }
    }
    if let Some(v) = config.vendor_patchlevel {
        overrides.push((TAG_VENDOR_PATCHLEVEL, explicit_integer(TAG_VENDOR_PATCHLEVEL, v)));
    }
    if let Some(b) = config.boot_patchlevel {
        overrides.push((TAG_BOOT_PATCHLEVEL, explicit_integer(TAG_BOOT_PATCHLEVEL, b)));
    }

    let strip_hw_unique_ids = config.id_overrides.is_some_and(|ids| {
        !ids.brand.is_empty()
            || !ids.device.is_empty()
            || !ids.product.is_empty()
            || !ids.model.is_empty()
    });
    let mut seen = Vec::new();
    let sw = replace_in_list(sw, &overrides, strip_hw_unique_ids, &mut seen)?;
    let mut hw = replace_in_list(hw, &overrides, strip_hw_unique_ids, &mut seen)?;
    // Device ID tags (710..717) are replaced in-place by replace_in_list ONLY when the TEE
    // actually emitted them; never inject unrequested ID tags into standard attestations.
    for tag in [TAG_VENDOR_PATCHLEVEL, TAG_BOOT_PATCHLEVEL] {
        if !seen.contains(&tag) {
            if let Some((_, elem)) = overrides.iter().find(|(t, _)| *t == tag) {
                hw = insert_in_order(hw, tag, elem)?;
            }
        }
    }

    let mut body = Vec::with_capacity(raw.len() + 64);
    for field in &fields[..6] {
        body.extend_from_slice(field);
    }
    body.extend_from_slice(&tlv(&[0x30], &sw));
    body.extend_from_slice(&tlv(&[0x30], &hw));
    let der = tlv(&[0x30], &body);
    if der.len() > MAX_KEY_DESCRIPTION_LEN {
        return Err("patched KeyDescription exceeds 64 KiB bound".into());
    }
    Ok(PatchedKeyDescription {
        der,
        attestation_version,
        attestation_security_level,
        keymaster_security_level,
    })
}

fn validate_original_root_of_trust(
    sw: &[u8],
    hw: &[u8],
    digest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut root = None;
    for (hardware, list) in [(false, sw), (true, hw)] {
        for field in split_elems(list, MAX_AUTHORIZATION_FIELDS)? {
            let elem = read_single(field)?;
            let tag = context_tag_number(elem.tag)
                .ok_or("AuthorizationList field is not an explicit context tag")?;
            if tag == TAG_ROOT_OF_TRUST {
                if !hardware {
                    return Err(
                        "original RootOfTrust is software-enforced, not hardware-enforced".into()
                    );
                }
                if root.replace(elem.value).is_some() {
                    return Err("duplicate original hardware RootOfTrust".into());
                }
            }
        }
    }
    let root = root.ok_or("original hardware RootOfTrust is missing")?;
    validate_root_of_trust(root, digest)
        .map_err(|e| format!("original hardware RootOfTrust: {}", e))
}

fn validate_root_of_trust(raw: &[u8], digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let sequence = read_single(raw)?;
    if sequence.tag != [0x30] {
        return Err("expected a SEQUENCE".into());
    }
    let fields = split_elems(sequence.value, 4)?;
    if fields.len() != 4 {
        return Err("expected key, deviceLocked, verifiedBootState and verifiedBootHash".into());
    }
    let key_elem = read_single(fields[0])?;
    if key_elem.tag != [0x04] {
        return Err("verifiedBootKey is not an OCTET STRING".into());
    }
    let locked = read_single(fields[1])?;
    if locked.tag != [0x01] || !matches!(locked.value, [0x00] | [0xff]) {
        return Err("deviceLocked is not a DER BOOLEAN".into());
    }
    if read_uint(fields[2], 0x0a)? > 3 {
        return Err("invalid verifiedBootState".into());
    }
    let hash = read_single(fields[3])?;
    if hash.tag != [0x04] || !matches!(hash.value.len(), 32 | 64) {
        return Err("verifiedBootHash must be a SHA-256 or SHA-512 OCTET STRING".into());
    }
    let hash_all_zero = hash.value.iter().all(|b| *b == 0);
    if !hash_all_zero && hash.value != digest {
        return Err(format!(
            "verifiedBootHash disagrees with {}; check the per-boot digest publisher",
            BOOT_DIGEST_PROPERTY
        ));
    }
    let effective_hash = if hash_all_zero { digest.to_vec() } else { hash.value.to_vec() };
    Ok((key_elem.value.to_vec(), effective_hash))
}

fn read_security_level(field: &[u8]) -> Result<u32, String> {
    let level = read_uint(field, 0x0a)?;
    if level > 2 {
        return Err("invalid attestation/keymaster security level".into());
    }
    Ok(level)
}

fn read_uint(field: &[u8], tag: u8) -> Result<u32, String> {
    let elem = read_single(field)?;
    if elem.tag != [tag] || elem.value.is_empty() || elem.value[0] & 0x80 != 0 {
        return Err("expected a nonnegative DER INTEGER/ENUMERATED".into());
    }
    if elem.value.len() > 1 && elem.value[0] == 0 && elem.value[1] & 0x80 == 0 {
        return Err("nonminimal DER INTEGER/ENUMERATED".into());
    }
    elem.value.iter().try_fold(0u32, |v, b| {
        v.checked_mul(256)
            .and_then(|v| v.checked_add(u32::from(*b)))
            .ok_or_else(|| "DER INTEGER/ENUMERATED exceeds u32".into())
    })
}

fn read_list(field: &[u8]) -> Result<&[u8], String> {
    let e = read_single(field)?;
    if e.tag != [0x30] {
        return Err("AuthorizationList is not a SEQUENCE".into());
    }
    Ok(e.value)
}

fn replace_in_list(
    body: &[u8],
    overrides: &[(u32, Vec<u8>)],
    strip_hw_unique_ids: bool,
    seen: &mut Vec<u32>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    while !rest.is_empty() {
        let e = read_elem(rest)?;
        let mut hit = None;
        let mut drop_elem = false;
        if let Some(n) = context_tag_number(e.tag) {
            if strip_hw_unique_ids
                && matches!(
                    n,
                    TAG_ATTESTATION_ID_SERIAL
                        | TAG_ATTESTATION_ID_IMEI
                        | TAG_ATTESTATION_ID_MEID
                        | TAG_ATTESTATION_ID_SECOND_IMEI
                )
            {
                drop_elem = true;
            } else if let Some((_, repl)) = overrides.iter().find(|(t, _)| *t == n) {
                hit = Some((n, repl));
            }
        }
        if !drop_elem {
            match hit {
                Some((n, repl)) => {
                    out.extend_from_slice(repl);
                    if !seen.contains(&n) {
                        seen.push(n);
                    }
                }
                None => out.extend_from_slice(&rest[..e.total]),
            }
        }
        rest = &rest[e.total..];
    }
    Ok(out)
}

fn insert_in_order(body: Vec<u8>, num: u32, element: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(body.len() + element.len());
    let mut rest: &[u8] = &body;
    let mut inserted = false;
    while !rest.is_empty() {
        let e = read_elem(rest)?;
        if !inserted {
            if let Some(n) = context_tag_number(e.tag) {
                if n > num {
                    out.extend_from_slice(element);
                    inserted = true;
                }
            }
        }
        out.extend_from_slice(&rest[..e.total]);
        rest = &rest[e.total..];
    }
    if !inserted {
        out.extend_from_slice(element);
    }
    Ok(out)
}

fn explicit_integer(tag_num: u32, value: u32) -> Vec<u8> {
    tlv(&context_tag(tag_num), &tlv(&[0x02], &der_uint(value)))
}

fn explicit_octet_string(tag_num: u32, value: &[u8]) -> Vec<u8> {
    tlv(&context_tag(tag_num), &tlv(&[0x04], value))
}

fn context_tag(n: u32) -> Vec<u8> {
    if n < 0x1f {
        return vec![0xA0 | (n & 0x1f) as u8];
    }
    let mut digits = Vec::new();
    let mut v = n;
    while v > 0 {
        digits.push((v & 0x7f) as u8);
        v >>= 7;
    }
    digits.reverse();
    let mut out = Vec::with_capacity(1 + digits.len());
    out.push(0xBF);
    let last = digits.len() - 1;
    for (i, d) in digits.iter().enumerate() {
        out.push(if i == last { *d } else { d | 0x80 });
    }
    out
}

fn context_tag_number(tag: &[u8]) -> Option<u32> {
    let first = *tag.first()?;
    if first & 0xE0 != 0xA0 {
        return None;
    }
    if first & 0x1f != 0x1f {
        return Some(u32::from(first & 0x1f));
    }
    let mut n: u32 = 0;
    for &b in &tag[1..] {
        n = n.checked_mul(128)?.checked_add(u32::from(b & 0x7f))?;
    }
    Some(n)
}

fn der_uint(mut value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut be = Vec::new();
    while value > 0 {
        be.push((value & 0xff) as u8);
        value >>= 8;
    }
    be.reverse();
    if be[0] & 0x80 != 0 {
        be.insert(0, 0x00);
    }
    be
}

struct Elem<'a> {
    tag: &'a [u8],
    value: &'a [u8],
    total: usize,
}

fn read_single(input: &[u8]) -> Result<Elem<'_>, String> {
    let elem = read_elem(input)?;
    if elem.total != input.len() {
        return Err("trailing data after DER element".into());
    }
    Ok(elem)
}

fn read_elem(input: &[u8]) -> Result<Elem<'_>, String> {
    let first = *input.first().ok_or("truncated DER (no tag)")?;
    if first == 0 {
        return Err("DER end-of-contents tag is not allowed".into());
    }
    let mut i = 1;
    if first & 0x1f == 0x1f {
        let mut number = 0u32;
        loop {
            if i > 5 {
                return Err("DER tag exceeds u32 bound".into());
            }
            let b = *input.get(i).ok_or("truncated multi-byte tag")?;
            if i == 1 && b & 0x7f == 0 {
                return Err("nonminimal DER tag".into());
            }
            number = number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(b & 0x7f)))
                .ok_or("DER tag overflow")?;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        if number < 31 {
            return Err("nonminimal DER high tag".into());
        }
    }
    let tag = &input[..i];
    let l0 = *input.get(i).ok_or("truncated length")?;
    i += 1;
    let len = if l0 & 0x80 == 0 {
        l0 as usize
    } else {
        let nbytes = (l0 & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 {
            return Err("unsupported or indefinite DER length".into());
        }
        if input.get(i) == Some(&0) {
            return Err("nonminimal DER length".into());
        }
        let mut v = 0usize;
        for _ in 0..nbytes {
            v = v
                .checked_mul(256)
                .and_then(|v| input.get(i).and_then(|b| v.checked_add(*b as usize)))
                .ok_or("truncated or overflowing DER length")?;
            i += 1;
        }
        if v < 128 {
            return Err("nonminimal DER long length".into());
        }
        v
    };
    let end = i.checked_add(len).ok_or("length overflow")?;
    if end > input.len() {
        return Err("value runs past end of input".into());
    }
    Ok(Elem { tag, value: &input[i..end], total: end })
}

fn split_elems(mut content: &[u8], limit: usize) -> Result<Vec<&[u8]>, String> {
    let mut out = Vec::new();
    while !content.is_empty() {
        if out.len() == limit {
            return Err("DER field count exceeds bound".into());
        }
        let e = read_elem(content)?;
        out.push(&content[..e.total]);
        content = &content[e.total..];
    }
    Ok(out)
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut be = Vec::new();
    let mut v = n;
    while v > 0 {
        be.push((v & 0xff) as u8);
        v >>= 8;
    }
    be.reverse();
    let mut out = Vec::with_capacity(1 + be.len());
    out.push(0x80 | be.len() as u8);
    out.extend_from_slice(&be);
    out
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 5 + value.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&der_len(value.len()));
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod tests;

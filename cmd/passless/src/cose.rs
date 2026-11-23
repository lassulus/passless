//! Attested credential data and COSE public keys, as the WebAuthn JSON responses need them.

/// The credential ID and COSE public key of the attested credential data in
/// `authenticator_data`.
pub(crate) fn attested_credential(
    authenticator_data: &[u8],
) -> Result<(&[u8], ciborium::Value), &'static str> {
    // rpIdHash (32), flags (1), signCount (4), AAGUID (16), credentialIdLength (2).
    const ATTESTED_OFFSET: usize = 37;
    const ERROR: &str = "authenticator data has no attested credential data";
    let flags = *authenticator_data.get(32).ok_or(ERROR)?;
    if flags & 0x40 == 0 {
        return Err(ERROR);
    }
    let length_at = ATTESTED_OFFSET + 16;
    let length = authenticator_data
        .get(length_at..length_at + 2)
        .ok_or(ERROR)?;
    let id_length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let key_at = length_at + 2 + id_length;
    let credential_id = authenticator_data.get(length_at + 2..key_at).ok_or(ERROR)?;
    let key_bytes = authenticator_data.get(key_at..).ok_or(ERROR)?;
    let key = ciborium::from_reader(key_bytes).map_err(|_| "malformed COSE key")?;
    Ok((credential_id, key))
}

/// The DER `SubjectPublicKeyInfo` of a COSE key: P-256 (EC2, crv 1) or Ed25519 (OKP, crv 6).
pub(crate) fn spki_from_cose_key(key: &ciborium::Value) -> Option<Vec<u8>> {
    // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (0 unused bits) }.
    const P256_PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    // SEQUENCE { SEQUENCE { id-Ed25519 }, BIT STRING (0 unused bits) }.
    const ED25519_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let map = key.as_map()?;
    let int = |label: i64| {
        map.iter().find_map(|(k, v)| {
            (k.as_integer() == Some(label.into()))
                .then(|| v.as_integer())
                .flatten()
                .map(i128::from)
        })
    };
    let bytes = |label: i64| {
        map.iter().find_map(|(k, v)| {
            (k.as_integer() == Some(label.into()))
                .then(|| v.as_bytes())
                .flatten()
        })
    };
    match (int(1)?, int(-1)?) {
        (2, 1) => {
            let (x, y) = (bytes(-2)?, bytes(-3)?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let mut spki = P256_PREFIX.to_vec();
            spki.push(0x04);
            spki.extend_from_slice(x);
            spki.extend_from_slice(y);
            Some(spki)
        }
        (1, 6) => {
            let x = bytes(-2)?;
            if x.len() != 32 {
                return None;
            }
            let mut spki = ED25519_PREFIX.to_vec();
            spki.extend_from_slice(x);
            Some(spki)
        }
        _ => None,
    }
}

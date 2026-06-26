use super::types::Ctap2Error;
use ciborium::value::Value;

/// Build attestation object.
/// If `cert_der` and `att_sig` are provided, produces full packed attestation with x5c.
/// Otherwise, produces packed self-attestation (credential key signs).
pub(crate) fn build_attestation_object(
    auth_data: &[u8],
    sig: &[u8],
    x5c: Option<&[Vec<u8>]>,
) -> Result<Vec<u8>, Ctap2Error> {
    let mut att_stmt = vec![
        (
            Value::Text("alg".to_string()),
            Value::Integer((-7i64).into()), // ES256
        ),
        (
            Value::Text("sig".to_string()),
            Value::Bytes(sig.to_vec()),
        ),
    ];

    if let Some(certs) = x5c {
        let cert_values: Vec<Value> = certs.iter()
            .map(|c| Value::Bytes(c.clone()))
            .collect();
        att_stmt.push((
            Value::Text("x5c".to_string()),
            Value::Array(cert_values),
        ));
    }

    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Text("packed".to_string()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Bytes(auth_data.to_vec()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Map(att_stmt),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}

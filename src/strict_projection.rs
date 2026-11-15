//! Byte-faithful browser port of the approved native clean-chat strict
//! projection (catbird-mls d69da1e1 `orchestrator/canonical_transport.rs`).
//!
//! The native strict projector is `#[cfg(not(target_arch = "wasm32"))]` gated
//! in the pinned catbird-mls sibling, so the browser WASM build cannot link it.
//! This module ports the exact same projection machinery (duplicate/unknown/
//! null/tag/bounds checks, canonical dag-cbor bytes, binding validation, wire
//! wrapper construction) un-gated so the browser path uses the SAME code as
//! native. Byte-equality with the approved Rust path is proven against the
//! approved signing-vector corpus in `tests/browser_transport.rs` and the
//! vendored schema/fixture provenance is checked in `tests/provenance.rs`.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use uuid::{Uuid, Variant, Version};

use catbird_mls::atproto::blue_catbird::chat::CanonicalDatetime;
use catbird_mls::canonical_transport::{
    canonical_route, CanonicalOperation, CleanChatSigningContext, PreparedRequest, TransportError,
};

const REPLENISH_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-REPLENISH\0";
const DEVICE_ENROLL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-ENROLL\0";
const DEVICE_REVOKE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-REVOKE\0";
const DEVICE_APPROVE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-DEVICE-APPROVE\0";
const CREATE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-CREATE\0";
const COMMIT_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-COMMIT\0";
const POLICY_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-POLICY\0";
const ACCEPT_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-ACCEPT\0";
const MESSAGE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-MESSAGE\0";
const METADATA_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-METADATA\0";
const TYPING_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-TYPING\0";
const RESET_REQUEST_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-RESET-REQUEST\0";
const RESET_ACTIVATE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-RESET-ACTIVATE\0";
const LEAF_RECOVERY_REQUEST_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\0";
const LEAF_RECOVERY_CANCEL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0";
const LEAF_RECOVERY_FULFILL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0";
const CLOSE_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-CLOSE\0";
const LEAVE_REQUEST_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-REQUEST\0";
const LEAVE_ZERO_LEAF_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0";
const LEAVE_CANCEL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-CANCEL\0";
const LEAVE_FULFILL_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0";
const WELCOME_ACK_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-WELCOME-ACK\0";
const WELCOME_REJECT_SIGNATURE_DOMAIN: &str = "CATBIRD-CHAT-WELCOME-REJECT\0";

const TYPE_PREFIX: &str = "blue.catbird.chat.defs#";
const SIGNED_JSON_MAX_BYTES: usize = 16 * 1024 * 1024;
const SIGNED_JSON_MAX_DEPTH: usize = 64;
const CHAT_DEFS_JSON: &str = include_str!("generated/blue.catbird.chat.defs.json");

/// A duplicate-detecting, null-free JSON tree. `serde_json::Value` is not
/// suitable at this boundary because it silently keeps the last duplicate
/// member and permits `null`/floating-point forms that are outside the signed
/// clean-chat profile.
#[derive(Debug, Clone)]
enum StrictSignedJson {
    String(String),
    Integer(u64),
    Bool(bool),
    Array(Vec<StrictSignedJson>),
    Object(BTreeMap<String, StrictSignedJson>),
}

struct StrictSignedJsonVisitor;

impl<'de> Visitor<'de> for StrictSignedJsonVisitor {
    type Value = StrictSignedJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict non-null clean-chat JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::Integer(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        u64::try_from(value)
            .map(StrictSignedJson::Integer)
            .map_err(|_| de::Error::custom("negative integers are forbidden"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom("floating-point values are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictSignedJson::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom("null values are forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom("null values are forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictSignedJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(StrictSignedJson::Object(values))
    }
}

impl<'de> Deserialize<'de> for StrictSignedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictSignedJsonVisitor)
    }
}

fn parse_strict_signed_json(raw: &[u8]) -> Result<StrictSignedJson, TransportError> {
    if raw.is_empty()
        || raw.len() > SIGNED_JSON_MAX_BYTES
        || !matches!(raw.first(), Some(b'{' | b'['))
        || !matches!(raw.last(), Some(b'}' | b']'))
    {
        return Err(TransportError::Serialization(
            "signed JSON has an invalid root or insignificant whitespace".into(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictSignedJson::deserialize(&mut deserializer)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    deserializer
        .end()
        .map_err(|_| TransportError::Serialization("trailing signed JSON data".into()))?;
    validate_strict_json_depth(&value, 0)?;
    Ok(value)
}

fn validate_strict_json_depth(
    value: &StrictSignedJson,
    depth: usize,
) -> Result<(), TransportError> {
    if depth > SIGNED_JSON_MAX_DEPTH {
        return Err(TransportError::Serialization(
            "signed JSON schema depth exceeds the strict limit".into(),
        ));
    }
    match value {
        StrictSignedJson::Array(values) => values
            .iter()
            .try_for_each(|value| validate_strict_json_depth(value, depth + 1)),
        StrictSignedJson::Object(values) => values
            .values()
            .try_for_each(|value| validate_strict_json_depth(value, depth + 1)),
        StrictSignedJson::String(_) | StrictSignedJson::Integer(_) | StrictSignedJson::Bool(_) => {
            Ok(())
        }
    }
}

fn chat_contract() -> &'static serde_json::Value {
    static CONTRACT: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
        serde_json::from_str(CHAT_DEFS_JSON).expect("canonical chat lexicon must be valid JSON")
    });
    &CONTRACT
}

fn chat_definition(name: &str) -> Result<&'static serde_json::Value, TransportError> {
    chat_contract()["defs"]
        .get(name)
        .ok_or_else(|| TransportError::Serialization(format!("unknown chat definition {name}")))
}

fn strict_text<'a>(value: &'a StrictSignedJson, field: &str) -> Result<&'a str, TransportError> {
    match value {
        StrictSignedJson::String(value) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "{field} must be a string"
        ))),
    }
}

fn schema_ref_name(schema: &serde_json::Value) -> Result<&str, TransportError> {
    schema["ref"]
        .as_str()
        .and_then(|value| value.strip_prefix('#'))
        .ok_or_else(|| TransportError::Serialization("invalid clean-chat schema reference".into()))
}

fn project_schema_ref(
    name: &str,
    input: &StrictSignedJson,
    tagged: bool,
) -> Result<CanonicalValue, TransportError> {
    match name {
        "operationId" | "deviceId" => {
            let text = strict_text(input, name)?;
            Ok(CanonicalValue::Bytes(canonical_uuid_bytes(text, name)?))
        }
        "bareDid" => {
            let text = strict_text(input, name)?;
            validate_bare_did(text)?;
            Ok(CanonicalValue::Text(text.to_owned()))
        }
        "keyId" => {
            let text = strict_text(input, name)?;
            validate_key_id(text)?;
            Ok(CanonicalValue::Text(text.to_owned()))
        }
        "canonicalDatetime" => {
            let text = strict_text(input, name)?;
            validate_datetime(text)?;
            parse_datetime(text.to_owned())?;
            Ok(CanonicalValue::Text(text.to_owned()))
        }
        _ => project_schema(chat_definition(name)?, input, Some(name), tagged),
    }
}

fn project_schema(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    field_name: Option<&str>,
    tagged: bool,
) -> Result<CanonicalValue, TransportError> {
    match schema["type"].as_str() {
        Some("ref") => project_schema_ref(schema_ref_name(schema)?, input, false),
        Some("union") => project_union(schema, input),
        Some("object") => project_object(schema, input, field_name, tagged),
        Some("string") => project_string(schema, input, field_name),
        Some("bytes") => project_bytes(schema, input),
        Some("integer") => project_integer(schema, input),
        Some("boolean") => project_boolean(schema, input),
        Some("array") => project_array(schema, input, field_name),
        _ => Err(TransportError::Serialization(
            "unsupported clean-chat schema type".into(),
        )),
    }
}

fn project_union(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Object(values) = input else {
        return Err(TransportError::Serialization(
            "closed clean-chat union must be an object".into(),
        ));
    };
    let type_id = strict_text(
        values
            .get("$type")
            .ok_or_else(|| TransportError::Serialization("union is missing $type".into()))?,
        "$type",
    )?;
    let variant = type_id
        .strip_prefix(TYPE_PREFIX)
        .ok_or_else(|| TransportError::Serialization("union $type namespace is invalid".into()))?;
    let allowed = schema["refs"]
        .as_array()
        .ok_or_else(|| TransportError::Serialization("union refs are invalid".into()))?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|value| value.strip_prefix('#'))
        .any(|candidate| candidate == variant);
    if !allowed {
        return Err(TransportError::Serialization(
            "unknown closed union $type".into(),
        ));
    }
    project_schema_ref(variant, input, true)
}

fn project_object(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    definition_name: Option<&str>,
    tagged: bool,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Object(values) = input else {
        return Err(TransportError::Serialization(
            "clean-chat object has the wrong JSON type".into(),
        ));
    };
    let properties = schema["properties"].as_object().ok_or_else(|| {
        TransportError::Serialization("object schema properties are invalid".into())
    })?;
    let mut output = BTreeMap::new();
    for (name, value) in values {
        if name == "$type" {
            if !tagged {
                return Err(TransportError::Serialization(
                    "unexpected object $type".into(),
                ));
            }
            let expected = format!("{}{}", TYPE_PREFIX, definition_name.unwrap_or_default());
            if strict_text(value, "$type")? != expected {
                return Err(TransportError::Serialization(
                    "wrong closed object $type".into(),
                ));
            }
            output.insert(name.clone(), CanonicalValue::Text(expected));
            continue;
        }
        let property = properties.get(name).ok_or_else(|| {
            TransportError::Serialization(format!("unknown closed clean-chat field {name}"))
        })?;
        let projected = project_schema(property, value, Some(name), false)
            .map_err(|error| TransportError::Serialization(format!("field {name}: {error}")))?;
        output.insert(name.clone(), projected);
    }
    if tagged && !output.contains_key("$type") {
        return Err(TransportError::Serialization(
            "closed object is missing $type".into(),
        ));
    }
    if let Some(required) = schema["required"].as_array() {
        for field in required.iter().filter_map(serde_json::Value::as_str) {
            if !output.contains_key(field) {
                return Err(TransportError::Serialization(format!(
                    "required clean-chat field {field} is missing"
                )));
            }
        }
    }
    enforce_contract_order(definition_name.unwrap_or_default(), &output)?;
    Ok(CanonicalValue::Map(output))
}

fn project_string(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    field_name: Option<&str>,
) -> Result<CanonicalValue, TransportError> {
    let value = strict_text(input, field_name.unwrap_or("string"))?;
    if let Some(expected) = schema["const"].as_str() {
        if value != expected {
            return Err(TransportError::Serialization(
                "wrong clean-chat string constant".into(),
            ));
        }
    }
    for key in ["enum", "knownValues"] {
        if let Some(values) = schema[key].as_array() {
            if !values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|candidate| candidate == value)
            {
                return Err(TransportError::Serialization(
                    "string is outside the closed clean-chat vocabulary".into(),
                ));
            }
        }
    }
    let length = value.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
        || schema["minGraphemes"]
            .as_u64()
            .is_some_and(|min| value.chars().count() < min as usize)
        || schema["maxGraphemes"]
            .as_u64()
            .is_some_and(|max| value.chars().count() > max as usize)
    {
        return Err(TransportError::Serialization(
            "string is outside the clean-chat length bound".into(),
        ));
    }
    if schema["format"].as_str() == Some("datetime") {
        validate_datetime(value)?;
        parse_datetime(value.to_owned())?;
    }
    if matches!(
        field_name,
        Some("dpopJkt" | "currentDpopJkt" | "newDpopJkt")
    ) {
        validate_jkt(value)?;
    }
    Ok(CanonicalValue::Text(value.to_owned()))
}

fn strict_base64(value: &str) -> Result<Vec<u8>, TransportError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| TransportError::Serialization("invalid standard base64 bytes".into()))?;
    if STANDARD.encode(&decoded) != value {
        return Err(TransportError::Serialization(
            "non-canonical standard base64 bytes".into(),
        ));
    }
    Ok(decoded)
}

fn project_bytes(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let bytes = match input {
        StrictSignedJson::String(value) => strict_base64(value)?,
        StrictSignedJson::Object(values) if values.len() == 1 => {
            let encoded = strict_text(
                values
                    .get("$bytes")
                    .ok_or_else(|| TransportError::Serialization("invalid byte object".into()))?,
                "$bytes",
            )?;
            strict_base64(encoded)?
        }
        StrictSignedJson::Array(values) => values
            .iter()
            .map(|value| match value {
                StrictSignedJson::Integer(value) => u8::try_from(*value).map_err(|_| {
                    TransportError::Serialization("byte array member is outside 0..=255".into())
                }),
                _ => Err(TransportError::Serialization(
                    "byte array member is not an integer".into(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(TransportError::Serialization(
                "clean-chat bytes have the wrong JSON type".into(),
            ))
        }
    };
    let length = bytes.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(TransportError::Serialization(
            "bytes are outside the clean-chat length bound".into(),
        ));
    }
    Ok(CanonicalValue::Bytes(bytes))
}

fn project_integer(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Integer(value) = input else {
        return Err(TransportError::Serialization(
            "clean-chat integer has the wrong JSON type".into(),
        ));
    };
    if *value > 9_007_199_254_740_991
        || schema["minimum"]
            .as_i64()
            .is_some_and(|min| *value < min as u64)
        || schema["maximum"]
            .as_i64()
            .is_some_and(|max| *value > max as u64)
        || schema["const"]
            .as_i64()
            .is_some_and(|constant| *value != constant as u64)
    {
        return Err(TransportError::Serialization(
            "integer is outside the clean-chat bound".into(),
        ));
    }
    Ok(CanonicalValue::Integer(*value))
}

fn project_boolean(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Bool(value) = input else {
        return Err(TransportError::Serialization(
            "clean-chat boolean has the wrong JSON type".into(),
        ));
    };
    if schema["const"]
        .as_bool()
        .is_some_and(|constant| *value != constant)
    {
        return Err(TransportError::Serialization(
            "boolean violates the clean-chat constant".into(),
        ));
    }
    Ok(CanonicalValue::Bool(*value))
}

fn project_array(
    schema: &serde_json::Value,
    input: &StrictSignedJson,
    field_name: Option<&str>,
) -> Result<CanonicalValue, TransportError> {
    let StrictSignedJson::Array(values) = input else {
        return Err(TransportError::Serialization(
            "clean-chat array has the wrong JSON type".into(),
        ));
    };
    let length = values.len() as u64;
    if schema["minLength"].as_u64().is_some_and(|min| length < min)
        || schema["maxLength"].as_u64().is_some_and(|max| length > max)
    {
        return Err(TransportError::Serialization(
            "array is outside the clean-chat length bound".into(),
        ));
    }
    let items = schema
        .get("items")
        .ok_or_else(|| TransportError::Serialization("array items schema is missing".into()))?;
    values
        .iter()
        .map(|value| project_schema(items, value, field_name, false))
        .collect::<Result<Vec<_>, _>>()
        .map(CanonicalValue::Array)
}

fn enforce_contract_order(
    definition_name: &str,
    object: &BTreeMap<String, CanonicalValue>,
) -> Result<(), TransportError> {
    if matches!(
        definition_name,
        "deviceEnrollmentBody" | "keyPackageReplenishmentBody"
    ) {
        let values = canonical_array(object, "keyPackages")?;
        let mut previous: Option<&[u8]> = None;
        for value in values {
            let item = canonical_map(value, "keyPackages item")?;
            let key_package_ref = canonical_bytes(item, "keyPackageRef")?;
            if previous.is_some_and(|prior| prior >= key_package_ref) {
                return Err(TransportError::Serialization(
                    "keyPackageRef values must be strictly increasing".into(),
                ));
            }
            previous = Some(key_package_ref);
        }
    }
    if matches!(
        definition_name,
        "creationManifest" | "resetActivationManifest"
    ) {
        enforce_did_order(object, "participants", "userDid")?;
    }
    if matches!(
        definition_name,
        "transitionManifest" | "policyTransitionBody"
    ) {
        enforce_did_order(object, "participantChanges", "userDid")?;
    }
    if definition_name == "transitionManifest" {
        let values = canonical_array(object, "leafChanges")?;
        let mut previous: Option<(&[u8], &[u8], u8)> = None;
        for value in values {
            let item = canonical_map(value, "leafChanges item")?;
            let did = canonical_text(item, "userDid")?.as_bytes();
            let device = canonical_bytes(item, "deviceId")?;
            let operation_rank = match canonical_text(item, "$type")? {
                "blue.catbird.chat.defs#removeLeaf" => 0,
                "blue.catbird.chat.defs#addLeafByRecovery" => 1,
                _ => {
                    return Err(TransportError::Serialization(
                        "unknown leaf change operation".into(),
                    ))
                }
            };
            if previous
                .is_some_and(|prior| (prior.0, prior.1, prior.2) >= (did, device, operation_rank))
            {
                return Err(TransportError::Serialization(
                    "leaf changes must be strictly ordered".into(),
                ));
            }
            previous = Some((did, device, operation_rank));
        }
    }
    Ok(())
}

fn canonical_map<'a>(
    value: &'a CanonicalValue,
    field: &str,
) -> Result<&'a BTreeMap<String, CanonicalValue>, TransportError> {
    match value {
        CanonicalValue::Map(value) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "{field} is not an object"
        ))),
    }
}

fn canonical_array<'a>(
    object: &'a BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<&'a [CanonicalValue], TransportError> {
    match object.get(field) {
        Some(CanonicalValue::Array(value)) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not an array"
        ))),
    }
}

fn enforce_did_order(
    object: &BTreeMap<String, CanonicalValue>,
    array_name: &str,
    did_name: &str,
) -> Result<(), TransportError> {
    let values = canonical_array(object, array_name)?;
    let mut previous: Option<&[u8]> = None;
    for value in values {
        let item = canonical_map(value, array_name)?;
        let did = canonical_text(item, did_name)?.as_bytes();
        if previous.is_some_and(|prior| prior >= did) {
            return Err(TransportError::Serialization(format!(
                "{array_name} values must be strictly ordered"
            )));
        }
        previous = Some(did);
    }
    Ok(())
}

fn canonical_text<'a>(
    map: &'a BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<&'a str, TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Text(value)) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not text"
        ))),
    }
}

fn canonical_integer(
    map: &BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<i64, TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Integer(value)) => i64::try_from(*value).map_err(|_| {
            TransportError::Serialization(format!("signed body field {field} is too large"))
        }),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not an integer"
        ))),
    }
}

fn canonical_uuid(
    map: &BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<Uuid, TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Bytes(value)) if value.len() == 16 => {
            Uuid::from_slice(value).map_err(|_| {
                TransportError::Serialization(format!("signed body field {field} is not a UUID"))
            })
        }
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not a UUID"
        ))),
    }
}

fn canonical_bytes<'a>(
    map: &'a BTreeMap<String, CanonicalValue>,
    field: &str,
) -> Result<&'a [u8], TransportError> {
    match map.get(field) {
        Some(CanonicalValue::Bytes(value)) => Ok(value),
        _ => Err(TransportError::Serialization(format!(
            "signed body field {field} is not bytes"
        ))),
    }
}

fn validate_projected_binding(
    binding: &CleanChatSigningContext,
    operation: CanonicalOperation,
    body: &BTreeMap<String, CanonicalValue>,
    spec: SignedRequestSpec,
) -> Result<(String, Option<Vec<u8>>), TransportError> {
    validate_bare_did(&binding.actor_did)?;
    if canonical_text(body, "actorDid")? != binding.actor_did {
        return Err(TransportError::Serialization(
            "signed body actorDid does not match authenticated actor".into(),
        ));
    }
    let device_field = if operation == CanonicalOperation::EnrollDevice {
        "deviceId"
    } else {
        "actorDeviceId"
    };
    let body_device = canonical_uuid(body, device_field)?;
    let expected_device = validate_uuid(&binding.device_id, device_field)?;
    if body_device != expected_device {
        return Err(TransportError::DeviceBindingMismatch {
            body: body_device.hyphenated().to_string(),
            authenticated: binding.device_id.clone(),
        });
    }
    match operation {
        CanonicalOperation::EnrollDevice => {
            if let Some(CanonicalValue::Text(jkt)) = body.get("dpopJkt") {
                validate_jkt(jkt)?;
            }
            let expected = canonical_integer(body, "expectedAuthGeneration")?;
            if expected != 0 {
                return Err(TransportError::InvalidEnrollmentGeneration { actual: expected });
            }
        }
        _ => {
            if let Some(CanonicalValue::Text(jkt)) = body.get("dpopJkt") {
                validate_jkt(jkt)?;
            }
            let actual = canonical_integer(body, "authGeneration")?;
            validate_auth_generation(actual)?;
            let expected = binding
                .auth_generation
                .ok_or(TransportError::MissingAuthGeneration)?;
            if actual != expected {
                return Err(TransportError::AuthGenerationMismatch { expected, actual });
            }
        }
    }

    if canonical_text(body, "signatureDomain")? != spec.domain {
        return Err(TransportError::InvalidSignatureDomain);
    }
    let key_id = canonical_text(body, "keyId")?.to_owned();
    validate_key_id(&key_id)?;
    let body_public_key = body
        .get("signaturePublicKey")
        .map(|_| canonical_bytes(body, "signaturePublicKey").map(|value| value.to_vec()))
        .transpose()?;
    if let Some(public_key) = &body_public_key {
        if public_key.len() != 32 || derive_key_id(public_key) != key_id {
            return Err(TransportError::Serialization(
                "signaturePublicKey does not match body keyId".into(),
            ));
        }
    }
    Ok((key_id, body_public_key))
}

fn canonical_json_value(value: &CanonicalValue) -> serde_json::Value {
    match value {
        CanonicalValue::Text(value) => serde_json::Value::String(value.clone()),
        CanonicalValue::Bytes(value) => serde_json::Value::String(STANDARD.encode(value)),
        CanonicalValue::Integer(value) => serde_json::json!(*value),
        CanonicalValue::Bool(value) => serde_json::Value::Bool(*value),
        CanonicalValue::Array(values) => {
            serde_json::Value::Array(values.iter().map(canonical_json_value).collect())
        }
        CanonicalValue::Map(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json_value(value)))
                .collect(),
        ),
    }
}

fn wire_json_ref(
    name: &str,
    value: &CanonicalValue,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match name {
        "operationId" | "deviceId" => match value {
            CanonicalValue::Bytes(value) if value.len() == 16 => Ok(serde_json::Value::String(
                Uuid::from_slice(value)
                    .map_err(|_| TransportError::Serialization("invalid wire UUID".into()))?
                    .hyphenated()
                    .to_string(),
            )),
            _ => Err(TransportError::Serialization(
                "invalid wire UUID value".into(),
            )),
        },
        "bareDid" | "keyId" | "canonicalDatetime" => Ok(canonical_json_value(value)),
        "artifactHash" | "identifierBytes" => Ok(canonical_json_value(value)),
        _ => wire_json_schema(chat_definition(name)?, value, Some(name), tagged),
    }
}

fn wire_json_schema(
    schema: &serde_json::Value,
    value: &CanonicalValue,
    field_name: Option<&str>,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match schema["type"].as_str() {
        Some("ref") => wire_json_ref(schema_ref_name(schema)?, value, false),
        Some("union") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization("invalid wire union".into()));
            };
            let tag = canonical_text(values, "$type")?;
            let variant = tag
                .strip_prefix(TYPE_PREFIX)
                .ok_or_else(|| TransportError::Serialization("invalid wire union tag".into()))?;
            wire_json_ref(variant, value, true)
        }
        Some("object") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization("invalid wire object".into()));
            };
            let properties = schema["properties"].as_object().ok_or_else(|| {
                TransportError::Serialization("invalid wire object properties".into())
            })?;
            let mut output = serde_json::Map::new();
            for (name, value) in values {
                if name == "$type" {
                    if tagged {
                        output.insert(name.clone(), canonical_json_value(value));
                    }
                    continue;
                }
                let property = properties.get(name).ok_or_else(|| {
                    TransportError::Serialization("unknown wire object field".into())
                })?;
                output.insert(
                    name.clone(),
                    wire_json_schema(property, value, Some(name), false)?,
                );
            }
            Ok(serde_json::Value::Object(output))
        }
        Some("bytes") | Some("string") | Some("integer") | Some("boolean") => {
            let _ = field_name;
            Ok(canonical_json_value(value))
        }
        Some("array") => match value {
            CanonicalValue::Array(values) => {
                let items = schema.get("items").ok_or_else(|| {
                    TransportError::Serialization("invalid wire array items".into())
                })?;
                Ok(serde_json::Value::Array(
                    values
                        .iter()
                        .map(|value| wire_json_schema(items, value, field_name, false))
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            _ => Err(TransportError::Serialization("invalid wire array".into())),
        },
        _ => Err(TransportError::Serialization(
            "unsupported wire schema".into(),
        )),
    }
}

fn generated_json_ref(
    name: &str,
    value: &CanonicalValue,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match name {
        "operationId" | "deviceId" => match value {
            CanonicalValue::Bytes(value) if value.len() == 16 => Ok(serde_json::Value::String(
                Uuid::from_slice(value)
                    .map_err(|_| TransportError::Serialization("invalid generated UUID".into()))?
                    .hyphenated()
                    .to_string(),
            )),
            _ => Err(TransportError::Serialization(
                "invalid generated UUID value".into(),
            )),
        },
        "bareDid" | "keyId" | "canonicalDatetime" => Ok(canonical_json_value(value)),
        "artifactHash" | "identifierBytes" => match value {
            CanonicalValue::Bytes(value) => Ok(serde_json::Value::Array(
                value.iter().map(|byte| serde_json::json!(*byte)).collect(),
            )),
            _ => Err(TransportError::Serialization(
                "invalid generated byte alias".into(),
            )),
        },
        _ => generated_json_schema(chat_definition(name)?, value, tagged),
    }
}

fn generated_json_schema(
    schema: &serde_json::Value,
    value: &CanonicalValue,
    tagged: bool,
) -> Result<serde_json::Value, TransportError> {
    match schema["type"].as_str() {
        Some("ref") => generated_json_ref(schema_ref_name(schema)?, value, false),
        Some("union") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization(
                    "invalid generated union".into(),
                ));
            };
            let tag = canonical_text(values, "$type")?;
            let variant = tag.strip_prefix(TYPE_PREFIX).ok_or_else(|| {
                TransportError::Serialization("invalid generated union tag".into())
            })?;
            generated_json_ref(variant, value, true)
        }
        Some("object") => {
            let CanonicalValue::Map(values) = value else {
                return Err(TransportError::Serialization(
                    "invalid generated object".into(),
                ));
            };
            let properties = schema["properties"].as_object().ok_or_else(|| {
                TransportError::Serialization("invalid generated object properties".into())
            })?;
            let mut output = serde_json::Map::new();
            for (name, value) in values {
                if name == "$type" {
                    if tagged {
                        output.insert(name.clone(), canonical_json_value(value));
                    }
                    continue;
                }
                let property = properties.get(name).ok_or_else(|| {
                    TransportError::Serialization("unknown generated object field".into())
                })?;
                output.insert(name.clone(), generated_json_schema(property, value, false)?);
            }
            Ok(serde_json::Value::Object(output))
        }
        Some("bytes") => match value {
            CanonicalValue::Bytes(value) => {
                Ok(serde_json::json!({"$bytes": STANDARD.encode(value)}))
            }
            _ => Err(TransportError::Serialization(
                "invalid generated bytes".into(),
            )),
        },
        Some("array") => match value {
            CanonicalValue::Array(values) => {
                let items = schema.get("items").ok_or_else(|| {
                    TransportError::Serialization("invalid generated array items".into())
                })?;
                Ok(serde_json::Value::Array(
                    values
                        .iter()
                        .map(|value| generated_json_schema(items, value, false))
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            }
            _ => Err(TransportError::Serialization(
                "invalid generated array".into(),
            )),
        },
        Some("string") | Some("integer") | Some("boolean") => Ok(canonical_json_value(value)),
        _ => Err(TransportError::Serialization(
            "unsupported generated schema".into(),
        )),
    }
}

#[derive(Debug)]
pub(crate) struct SignedBodyProjection {
    operation: CanonicalOperation,
    spec: SignedRequestSpec,
    pub(crate) transcript: Vec<u8>,
    pub(crate) key_id: String,
    pub(crate) body_public_key: Option<Vec<u8>>,
    pub(crate) body_json: serde_json::Value,
    pub(crate) generated_body_json: serde_json::Value,
    pub(crate) expected_device_id: String,
    pub(crate) expected_auth_generation: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
struct SignedRequestSpec {
    domain: &'static str,
    body_type: &'static str,
    variant: Option<&'static str>,
}

fn signed_request_spec(
    operation: CanonicalOperation,
    variant: Option<&str>,
) -> Result<SignedRequestSpec, TransportError> {
    let spec = match operation {
        CanonicalOperation::AcceptConversation => SignedRequestSpec {
            domain: ACCEPT_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#participantAcceptanceBody",
            variant: None,
        },
        CanonicalOperation::AcknowledgeWelcome => SignedRequestSpec {
            domain: WELCOME_ACK_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#welcomeAcknowledgementBody",
            variant: None,
        },
        CanonicalOperation::ActivateReset => SignedRequestSpec {
            domain: RESET_ACTIVATE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#resetActivationBody",
            variant: None,
        },
        CanonicalOperation::CancelLeafRecovery => SignedRequestSpec {
            domain: LEAF_RECOVERY_CANCEL_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#leafRecoveryCancellationBody",
            variant: None,
        },
        CanonicalOperation::CancelLeave => SignedRequestSpec {
            domain: LEAVE_CANCEL_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#leaveCancellationBody",
            variant: None,
        },
        CanonicalOperation::CloseConversation => SignedRequestSpec {
            domain: CLOSE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#conversationCloseBody",
            variant: None,
        },
        CanonicalOperation::CreateConversation => SignedRequestSpec {
            domain: CREATE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#creationBody",
            variant: None,
        },
        CanonicalOperation::SendMessage => SignedRequestSpec {
            domain: MESSAGE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#applicationSendBody",
            variant: None,
        },
        CanonicalOperation::PublishTyping => SignedRequestSpec {
            domain: TYPING_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#typingBody",
            variant: None,
        },
        CanonicalOperation::RejectWelcome => SignedRequestSpec {
            domain: WELCOME_REJECT_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#welcomeRejectionBody",
            variant: None,
        },
        CanonicalOperation::ReplenishKeyPackages => SignedRequestSpec {
            domain: REPLENISH_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#keyPackageReplenishmentBody",
            variant: None,
        },
        CanonicalOperation::RequestLeafRecovery => SignedRequestSpec {
            domain: LEAF_RECOVERY_REQUEST_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#leafRecoveryRequestBody",
            variant: None,
        },
        CanonicalOperation::EnrollDevice => SignedRequestSpec {
            domain: DEVICE_ENROLL_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#deviceEnrollmentBody",
            variant: None,
        },
        CanonicalOperation::RequestReset => SignedRequestSpec {
            domain: RESET_REQUEST_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#resetRequestBody",
            variant: None,
        },
        CanonicalOperation::RevokeDevice => SignedRequestSpec {
            domain: DEVICE_REVOKE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#deviceRevocationBody",
            variant: None,
        },
        CanonicalOperation::ApproveDevice => SignedRequestSpec {
            domain: DEVICE_APPROVE_SIGNATURE_DOMAIN,
            body_type: "blue.catbird.chat.defs#deviceApprovalBody",
            variant: None,
        },
        CanonicalOperation::RequestLeave => match variant {
            Some("blue.catbird.chat.defs#signedLeaveRequest") => SignedRequestSpec {
                domain: LEAVE_REQUEST_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#leaveRequestBody",
                variant: Some("blue.catbird.chat.defs#signedLeaveRequest"),
            },
            Some("blue.catbird.chat.defs#signedZeroLeafLeave") => SignedRequestSpec {
                domain: LEAVE_ZERO_LEAF_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#zeroLeafLeaveBody",
                variant: Some("blue.catbird.chat.defs#signedZeroLeafLeave"),
            },
            _ => {
                return Err(TransportError::Serialization(
                    "requestLeave signedRequest requires a known union $type".into(),
                ))
            }
        },
        CanonicalOperation::SubmitTransition => match variant {
            Some("blue.catbird.chat.defs#signedCommitTransition") => SignedRequestSpec {
                domain: COMMIT_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#commitTransitionBody",
                variant: Some("blue.catbird.chat.defs#signedCommitTransition"),
            },
            Some("blue.catbird.chat.defs#signedPolicyTransition") => SignedRequestSpec {
                domain: POLICY_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#policyTransitionBody",
                variant: Some("blue.catbird.chat.defs#signedPolicyTransition"),
            },
            Some("blue.catbird.chat.defs#signedLeafRecoveryFulfillment") => SignedRequestSpec {
                domain: LEAF_RECOVERY_FULFILL_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
                variant: Some("blue.catbird.chat.defs#signedLeafRecoveryFulfillment"),
            },
            Some("blue.catbird.chat.defs#signedMetadataTransition") => SignedRequestSpec {
                domain: METADATA_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#metadataTransitionBody",
                variant: Some("blue.catbird.chat.defs#signedMetadataTransition"),
            },
            Some("blue.catbird.chat.defs#signedLeaveCommitFulfillment") => SignedRequestSpec {
                domain: LEAVE_FULFILL_SIGNATURE_DOMAIN,
                body_type: "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
                variant: Some("blue.catbird.chat.defs#signedLeaveCommitFulfillment"),
            },
            _ => {
                return Err(TransportError::Serialization(
                    "submitTransition signedRequest requires a known union $type".into(),
                ))
            }
        },
        operation => {
            return Err(TransportError::UnsupportedOperation {
                operation,
                reason: "only generated signed mutation endpoints may use the signed orchestrator",
            })
        }
    };
    Ok(spec)
}

fn signed_spec_for_body(
    operation: CanonicalOperation,
    body_type: &str,
    outer_variant: Option<&str>,
) -> Result<SignedRequestSpec, TransportError> {
    let variant = match operation {
        CanonicalOperation::RequestLeave => match body_type {
            "blue.catbird.chat.defs#leaveRequestBody" => {
                "blue.catbird.chat.defs#signedLeaveRequest"
            }
            "blue.catbird.chat.defs#zeroLeafLeaveBody" => {
                "blue.catbird.chat.defs#signedZeroLeafLeave"
            }
            _ => {
                return Err(TransportError::Serialization(
                    "requestLeave body type is invalid".into(),
                ))
            }
        },
        CanonicalOperation::SubmitTransition => match body_type {
            "blue.catbird.chat.defs#commitTransitionBody" => {
                "blue.catbird.chat.defs#signedCommitTransition"
            }
            "blue.catbird.chat.defs#policyTransitionBody" => {
                "blue.catbird.chat.defs#signedPolicyTransition"
            }
            "blue.catbird.chat.defs#leafRecoveryFulfillmentBody" => {
                "blue.catbird.chat.defs#signedLeafRecoveryFulfillment"
            }
            "blue.catbird.chat.defs#metadataTransitionBody" => {
                "blue.catbird.chat.defs#signedMetadataTransition"
            }
            "blue.catbird.chat.defs#leaveCommitFulfillmentBody" => {
                "blue.catbird.chat.defs#signedLeaveCommitFulfillment"
            }
            _ => {
                return Err(TransportError::Serialization(
                    "submitTransition body type is invalid".into(),
                ))
            }
        },
        _ => {
            if outer_variant.is_some() {
                return Err(TransportError::Serialization(
                    "signed wrapper tag is not allowed for non-union operation".into(),
                ));
            }
            return signed_request_spec(operation, None);
        }
    };
    if outer_variant.is_some_and(|outer| outer != variant) {
        return Err(TransportError::Serialization(
            "signed wrapper variant does not match body type".into(),
        ));
    }
    signed_request_spec(operation, Some(variant))
}

fn extract_strict_signed_body(
    value: StrictSignedJson,
) -> Result<(StrictSignedJson, Option<String>, Option<String>), TransportError> {
    let StrictSignedJson::Object(mut root) = value else {
        return Err(TransportError::Serialization(
            "signed request body must be a JSON object".into(),
        ));
    };
    if let Some(signed_request) = root.remove("signedRequest") {
        let root_variant = root
            .remove("$type")
            .map(|value| strict_text(&value, "$type").map(str::to_owned))
            .transpose()?;
        if !root.is_empty() {
            return Err(TransportError::Serialization(
                "signed request wrapper has unknown fields".into(),
            ));
        }
        let StrictSignedJson::Object(mut wrapper) = signed_request else {
            return Err(TransportError::Serialization(
                "signedRequest must be an object".into(),
            ));
        };
        let outer_variant = wrapper
            .remove("$type")
            .map(|value| strict_text(&value, "signedRequest.$type").map(str::to_owned))
            .transpose()?;
        let body = wrapper
            .remove("body")
            .ok_or_else(|| TransportError::Serialization("signedRequest is missing body".into()))?;
        if !wrapper.is_empty() {
            return Err(TransportError::Serialization(
                "signedRequest body input has unknown fields".into(),
            ));
        }
        return Ok((body, root_variant, outer_variant));
    }
    Ok((StrictSignedJson::Object(root), None, None))
}

pub(crate) fn prepare_signed_body(
    binding: &CleanChatSigningContext,
    operation: CanonicalOperation,
    body_json: &[u8],
) -> Result<SignedBodyProjection, TransportError> {
    let value = parse_strict_signed_json(body_json)?;
    let (body, root_variant, wrapper_variant) = extract_strict_signed_body(value)?;
    let outer_variant = match (root_variant, wrapper_variant) {
        (Some(root), Some(wrapper)) if root != wrapper => {
            return Err(TransportError::Serialization(
                "signed wrapper tags do not match".into(),
            ))
        }
        (Some(root), _) | (_, Some(root)) => Some(root),
        (None, None) => None,
    };
    let body_type = match &body {
        StrictSignedJson::Object(values) => strict_text(
            values.get("$type").ok_or_else(|| {
                TransportError::Serialization("signed body is missing $type".into())
            })?,
            "$type",
        )?,
        _ => {
            return Err(TransportError::Serialization(
                "signed body must be an object".into(),
            ))
        }
    };
    let spec = signed_spec_for_body(operation, body_type, outer_variant.as_deref())?;
    let definition_name = spec
        .body_type
        .strip_prefix(TYPE_PREFIX)
        .ok_or_else(|| TransportError::Serialization("invalid signed body definition".into()))?;
    let projected = project_schema_ref(definition_name, &body, true)?;
    let CanonicalValue::Map(body_map) = &projected else {
        return Err(TransportError::Serialization(
            "signed body projection is not an object".into(),
        ));
    };
    let (key_id, body_public_key) = validate_projected_binding(binding, operation, body_map, spec)?;
    let cbor = serde_ipld_dagcbor::to_vec(&projected)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    let mut transcript = spec.domain.as_bytes().to_vec();
    transcript.extend_from_slice(&cbor);
    if transcript.is_empty() {
        return Err(TransportError::EmptySigningTranscript);
    }
    let generated_body_json = generated_json_ref(definition_name, &projected, true)?;
    Ok(SignedBodyProjection {
        operation,
        spec,
        transcript,
        key_id,
        body_public_key,
        body_json: wire_json_ref(definition_name, &projected, true)?,
        generated_body_json,
        expected_device_id: binding.device_id.clone(),
        expected_auth_generation: binding.auth_generation,
    })
}

pub(crate) fn parse_generated_request(
    operation: CanonicalOperation,
    body: &[u8],
) -> Result<catbird_mls::canonical_transport::CleanChatRequest, String> {
    use catbird_mls::canonical_transport::CleanChatRequest;
    macro_rules! parse {
        ($ty:path, $variant:ident) => {
            serde_json::from_slice::<$ty>(body)
                .map(CleanChatRequest::$variant)
                .map_err(|error| format!("generated request is invalid: {error}"))
        };
    }
    use catbird_mls::atproto::blue_catbird::chat::{
        get_conversations::GetConversations, get_entries::GetEntries,
    };
    use catbird_mls::canonical_transport::{
        AcceptConversationRequestBody, AcknowledgeEntriesRequestBody,
        AcknowledgeWelcomeRequestBody, ActivateResetRequestBody, ApproveDeviceRequestBody,
        CancelLeafRecoveryRequestBody, CancelLeaveRequestBody, CloseConversationRequestBody,
        CreateConversationRequestBody, EnrollDeviceRequestBody, GetConversationStateRequestBody,
        GetDeviceKeyRequestBody, GetDevicesRequestBody, GetLeafRecoveryInboxRequestBody,
        GetOwnDevicesRequestBody, GetPendingWelcomesRequestBody, GetSubscriptionTicketRequestBody,
        PublishTypingRequestBody, RegisterPushGatewayRequestBody, RejectWelcomeRequestBody,
        RelaySpaceCredentialRequestBody, RelaySpaceReadRequestBody,
        ReplenishKeyPackagesRequestBody, RequestLeafRecoveryRequestBody, RequestLeaveRequestBody,
        RequestResetRequestBody, RevokeDeviceRequestBody, SendMessageRequestBody,
        SubmitTransitionRequestBody, SubscribeEventsRequestBody,
    };
    match operation {
        CanonicalOperation::PrepareDirectRequest
        | CanonicalOperation::PublishDirectRequest
        | CanonicalOperation::CancelDirectRequestPreparation
        | CanonicalOperation::GetDirectRequestOutcome
        | CanonicalOperation::PublishDirectRequestKeys => Err(
            "browser direct-request lifecycle is unavailable; v1 projection cannot authorize wire2"
                .into(),
        ),
        CanonicalOperation::AcceptConversation => {
            parse!(AcceptConversationRequestBody, AcceptConversation)
        }
        CanonicalOperation::AcknowledgeEntries => {
            parse!(AcknowledgeEntriesRequestBody, AcknowledgeEntries)
        }
        CanonicalOperation::AcknowledgeWelcome => {
            parse!(AcknowledgeWelcomeRequestBody, AcknowledgeWelcome)
        }
        CanonicalOperation::ActivateReset => parse!(ActivateResetRequestBody, ActivateReset),
        CanonicalOperation::CancelLeafRecovery => {
            parse!(CancelLeafRecoveryRequestBody, CancelLeafRecovery)
        }
        CanonicalOperation::CancelLeave => parse!(CancelLeaveRequestBody, CancelLeave),
        CanonicalOperation::CloseConversation => {
            parse!(CloseConversationRequestBody, CloseConversation)
        }
        CanonicalOperation::GetConversations => parse!(GetConversations<String>, GetConversations),
        CanonicalOperation::CreateConversation => {
            parse!(CreateConversationRequestBody, CreateConversation)
        }
        CanonicalOperation::SendMessage => parse!(SendMessageRequestBody, SendMessage),
        CanonicalOperation::GetConversationState => {
            parse!(GetConversationStateRequestBody, GetConversationState)
        }
        CanonicalOperation::GetDevices => parse!(GetDevicesRequestBody, GetDevices),
        CanonicalOperation::GetDeviceKey => parse!(GetDeviceKeyRequestBody, GetDeviceKey),
        CanonicalOperation::GetEntries => parse!(GetEntries<String>, GetEntries),
        CanonicalOperation::GetLeafRecoveryInbox => {
            parse!(GetLeafRecoveryInboxRequestBody, GetLeafRecoveryInbox)
        }
        CanonicalOperation::GetOwnDevices => parse!(GetOwnDevicesRequestBody, GetOwnDevices),
        CanonicalOperation::GetPendingWelcomes => {
            parse!(GetPendingWelcomesRequestBody, GetPendingWelcomes)
        }
        CanonicalOperation::GetSubscriptionTicket => {
            parse!(GetSubscriptionTicketRequestBody, GetSubscriptionTicket)
        }
        CanonicalOperation::PublishTyping => parse!(PublishTypingRequestBody, PublishTyping),
        CanonicalOperation::RegisterPushGateway => {
            parse!(RegisterPushGatewayRequestBody, RegisterPushGateway)
        }
        CanonicalOperation::RejectWelcome => parse!(RejectWelcomeRequestBody, RejectWelcome),
        CanonicalOperation::RelaySpaceCredential => {
            parse!(RelaySpaceCredentialRequestBody, RelaySpaceCredential)
        }
        CanonicalOperation::RelaySpaceRead => {
            parse!(RelaySpaceReadRequestBody, RelaySpaceRead)
        }
        CanonicalOperation::ReplenishKeyPackages => {
            parse!(ReplenishKeyPackagesRequestBody, ReplenishKeyPackages)
        }
        CanonicalOperation::RequestLeafRecovery => {
            parse!(RequestLeafRecoveryRequestBody, RequestLeafRecovery)
        }
        CanonicalOperation::EnrollDevice => parse!(EnrollDeviceRequestBody, EnrollDevice),
        CanonicalOperation::RequestLeave => parse!(RequestLeaveRequestBody, RequestLeave),
        CanonicalOperation::RequestReset => parse!(RequestResetRequestBody, RequestReset),
        CanonicalOperation::RevokeDevice => parse!(RevokeDeviceRequestBody, RevokeDevice),
        CanonicalOperation::SubmitTransition => {
            parse!(SubmitTransitionRequestBody, SubmitTransition)
        }
        CanonicalOperation::SubscribeEvents => parse!(SubscribeEventsRequestBody, SubscribeEvents),
        CanonicalOperation::ApproveDevice => parse!(ApproveDeviceRequestBody, ApproveDevice),
    }
}

pub(crate) fn finish_signed_request(
    prepared: SignedBodyProjection,
    signature: Vec<u8>,
) -> Result<PreparedRequest, TransportError> {
    if signature.len() != 64 {
        return Err(TransportError::InvalidSigningAuthority);
    }
    let mut generated_body = prepared.generated_body_json.clone();
    if let serde_json::Value::Object(values) = &mut generated_body {
        values.remove("$type");
    }
    let mut wrapper = serde_json::Map::new();
    if let Some(variant) = prepared.spec.variant {
        wrapper.insert("$type".into(), serde_json::Value::String(variant.into()));
    }
    wrapper.insert("body".into(), generated_body);
    wrapper.insert(
        "signature".into(),
        serde_json::json!({"$bytes": STANDARD.encode(&signature)}),
    );
    let endpoint = serde_json::json!({"signedRequest": wrapper});
    let endpoint_bytes = serde_json::to_vec(&endpoint)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;
    parse_generated_request(prepared.operation, &endpoint_bytes)
        .map_err(|error| TransportError::Serialization(error.to_string()))?;

    let wire = serde_json::json!({
        "signedRequest": {
            "body": prepared.body_json,
            "signature": STANDARD.encode(&signature),
        }
    });
    Ok(PreparedRequest {
        operation: prepared.operation,
        method: "POST".into(),
        path: canonical_route(prepared.operation).path.to_owned(),
        body: Some(
            serde_json::to_vec(&wire)
                .map_err(|error| TransportError::Serialization(error.to_string()))?,
        ),
    })
}

// ---------------------------------------------------------------------------
// Validators (ported verbatim from the approved native module)
// ---------------------------------------------------------------------------

/// Validate an unsigned read/event shape against the pinned canonical schema.
/// This validates framing only; shared orchestration owns all state authority.
pub(crate) fn validate_read_shape(
    name: &str,
    raw: &[u8],
) -> Result<serde_json::Value, TransportError> {
    let value = parse_strict_signed_json(raw)?;
    project_schema_ref(name, &value, false)?;
    serde_json::from_slice(raw).map_err(|e| TransportError::Serialization(e.to_string()))
}

pub(crate) fn derive_key_id(public_key: &[u8]) -> String {
    use sha2::Digest as _;
    URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(public_key))
}

fn canonical_uuid_bytes(value: &str, field: &str) -> Result<Vec<u8>, TransportError> {
    let uuid = validate_uuid(value, field)?;
    Ok(uuid.as_bytes().to_vec())
}

pub(crate) fn validate_uuid(value: &str, field: &str) -> Result<Uuid, TransportError> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| TransportError::Serialization(format!("{field} is not a UUID")))?;
    if uuid.get_version() != Some(Version::Random)
        || uuid.get_variant() != Variant::RFC4122
        || uuid.to_string() != value
    {
        return Err(TransportError::Serialization(format!(
            "{field} is not canonical lowercase UUIDv4"
        )));
    }
    Ok(uuid)
}

fn validate_jkt(value: &str) -> Result<(), TransportError> {
    if value.len() != 43
        || URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .is_none_or(|bytes| bytes.len() != 32)
        || URL_SAFE_NO_PAD.encode(URL_SAFE_NO_PAD.decode(value).unwrap()) != value
    {
        return Err(TransportError::Serialization(
            "dpopJkt is not canonical 43-character base64url".into(),
        ));
    }
    Ok(())
}

fn validate_key_id(value: &str) -> Result<(), TransportError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TransportError::Serialization("keyId is not canonical base64url".into()))?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(TransportError::Serialization(
            "keyId is not a canonical Ed25519 thumbprint".into(),
        ));
    }
    Ok(())
}

fn validate_auth_generation(value: i64) -> Result<(), TransportError> {
    if !(1..=9_007_199_254_740_991).contains(&value) {
        return Err(TransportError::Serialization(
            "authGeneration is outside the canonical safe integer range".into(),
        ));
    }
    Ok(())
}

fn validate_bare_did(value: &str) -> Result<(), TransportError> {
    let valid = value.is_ascii()
        && (12..=261).contains(&value.len())
        && if let Some(plc) = value.strip_prefix("did:plc:") {
            plc.len() == 24
                && plc
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        } else if let Some(host) = value.strip_prefix("did:web:") {
            validate_hostname(host)
        } else {
            false
        };
    if !valid {
        return Err(TransportError::Serialization(
            "actorDid is not a production bare DID".into(),
        ));
    }
    Ok(())
}

fn validate_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.ends_with('.') || host.eq("localhost") {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            !(!label.is_empty() && label.len() <= 63 && label.is_ascii())
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return false;
    }
    let tld = labels.last().unwrap();
    !tld.as_bytes()[0].is_ascii_digit()
        && !matches!(
            *tld,
            "alt"
                | "arpa"
                | "example"
                | "internal"
                | "invalid"
                | "local"
                | "localhost"
                | "onion"
                | "test"
        )
}

fn parse_datetime(value: String) -> Result<CanonicalDatetime, TransportError> {
    CanonicalDatetime::from_str(&value)
        .map_err(|_| TransportError::Serialization("signedAt is not a canonical datetime".into()))
}

fn validate_datetime(value: &str) -> Result<(), TransportError> {
    let bytes = value.as_bytes();
    let punctuation = [4, 7, 10, 13, 16, 19, 23];
    if bytes.len() != 24
        || !punctuation.iter().enumerate().all(|(index, position)| {
            let expected = b"--T::.Z"[index];
            bytes[*position] == expected
        })
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !punctuation.contains(&index) && !byte.is_ascii_digit())
    {
        return Err(TransportError::Serialization(
            "signedAt is not exact UTC milliseconds".into(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
enum CanonicalValue {
    Text(String),
    Bytes(Vec<u8>),
    Integer(u64),
    Bool(bool),
    Array(Vec<CanonicalValue>),
    Map(BTreeMap<String, CanonicalValue>),
}

impl Serialize for CanonicalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Text(value) => serializer.serialize_str(value),
            Self::Bytes(value) => serializer.serialize_bytes(value),
            Self::Integer(value) => serializer.serialize_u64(*value),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            Self::Map(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

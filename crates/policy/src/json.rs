//! JSON as policies are read: like `serde_json::Value`, except an object that names the
//! same key twice is refused instead of silently keeping the last one. Two readers of
//! one policy (TeiFS, and a person or tool reviewing it) must see the same statements.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// A JSON value read strictly: an object may not name a key twice. Policies are read
/// this way, and so are the web identity tokens `AssumeRoleWithWebIdentity` takes.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(serde_json::Number),
    /// A string.
    String(String),
    /// A list.
    Array(Vec<Json>),
    /// An object, its members in document order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Parses `text`, refusing an object that names a key twice.
    pub fn parse(text: &str) -> Result<Self, crate::Error> {
        serde_json::from_str(text).map_err(|e| crate::Error::new(format!("not valid JSON: {e}")))
    }

    /// What kind of value this is, for messages.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "a boolean",
            Self::Number(_) => "a number",
            Self::String(_) => "a string",
            Self::Array(_) => "a list",
            Self::Object(_) => "an object",
        }
    }
}

impl Json {
    /// The member `name` of an object; `None` for a missing member or another kind of
    /// value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text of a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON")
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Json, E> {
        serde_json::Number::from_f64(value)
            .map(Json::Number)
            .ok_or_else(|| E::custom("a number JSON can't hold"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Json, E> {
        Ok(Json::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Json, E> {
        Ok(Json::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64));
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut fields: Vec<(String, Json)> = Vec::new();
        while let Some(field) = map.next_entry::<String, Json>()? {
            fields.push(field);
        }
        // Sorted, so a large object costs n log n, not n².
        let mut names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        if let Some([name, _]) = names.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(de::Error::custom(format!("`{name}` appears twice")));
        }
        Ok(Json::Object(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_given_twice_is_refused_at_any_depth() {
        assert!(Json::parse(r#"{"a": 1, "b": {"c": true, "d": [null, "x"]}}"#).is_ok());
        let twice = Json::parse(r#"{"Effect": "Deny", "Effect": "Allow"}"#).unwrap_err();
        assert!(
            twice.to_string().contains("`Effect` appears twice"),
            "{twice}"
        );
        assert!(Json::parse(r#"{"a": [{"b": 1, "b": 2}]}"#).is_err());
        // Keys differing in case are different keys, as in JSON.
        assert!(Json::parse(r#"{"a": 1, "A": 2}"#).is_ok());
    }

    #[test]
    fn values_keep_their_kind_and_order() {
        let json = Json::parse(r#"{"z": 1.5, "a": -2, "m": false}"#).unwrap();
        let Json::Object(fields) = json else {
            panic!("an object")
        };
        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["z", "a", "m"]);
        assert_eq!(
            fields[0].1,
            Json::Number(serde_json::Number::from_f64(1.5).unwrap())
        );
        assert_eq!(fields[2].1.kind(), "a boolean");
    }
}

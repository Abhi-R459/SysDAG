//! Deterministic length-prefixed serialization and SHA-256 digests.
//!
//! Never uses language-runtime hash maps for persisted artifacts. Missing is a
//! distinct token from empty or zero so `ab|c` cannot collide with `a|bc`.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

const MISSING: &[u8] = b"\x00N";
const FALSE: &[u8] = b"\x00F";
const TRUE: &[u8] = b"\x00T";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Canon {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Canon>),
    Map(BTreeMap<String, Canon>),
}

impl Canon {
    pub fn str(s: impl Into<String>) -> Self {
        Self::Str(nfc(&s.into()))
    }

    pub fn map_from<I, K>(items: I) -> Self
    where
        I: IntoIterator<Item = (K, Canon)>,
        K: Into<String>,
    {
        let mut map = BTreeMap::new();
        for (k, v) in items {
            map.insert(nfc(&k.into()), v);
        }
        Self::Map(map)
    }
}

pub fn nfc(text: &str) -> String {
    text.nfc().collect()
}

pub fn dumps(value: &Canon) -> Vec<u8> {
    match value {
        Canon::Null => MISSING.to_vec(),
        Canon::Bool(false) => FALSE.to_vec(),
        Canon::Bool(true) => TRUE.to_vec(),
        Canon::Int(n) => {
            let mut out = Vec::from(b"I");
            out.extend(n.to_string().as_bytes());
            out.push(b';');
            out
        }
        Canon::Str(s) => {
            let encoded = nfc(s).into_bytes();
            let mut out = Vec::from(b"S");
            out.extend(encoded.len().to_string().as_bytes());
            out.push(b':');
            out.extend(encoded);
            out
        }
        Canon::Bytes(b) => {
            let mut out = Vec::from(b"B");
            out.extend(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend(b);
            out
        }
        Canon::List(items) => {
            let parts: Vec<Vec<u8>> = items.iter().map(dumps).collect();
            let mut out = Vec::from(b"L");
            out.extend(parts.len().to_string().as_bytes());
            out.push(b';');
            for p in parts {
                out.extend(p);
            }
            out
        }
        Canon::Map(map) => {
            let mut out = Vec::from(b"D");
            out.extend(map.len().to_string().as_bytes());
            out.push(b';');
            for (k, v) in map {
                out.extend(dumps(&Canon::str(k)));
                out.extend(dumps(v));
            }
            out
        }
    }
}

pub fn digest(value: &Canon) -> String {
    hex::encode(Sha256::digest(dumps(value)))
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical_multiset(tokens: &[Canon]) -> Vec<u8> {
    let mut encoded: Vec<Vec<u8>> = tokens.iter().map(dumps).collect();
    encoded.sort();
    let mut out = Vec::from(b"M");
    out.extend(encoded.len().to_string().as_bytes());
    out.push(b';');
    for p in encoded {
        out.extend(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_avoids_pipe_ambiguity() {
        let ab_c = dumps(&Canon::List(vec![Canon::str("ab"), Canon::str("c")]));
        let a_bc = dumps(&Canon::List(vec![Canon::str("a"), Canon::str("bc")]));
        assert_ne!(ab_c, a_bc);
        assert_ne!(digest(&Canon::str("ab|c")), digest(&Canon::str("a|bc")));
    }

    #[test]
    fn missing_is_not_empty_or_zero() {
        assert_ne!(dumps(&Canon::Null), dumps(&Canon::str("")));
        assert_ne!(dumps(&Canon::Null), dumps(&Canon::Int(0)));
        assert_ne!(dumps(&Canon::str("")), dumps(&Canon::Int(0)));
    }

    #[test]
    fn map_keys_are_sorted() {
        let a = Canon::map_from([("b", Canon::Int(1)), ("a", Canon::Int(2))]);
        let b = Canon::map_from([("a", Canon::Int(2)), ("b", Canon::Int(1))]);
        assert_eq!(dumps(&a), dumps(&b));
    }

    #[test]
    fn digest_is_stable() {
        let d = digest(&Canon::str("sysdag"));
        assert_eq!(d.len(), 64);
        assert_eq!(d, digest(&Canon::str("sysdag")));
    }
}

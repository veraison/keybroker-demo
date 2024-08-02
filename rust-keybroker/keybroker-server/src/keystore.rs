// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use keybroker_common::PublicWrappingKey;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};

use crate::error::Result;
use std::collections::HashMap;

/// A minimally simple key-value store where the lookup keys are strings and the values
/// are byte arrays (octet vectors).
///
/// The byte arrays are typically intended to be encryption keys, which is why this
/// structure is called a "key store", so take care not to confuse the lookup keys
/// (which are strings) with the values, since the term "key" can be ambiguous.
///
/// The byte arrays do not necessarily need to be encryption keys. They could be other small
/// secret data blobs. However, whatever they are, they should be small, because they
/// are treated using asymmetric encryption methods. Do not store very large data
/// blobs in this store. It is only intended to demonstrate the retrieval of secrets
/// in confidential computing contexts.
///
/// Data is never revealed in plaintext - only the `wrap()` function is used, which
/// encrypts data with a given public key.
pub struct KeyStore {
    keys: HashMap<String, Vec<u8>>,
}

impl KeyStore {
    /// Create a new, empty key store
    pub fn new() -> KeyStore {
        KeyStore {
            keys: HashMap::new(),
        }
    }

    /// Store a new key in the key store.
    ///
    /// Key data here is provided as plain text. That's because this is an initialization
    /// function that is only used by the internals of the key broker to build the contents
    /// of the store from trusted internal sources, such as command-line arguments or a local
    /// configuration file.
    pub fn store_key(&mut self, key_id: &String, data: Vec<u8>) -> () {
        self.keys.insert(key_id.clone(), data.clone());
    }

    /// Obtain a wrapped (encrypted) data item from the store.
    pub fn wrap_key(&self, key_id: &String, wrapping_key: &PublicWrappingKey) -> Result<Vec<u8>> {
        let k_mod = URL_SAFE_NO_PAD.decode(&wrapping_key.n)?;
        let n = BigUint::from_bytes_be(&k_mod);
        let k_exp = URL_SAFE_NO_PAD.decode(&wrapping_key.e)?;
        let e = BigUint::from_bytes_be(&k_exp);

        let mut rng = rand::thread_rng();

        let rsa_pub_key = RsaPublicKey::new(n, e)?;

        if let Some(entry) = self.keys.get_key_value(key_id) {
            let (_k, data) = entry;
            let wrapped_data = rsa_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)?;
            Ok(wrapped_data)
        } else {
            Err(crate::error::Error::KeyStoreError(
                crate::error::KeyStoreErrorKind::KeyNotFound,
            ))
        }
    }
}

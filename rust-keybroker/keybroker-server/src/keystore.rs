// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use keybroker_common::{PublicWrappingKey, WrappedKeyData};
use rsa::{BigUint, Oaep, Pkcs1v15Encrypt, RsaPublicKey};
use sha2::Sha256;

use crate::error::Result;
use std::collections::HashMap;

const RSA_KEY_TYPE: &str = "RSA";
const RSA_PKCS15_ALGORITHM: &str = "RSA1_5";
const RSA_OAEP_ALGORITHM: &str = "RSA-OAEP";

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
    pub fn wrap_key(
        &self,
        key_id: &String,
        wrapping_key: &PublicWrappingKey,
    ) -> Result<WrappedKeyData> {
        if wrapping_key.kty != *RSA_KEY_TYPE {
            return Err(crate::error::Error::KeyStoreError(
                crate::error::KeyStoreErrorKind::UnsupportedWrappingKeyType,
            ));
        }

        let k_mod = URL_SAFE_NO_PAD.decode(&wrapping_key.n)?;
        let n = BigUint::from_bytes_be(&k_mod);
        let k_exp = URL_SAFE_NO_PAD.decode(&wrapping_key.e)?;
        let e = BigUint::from_bytes_be(&k_exp);

        let mut rng = rand::thread_rng();

        let rsa_pub_key = RsaPublicKey::new(n, e)?;

        if let Some(entry) = self.keys.get_key_value(key_id) {
            let (_k, data) = entry;
            let wrapped_data = {
                if wrapping_key.alg == *RSA_PKCS15_ALGORITHM {
                    rsa_pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
                } else if wrapping_key.alg == *RSA_OAEP_ALGORITHM {
                    let padding = Oaep::new::<Sha256>();
                    rsa_pub_key.encrypt(&mut rng, padding, data)
                } else {
                    return Err(crate::error::Error::KeyStoreError(
                        crate::error::KeyStoreErrorKind::UnsupportedWrappingKeyAlgorithm,
                    ));
                }
            }?;
            let data_base64 = URL_SAFE_NO_PAD.encode(wrapped_data);
            let retobj = WrappedKeyData { data: data_base64 };
            Ok(retobj)
        } else {
            Err(crate::error::Error::KeyStoreError(
                crate::error::KeyStoreErrorKind::KeyNotFound,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{traits::PublicKeyParts, RsaPrivateKey};

    fn key_store_round_trip(kty: &str, alg: &str) {
        let mut store = KeyStore::new();

        // Put a key into the store
        let key_id = "skywalker";
        let key_content = "May the force be with you.";
        store.store_key(&key_id.to_string(), key_content.as_bytes().to_vec());

        // Create an ephemeral wrapping key-pair
        let mut rng = rand::thread_rng();
        let bits = 1024;
        let priv_key =
            RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate ephemeral wrapping key.");

        // Get the public key and deconstruct into modulus and exponent
        let pub_key = RsaPublicKey::from(&priv_key);
        let k_mod = pub_key.n();
        let k_exp = pub_key.e();

        // Create base64 strings for n and e
        let k_mod_base64 = URL_SAFE_NO_PAD.encode(BigUint::to_bytes_be(k_mod));
        let k_exp_base64 = URL_SAFE_NO_PAD.encode(BigUint::to_bytes_be(k_exp));

        // Turn this into API-level input
        let wrapping_key = PublicWrappingKey {
            kty: kty.to_string(),
            alg: alg.to_string(),
            n: k_mod_base64,
            e: k_exp_base64,
        };

        // Make the API call
        let wrapped_data = store
            .wrap_key(&key_id.to_string(), &wrapping_key)
            .expect("Key store did not return the wrapped key.");

        // Decode and decrypt with the private key.
        let ciphertext = URL_SAFE_NO_PAD
            .decode(wrapped_data.data)
            .expect("Failed to base64-decode the wrapped data from the key store.");
        let plaintext = {
            if alg == RSA_PKCS15_ALGORITHM {
                priv_key
                    .decrypt(Pkcs1v15Encrypt, &ciphertext)
                    .expect("Failed to decrypt wrapped data from the key store.")
            } else if alg == RSA_OAEP_ALGORITHM {
                let padding = Oaep::new::<Sha256>();
                priv_key
                    .decrypt(padding, &ciphertext)
                    .expect("Failed to decrypt wrapped data from the key store.")
            } else {
                vec![]
            }
        };

        // Check we got it back
        assert_eq!(key_content.as_bytes(), &plaintext);
    }

    #[test]
    fn round_trip_rsa_pkcs15() {
        key_store_round_trip(RSA_KEY_TYPE, RSA_PKCS15_ALGORITHM)
    }

    #[test]
    fn round_trip_rsa_oaep() {
        key_store_round_trip(RSA_KEY_TYPE, RSA_OAEP_ALGORITHM)
    }
}

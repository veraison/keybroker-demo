// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

//! This module handles the creation and caching of challenges.
//!
//! A challenge is allocated whenever a client of the keybroker makes its initial request to access a key from the store.
//! Keys are never returned directly to the client. Instead, a challenge is created. This challenge invites the client to
//! form a bundle of attestation evidence to prove that it is trustworthy to receive the key. The client must incorporate
//! the challenge value (commonly called a "nonce") into the signed attestation evidence, according to the specific
//! conventions of the evidence type that it employs.
//!
//! When a challenge is allocated, it is cached by the server along with all of the details that the client initially
//! provided: included the identity of the key that it wants to access, and the public wrapping key that it provided in
//! order to keep the data protected in transit.
//!
//! Challenges are given their own unique identities (simple 32-bit integer values) and cached within the keybroker service,
//! with the expectation that the client will later attempt to redeem the challenge by submitting an evidence bundle.
//!
use crate::error::Result;
use keybroker_common::PublicWrappingKey;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;

/// Represents a single challenge, and provides the challenge value ("nonce") while also remembering the information
/// that the client provided in order to access a key.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// The identity of the challenge itself. A simple integer value, designed to be unique only within the keybroker
    /// server instance. This value (represented in decimal) also forms part of the URL path when the client
    /// redeems the challenge by supplying the attestation evidence bundle.
    pub challenge_id: u32,

    /// The identity of the key that the client wants to access.
    pub key_id: String,

    /// The public part of the wrapping key pair that the client has specified for use in order to protect the
    /// secret data in transit when it is later returned.
    pub wrapping_key: PublicWrappingKey,

    /// The challenge value (nonce) that the client must incorporate into the evidence bundle.
    pub challenge_value: Vec<u8>,
}

/// This structure provides a hash map of challenges, keyed on the integer challenge identifier.
pub struct Challenger {
    challenge_table: HashMap<u32, Challenge>,
    rng: StdRng,
    pub verbose: bool,
}

// This is the challenge value from from https://git.trustedfirmware.org/TF-M/tf-m-tools/+/refs/heads/main/iat-verifier/tests/data/cca_example_token.cbor
// TODO: This is only being used during early development of the service, where the client is being mocked and therefore certain fixed values are
// expected. As soon as we move to proper random nonces and testing with real clients, this constant should be deleted.
const CCA_EXAMPLE_TOKEN_NONCE: &[u8] = &[
    0x6e, 0x86, 0xd6, 0xd9, 0x7c, 0xc7, 0x13, 0xbc, 0x6d, 0xd4, 0x3d, 0xbc, 0xe4, 0x91, 0xa6, 0xb4,
    0x03, 0x11, 0xc0, 0x27, 0xa8, 0xbf, 0x85, 0xa3, 0x9d, 0xa6, 0x3e, 0x9c, 0xe4, 0x4c, 0x13, 0x2a,
    0x8a, 0x11, 0x9d, 0x29, 0x6f, 0xae, 0x6a, 0x69, 0x99, 0xe9, 0xbf, 0x3e, 0x44, 0x71, 0xb0, 0xce,
    0x01, 0x24, 0x5d, 0x88, 0x94, 0x24, 0xc3, 0x1e, 0x89, 0x79, 0x3b, 0x3b, 0x1d, 0x6b, 0x15, 0x04,
];

impl Challenger {
    pub fn new() -> Challenger {
        Challenger {
            challenge_table: HashMap::new(),
            rng: StdRng::from_entropy(),
            verbose: false,
        }
    }

    /// Allocate a new challenge and store it in the table.
    ///
    /// The inputs are the identity of the key that the client wants to access, and the public wrapping
    /// key that the client has specified to encrypt and protect the data in transit.
    pub fn create_challenge(
        &mut self,
        key_id: &str,
        wrapping_key: &PublicWrappingKey,
        mock_challenge: bool,
    ) -> Challenge {
        // All challenges are given random u32 identities
        let mut challenge_id: u32 = self.rng.gen();

        // Simple lightweight collision avoidance - probably not needed given u32 distribution space,
        // but it's easy to do. Also allows us to throw out zero if we get it.
        while challenge_id == 0 || self.challenge_table.contains_key(&challenge_id) {
            challenge_id = self.rng.gen();
        }

        let challenge = Challenge {
            challenge_id,
            key_id: key_id.to_owned(),
            wrapping_key: wrapping_key.clone(),
            challenge_value: if mock_challenge {
                CCA_EXAMPLE_TOKEN_NONCE.to_vec()
            } else {
                let mut v: Vec<u8> = vec![0; 64];
                self.rng.fill(&mut v[..]);
                v
            },
        };

        self.challenge_table.insert(challenge_id, challenge.clone());

        if self.verbose {
            println!("Created challenge:");
            println!(" - challenge_id: {}", challenge_id);
            println!(" - key_id: {}", challenge.key_id);
            println!(
                " - challenge value ({} bytes): {:02x?}",
                challenge.challenge_value.len(),
                challenge.challenge_value
            );
        }

        challenge
    }

    /// Looks up a challenge in the table and returns it, failing if no such challenge is found.
    pub fn get_challenge(&self, challenge_id: u32) -> Result<Challenge> {
        let challenge = self.challenge_table.get(&challenge_id);
        match challenge {
            Some(c) => Ok(c.clone()),
            None => Err(crate::error::Error::Challenge(
                crate::error::ChallengeErrorKind::ChallengeNotFound,
            )),
        }
    }

    /// Deletes a challenge from the table, failing if no such challenge is found.
    ///
    /// The key broker deletes challenges eagerly, rather than relying on a garbage collection mechanism.
    /// This is for the sake of simplicity, since this is only a demo keybroker. Challenges are deleted
    /// as soon as the client makes an attempt to redeem the challenge by providing an attestation
    /// token. This happens even if the attestation verification fails, meaning that the client only
    /// has one opportunity to redeem any given challenge, otherwise it needs to begin the key
    /// request all over again.
    pub fn delete_challenge(&mut self, challenge_id: u32) -> Result<()> {
        let challenge = self.challenge_table.remove(&challenge_id);
        match challenge {
            Some(_c) => Ok(()),
            None => Err(crate::error::Error::Challenge(
                crate::error::ChallengeErrorKind::ChallengeNotFound,
            )),
        }
    }
}

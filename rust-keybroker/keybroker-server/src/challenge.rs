// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use keybroker_common::PublicWrappingKey;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Challenge {
    pub challenge_id: u32,
    pub key_id: String,
    pub wrapping_key: PublicWrappingKey,
    pub challenge_value: Vec<u8>,
}

pub struct Challenger {
    challenge_table: HashMap<u32, Challenge>,
}

// This is the challenge value from from https://git.trustedfirmware.org/TF-M/tf-m-tools/+/refs/heads/main/iat-verifier/tests/data/cca_example_token.cbor
// TODO: This is only being used during early development of the service, where the client is being mocked and therefore certain fixed values are
// expected. As soon as we move to proper random nonces and testing with real clients, this constant should be deleted.
const CCA_EXAMPLE_TOKEN_NONCE: &'static [u8] = &[
    0x6e, 0x86, 0xd6, 0xd9, 0x7c, 0xc7, 0x13, 0xbc, 0x6d, 0xd4, 0x3d, 0xbc, 0xe4, 0x91, 0xa6, 0xb4,
    0x03, 0x11, 0xc0, 0x27, 0xa8, 0xbf, 0x85, 0xa3, 0x9d, 0xa6, 0x3e, 0x9c, 0xe4, 0x4c, 0x13, 0x2a,
    0x8a, 0x11, 0x9d, 0x29, 0x6f, 0xae, 0x6a, 0x69, 0x99, 0xe9, 0xbf, 0x3e, 0x44, 0x71, 0xb0, 0xce,
    0x01, 0x24, 0x5d, 0x88, 0x94, 0x24, 0xc3, 0x1e, 0x89, 0x79, 0x3b, 0x3b, 0x1d, 0x6b, 0x15, 0x04,
];

impl Challenger {
    pub fn new() -> Challenger {
        Challenger {
            challenge_table: HashMap::new(),
        }
    }

    pub fn create_challenge(
        &mut self,
        key_id: &String,
        wrapping_key: &PublicWrappingKey,
    ) -> Challenge {
        // All challenges are given random u32 identities
        let mut challenge_id: u32 = rand::random();

        // Simple lightweight collision avoidance - probably not needed given u32 distribution space,
        // but it's easy to do. Also allows us to throw out zero if we get it.
        while challenge_id == 0 || self.challenge_table.contains_key(&challenge_id) {
            challenge_id = rand::random();
        }

        let challenge = Challenge {
            challenge_id: challenge_id,
            key_id: key_id.clone(),
            wrapping_key: wrapping_key.clone(),
            // TODO: We should create a random nonce here. The use of this mock value allows the
            // server to be tested with a hard-coded example attestation token during development.
            challenge_value: CCA_EXAMPLE_TOKEN_NONCE.to_vec(),
        };

        self.challenge_table.insert(challenge_id, challenge.clone());

        challenge
    }

    pub fn get_challenge(&self, challenge_id: u32) -> Result<Challenge> {
        let challenge = self.challenge_table.get(&challenge_id);
        match challenge {
            Some(c) => Ok(c.clone()),
            None => Err(crate::error::Error::ChallengeError(
                crate::error::ChallengeErrorKind::ChallengeNotFound,
            )),
        }
    }

    pub fn delete_challenge(&mut self, challenge_id: u32) -> Result<()> {
        let challenge = self.challenge_table.remove(&challenge_id);
        match challenge {
            Some(_c) => Ok(()),
            None => Err(crate::error::Error::ChallengeError(
                crate::error::ChallengeErrorKind::ChallengeNotFound,
            )),
        }
    }
}

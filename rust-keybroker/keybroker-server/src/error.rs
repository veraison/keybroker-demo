// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Top-level error type for the whole of the key broker service.
#[derive(Error, Debug)]
pub enum Error {
    /// Represents errors resulting from the Veraison API usage (when the keybroker calls out to Veraison to verify attestation tokens).
    #[error(transparent)]
    VeraisonApi(#[from] veraison_apiclient::Error),

    /// Represents errors from the use of the attestation results library. These errors may occur when inspecting attestation
    /// results in order to implement an appraisal policy.
    #[error(transparent)]
    Ear(#[from] ear::Error),

    /// Represents errors in verification that are not API usage errors.
    #[error(transparent)]
    Verification(#[from] VerificationErrorKind),

    /// Represents errors related to RSA encryption or decryption. These can occur when using the RSA algorithm to wrap
    /// key data from the server.
    #[error(transparent)]
    Rsa(#[from] rsa::Error),

    /// Represents an error from the key store, such as an attempt to access a key that does not exist.
    #[error(transparent)]
    KeyStore(#[from] KeyStoreErrorKind),

    /// Represents an error from the challenge manager, such as an attempt to lookup a challenge that was
    /// never allocated.
    #[error(transparent)]
    Challenge(#[from] ChallengeErrorKind),

    /// Represents errors related to base64 decoding, which can occur when processing the various base64 strings
    /// that are transacted through the API between the client and the server, if the client provides faulty data.
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),

    /// Represents errors from the use of the policy evaluation library.
    #[error(transparent)]
    Policy(#[from] anyhow::Error),

    /// Represents errors from the use of the JSON serialisation and deserialisation library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Errors happening within the verification process logic.
#[derive(Error, Debug)]
pub enum VerificationErrorKind {
    /// It was not possible to find the challenge-response newSession endpoint
    #[error("No newChallengeResponseSession endpoint was found on the Veraison server.")]
    NoChallengeResponseEndpoint,
}

/// Errors happening within the key store.
#[derive(Error, Debug)]
pub enum KeyStoreErrorKind {
    /// Attempt to obtain a key that is not in the store.
    #[error("Requested key is not in the store.")]
    KeyNotFound,

    /// The client provided a wrapping key that is not an RSA key.
    #[error("The wrapping key type is not supported. Wrapping key must be an RSA key.")]
    UnsupportedWrappingKeyType,

    /// The client provided a wrapping key whose algorithm was not supported.
    #[error("Thw wrapping key encryption algorithm is not supported.")]
    UnsupportedWrappingKeyAlgorithm,
}

/// Errors related to the management of challenges
#[derive(Error, Debug)]
pub enum ChallengeErrorKind {
    /// Attempt to lookup a challenge with an unknown ID.
    #[error("Reference to a challenge that does not exist.")]
    ChallengeNotFound,
}

pub type Result<T> = std::result::Result<T, Error>;

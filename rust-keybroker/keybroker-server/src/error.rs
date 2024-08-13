// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Top-level error type for the whole of the key broker service.
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    VeraisonApiError(#[from] veraison_apiclient::Error),

    #[error(transparent)]
    EarError(#[from] ear::Error),

    #[error(transparent)]
    VerificationError(#[from] VerificationErrorKind),

    #[error(transparent)]
    RsaError(#[from] rsa::Error),

    #[error(transparent)]
    KeyStoreError(#[from] KeyStoreErrorKind),

    #[error(transparent)]
    ChallengeError(#[from] ChallengeErrorKind),

    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
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

    #[error("The wrapping key type is not supported. Wrapping key must be an RSA key.")]
    UnsupportedWrappingKeyType,

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

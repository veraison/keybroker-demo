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
}

/// Errors happening within the verification process logic.
#[derive(Error, Debug)]
pub enum VerificationErrorKind {
    /// It was not possible to find the challenge-response newSession endpoint
    #[error("No newChallengeResponseSession endpoint was found on the Veraison server.")]
    NoChallengeResponseEndpoint,
}

pub type Result<T> = std::result::Result<T, Error>;

// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Top-level error type for a keybroker client.
#[derive(Error, Debug)]
pub enum Error {
    /// Represents genuine attestation failures.
    #[error("Attestation failure: {0} ({1})")]
    AttestationFailure(String, String),
    /// Represents all kind of runtime errors that can be faced by a client, like a bogus HTTP connection for example.
    #[error(transparent)]
    RuntimeError(#[from] RuntimeErrorKind),
}

/// Enumeration holding the different kind of runtime errors (in contrast to genuine
/// attestation failure) that a client can get.
#[derive(Error, Debug)]
pub enum RuntimeErrorKind {
    /// Can not connect to the keybroker server.
    #[error("HTTP connection to {0} failed with error: {1}")]
    HTTPConnect(String, String),

    /// Unexpected response from the keybroker server.
    #[error("Unhandled HTTP response: {0}")]
    HTTPResponse(String),

    /// Represents errors due to base64 decoding.
    #[error("Failed to base64-decode {0} with error: {1}")]
    Base64Decode(String, String),

    /// Represents errors due to base64 decoding.
    #[error("Failed to JSON-deserialize {0} with error: {1}")]
    JSONDeserialize(String, String),

    /// Represents errors related to TSM report generation.
    #[error(transparent)]
    TSMReport(#[from] tsm_report::TsmReportError),

    /// Represents errors in the key decryption.
    #[error("Failed to decrypt {0} with error: {1}")]
    Decrypt(String, String),

    /// Represents errors in the retrieval of the challenge from the keybroker server.
    #[error("Challenge retrieval error: {0}")]
    ChallengeRetrieval(String),

    /// Represents the error when the challenge has an incorrect number of bytes.
    #[error("Challenge length error, expecting {0} but got {1} instead")]
    ChallengeLength(usize, usize),

    /// Represents error that occured when attempting to generate the evidence.
    #[error("Evidence generation error: {0}")]
    EvidenceGeneration(String),

    /// Used when the response from the keybroker is missing the location field.
    #[error("Missing location field in HTTP requets")]
    MissingLocation,
}

pub type Result<T> = std::result::Result<T, Error>;

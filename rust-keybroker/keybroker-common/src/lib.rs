// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

//! This library provides the common data types that are defined in the OpenAPI schema for the keybroker,
//! along with the serialization functionality that allows them to be transacted over HTTP. The small collection
//! of data types in this library are consumed by both the server and the client.

/// Represents a single attestation challenge (nonce).
///
/// Challenges are formed in response to a key access request. The purpose of the key broker is to provide
/// keys (secret strings) in exchange for a verifiable attestation token. In order to produce an attestation
/// token, the client must first be given the challenge value (commonly called a "nonce"). This structure
/// provides the nonce along with a vector of permissible evidence content types that the server will
/// accept.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AttestationChallenge {
    /// Base64 encoding of the challenge value (nonce). The client must incorporate this challenge value
    /// into its attestation token/evidence, according to the conventions of the evidence bundle being
    /// formed.
    pub challenge: String,

    /// List of acceptable evidence media types, such as "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0".
    pub accept: Vec<EvidenceContentType>,
}

/// A request to access a key or secret string according to the "background check" interaction pattern
/// for attestation.
///
/// The identity of the key being accessed is not part of this structure, because it is implicit in the path
/// of the API request to access a key.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BackgroundCheckKeyRequest {
    /// The public part of the wrapping key pair that the client has specified for encryption of the key/secret
    /// in transit. The keybroker server uses this public key to wrap (encrypt) the data before returning
    /// it to the client. This is in order for confidentiality to be maintained without relying solely on TLS
    /// between the client and the server.
    pub pubkey: PublicWrappingKey,
}

/// Represents an error occurring within the API usage.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ErrorInformation {
    /// Formal type string for the error.
    pub r#type: String,

    /// Human-readable error details, giving more information about the error.
    pub detail: String,
}

pub type EvidenceBytes = String;

pub type EvidenceContentType = String;

/// The public portion of a wrapping key pair used to protect keys/secrets in transit between the client and
/// the server.
///
/// Wrapping keys are used so that confidentiality of the brokered data is maintained without relying solely
/// on TLS between the client and the server.
///
/// Only the client (within its confidential compute environment) has the private part of the key pair, with
/// which it can decrypt and use the data from the server.
///
/// Only RSA keys are currently supported for wrapping.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublicWrappingKey {
    /// Public key type. This must be "RSA".
    pub kty: String,

    /// Encryption algorithm. This must be either "RSA1_5" or "OAEP".
    pub alg: String,

    /// Base64 encoding of the public key modulus.
    pub n: String,

    /// Base64 encoding of the public key exponent.
    pub e: String,
}

/// Wrapped/encrypted secret data returned from the server in the case of a successfully-verified attestation.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WrappedKeyData {
    /// Base64 encoding of encrypted data. The client should Base64-decode this string, and then RSA decrypt the
    /// resulting vector of bytes in order to obtain the secret data payload.
    pub data: String,
}

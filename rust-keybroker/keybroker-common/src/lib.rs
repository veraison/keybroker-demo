// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]

pub struct AttestationChallenge {
    pub challenge: String,
    pub accept: Vec<EvidenceContentType>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]

pub struct BackgroundCheckKeyRequest {
    pub pubkey: PublicWrappingKey,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]

pub struct ErrorInformation {
    pub r#type: String,
    pub detail: String,
}

pub type EvidenceBytes = String;

pub type EvidenceContentType = String;

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]

pub struct PublicWrappingKey {
    pub kty: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]

pub struct WrappedKeyData {
    pub data: String,
}

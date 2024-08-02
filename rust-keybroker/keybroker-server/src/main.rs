// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{get, http, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::prelude::*;
use keybroker_common::{
    AttestationChallenge, BackgroundCheckKeyRequest, ErrorInformation, WrappedKeyData,
};

mod error;
mod verifier;

// This is the challenge value from from https://git.trustedfirmware.org/TF-M/tf-m-tools/+/refs/heads/main/iat-verifier/tests/data/cca_example_token.cbor
const CCA_EXAMPLE_TOKEN_NONCE: &'static [u8] = &[
    0x6e, 0x86, 0xd6, 0xd9, 0x7c, 0xc7, 0x13, 0xbc, 0x6d, 0xd4, 0x3d, 0xbc, 0xe4, 0x91, 0xa6, 0xb4,
    0x03, 0x11, 0xc0, 0x27, 0xa8, 0xbf, 0x85, 0xa3, 0x9d, 0xa6, 0x3e, 0x9c, 0xe4, 0x4c, 0x13, 0x2a,
    0x8a, 0x11, 0x9d, 0x29, 0x6f, 0xae, 0x6a, 0x69, 0x99, 0xe9, 0xbf, 0x3e, 0x44, 0x71, 0xb0, 0xce,
    0x01, 0x24, 0x5d, 0x88, 0x94, 0x24, 0xc3, 0x1e, 0x89, 0x79, 0x3b, 0x3b, 0x1d, 0x6b, 0x15, 0x04,
];

#[post("/key/{keyid}")]
async fn request_key(
    path: web::Path<String>,
    key_request: web::Json<BackgroundCheckKeyRequest>,
) -> impl Responder {
    let key_id = path.into_inner();

    // TODO: Mock implementation for now
    let attestation_challenge = AttestationChallenge {
        challenge: BASE64_STANDARD.encode(CCA_EXAMPLE_TOKEN_NONCE),
        accept: vec![
            "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0".to_string(),
        ],
    };

    HttpResponse::Created().json(attestation_challenge)
}

#[post("/evidence/{challengeid}")]
async fn submit_evidence(
    path: web::Path<String>,
    request: HttpRequest,
    evidence_base64: String,
) -> impl Responder {
    let challenge_id = path.into_inner();
    let default_content_type = http::header::HeaderValue::from_static("application/string");

    let content_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .unwrap_or(&default_content_type);

    let evidence_bytes = BASE64_STANDARD.decode(evidence_base64).unwrap(); // TODO: Error handling needed here in case of faulty base64 input

    /*

    (verification not working yet)

    // TODO: Allow the veraison endpoint to be configurable. Currently using the Linaro-provided instance for emulated platforms.
    // TODO: Use the media content type from the request's Content-Type header - currently not doing that because actix_web doesn't like the CCA media type
    // TODO: Use of hard-coded nonce here - temporary until we have proper sessions based on the key request
    let verified = verifier::verify_with_veraison_instance(
        "http://veraison.test.linaro.org:8080",
        "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0",
        CCA_EXAMPLE_TOKEN_NONCE,
        &evidence_bytes,
    );
    */

    let verified = true;

    // Switch on whether the evidence was successfully verified or not.
    if verified {
        // TODO: The attestation is valid - so wrap a key out of the key store here. Currently returning a dummy response that is not encrypted at all.
        let wrapped_key = WrappedKeyData {
            data: "May the force be with you".to_string(),
        };

        HttpResponse::Ok().json(wrapped_key)
    } else {
        let error_info = ErrorInformation {
            r#type: "AttestationFailure".to_string(),
            detail: "The attestation failed.".to_string(),
        };

        HttpResponse::Forbidden().json(error_info)
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let scope = web::scope("/keys/v1")
            .service(request_key)
            .service(submit_evidence);
        App::new().service(scope)
    })
    .bind(("127.0.0.1", 8088))?
    .run()
    .await
}

// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use actix_web::{http, post, rt::task, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::*;
use challenge::Challenger;
use clap::Parser;
use keybroker_common::{AttestationChallenge, BackgroundCheckKeyRequest, ErrorInformation};
use keystore::KeyStore;
mod challenge;
mod error;
mod keystore;
mod verifier;

#[post("/key/{keyid}")]
async fn request_key(
    path: web::Path<String>,
    data: web::Data<ServerState>,
    key_request: web::Json<BackgroundCheckKeyRequest>,
) -> impl Responder {
    let key_id = path.into_inner();

    // Get a new challenge from the challenger.
    let mut challenger = data.challenger.lock().expect("Poisoned challenger lock.");
    let challenge = challenger.create_challenge(&key_id, &key_request.pubkey);

    // TODO: The "accept" list is being hardcoded for Arm CCA here - it should come from the verifier.
    let attestation_challenge = AttestationChallenge {
        challenge: URL_SAFE_NO_PAD.encode(&challenge.challenge_value),
        accept: vec![
            "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0".to_string(),
        ],
    };

    let location = format!(
        "{}:{}/keys/v1/evidence/{}",
        data.args.baseurl, data.args.port, challenge.challenge_id
    );

    // TODO: Remove this println - tracer message for dev purposes only.
    println!("Created attestation challenge at {}", location);

    HttpResponse::Created()
        .append_header((http::header::LOCATION, location))
        .json(attestation_challenge)
}

#[post("/evidence/{challengeid}")]
async fn submit_evidence(
    path: web::Path<u32>,
    data: web::Data<ServerState>,
    request: HttpRequest,
    evidence_base64: String,
) -> impl Responder {
    let challenge_id = path.into_inner();
    let default_content_type = http::header::HeaderValue::from_static("application/string");

    let mut challenger = data.challenger.lock().expect("Poisoned challenger lock.");
    let challenge = challenger.get_challenge(challenge_id);

    if challenge.is_err() {
        let error_info = ErrorInformation {
            r#type: "AttestationFailure".to_string(),
            detail: "The challenge identifier did not match any issued challenge.".to_string(),
        };

        return HttpResponse::Forbidden().json(error_info);
    }

    // This unwrap is now safe because we did the error check above.
    let challenge = challenge.unwrap();

    // Once the evidence is submitted, delete the challenge. It can't be used again.
    challenger.delete_challenge(challenge_id).unwrap();

    // TODO: We are currently ignoring the content type from the request and assuming a CCA eat-collection.
    let _content_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .unwrap_or(&default_content_type);

    let evidence_bytes = URL_SAFE_NO_PAD.decode(evidence_base64).unwrap(); // TODO: Error handling needed here in case of faulty base64 input

    let verifier_base = data.args.verifier.clone();

    // We are in an async context, but the verifier client is synchronous, so spawn
    // it as a blocking task.
    let handle = task::spawn_blocking(move || {
        // TODO: Use the media content type from the request's Content-Type header - currently not doing that because actix_web doesn't like the CCA media type
        verifier::verify_with_veraison_instance(
            &verifier_base,
            "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0",
            &challenge.challenge_value,
            &evidence_bytes,
        )
    });
    let result = handle.await.unwrap();

    match result {
        Ok(verified) => {
            // Switch on whether the evidence was successfully verified or not.
            if verified {
                let keystore = data.keystore.lock().expect("Poisoned keystore lock.");
                let data = keystore.wrap_key(&challenge.key_id, &challenge.wrapping_key);

                // TODO: Error checks - can't just unwrap here
                let wrapped_key = data.unwrap();

                HttpResponse::Ok().json(wrapped_key)
            } else {
                let error_info = ErrorInformation {
                    r#type: "AttestationFailure".to_string(),
                    detail: "The attestation result is not in policy..".to_string(),
                };

                HttpResponse::Forbidden().json(error_info)
            }
        }
        Err(_) => {
            let error_info = ErrorInformation {
                r#type: "AttestationFailure".to_string(),
                detail: "No attestation result was obtained..".to_string(),
            };

            HttpResponse::Forbidden().json(error_info)
        }
    }
}

/// Structure for parsing and storing the command-line arguments
#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The port on which the web server will listen
    #[arg(short, long, default_value_t = 8088)]
    port: u16,

    #[arg(short, long, default_value = "http://127.0.0.1")]
    baseurl: String,

    #[arg(short, long, default_value = "http://veraison.test.linaro.org:8080")]
    verifier: String,
}

struct ServerState {
    args: Args,
    keystore: Mutex<KeyStore>,
    challenger: Mutex<Challenger>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let mut keystore = KeyStore::new();
    let challenger = Challenger::new();

    // TODO: Just storing one hard-coded item in the store. Would be better to read from an input file.
    keystore.store_key(
        &"skywalker".to_string(),
        "May the force be with you.".as_bytes().to_vec(),
    );

    let server_state = ServerState {
        args: args.clone(),
        keystore: Mutex::new(keystore),
        challenger: Mutex::new(challenger),
    };

    let app_data = web::Data::new(server_state);

    HttpServer::new(move || {
        let scope = web::scope("/keys/v1")
            .service(request_key)
            .service(submit_evidence);
        App::new().app_data(app_data.clone()).service(scope)
    })
    .bind(("127.0.0.1", args.port))?
    .run()
    .await
}

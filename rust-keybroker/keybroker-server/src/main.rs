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
pub mod policy;
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
    let challenge =
        challenger.create_challenge(&key_id, &key_request.pubkey, data.args.mock_challenge);

    // TODO: The "accept" list is being hardcoded for Arm CCA here - it should come from the verifier.
    let attestation_challenge = AttestationChallenge {
        challenge: URL_SAFE_NO_PAD.encode(&challenge.challenge_value),
        accept: vec![
            "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0".to_string(),
        ],
    };

    let location = format!(
        "{}/keys/v1/evidence/{}",
        data.endpoint, challenge.challenge_id
    );

    log::info!("Created attestation challenge at {}", location);

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
    let default_content_type = http::header::HeaderValue::from_static("text/plain");

    let challenge = {
        let mut challenger = data.challenger.lock().expect("Poisoned challenger lock.");
        let challenge = challenger.get_challenge(challenge_id);

        if challenge.is_err() {
            let error_info = ErrorInformation {
                r#type: "AttestationFailure".to_string(),
                detail: "The challenge identifier did not match any issued challenge.".to_string(),
            };

            return HttpResponse::Forbidden().json(error_info);
        }

        // Once the evidence is submitted, delete the challenge. It can't be used again.
        challenger.delete_challenge(challenge_id).unwrap();

        // This unwrap is now safe because we did the error check above.
        challenge.unwrap()
    };

    let content_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .unwrap_or(&default_content_type)
        .clone();

    let evidence_bytes = URL_SAFE_NO_PAD.decode(evidence_base64).unwrap(); // TODO: Error handling needed here in case of faulty base64 input

    let verifier_base = data.args.verifier.clone();

    let reference_values = data.args.reference_values.clone();

    // We are in an async context, but the verifier client is synchronous, so spawn
    // it as a blocking task.
    let handle = task::spawn_blocking(move || {
        // TODO: In theory, this unwrap() could fail and panic if there are non-printing characters in the content type header.
        let content_type_str = content_type.to_str().unwrap();

        // TODO: Blind pass-through of content type here. Ideally we should do a friendly check against the set that Veraison supports.
        verifier::verify_with_veraison_instance(
            &verifier_base,
            content_type_str,
            &challenge.challenge_value,
            &evidence_bytes,
            &reference_values,
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
                    detail: "The attestation result is not in policy.".to_string(),
                };

                HttpResponse::Forbidden().json(error_info)
            }
        }
        Err(_) => {
            let error_info = ErrorInformation {
                r#type: "AttestationFailure".to_string(),
                detail: "No attestation result was obtained.".to_string(),
            };

            HttpResponse::Forbidden().json(error_info)
        }
    }
}

/// Structure for parsing and storing the command-line arguments
#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The interface on which this server will listen (use 0.0.0.0 to listen on all interfaces)
    #[arg(short, long, default_value = "127.0.0.1")]
    addr: String,

    /// The port on which this server will listen
    #[arg(short, long, default_value_t = 8088)]
    port: u16,

    /// The address at which this server can be reached to request a key or submit an evidence.
    /// It will be set by default to 'http://{addr}', but this value can be overridden with
    /// an FQDN for {addr} in order to use name resolution for example.
    /// The port number will be appended, so don't leave a trailing '/' to the FQDN.
    #[arg(short, long, default_value = None)]
    endpoint: Option<String>,

    /// The URL where the verifier can be reached
    #[arg(long, default_value = "http://veraison.test.linaro.org:8080")]
    verifier: String,

    /// Use the static CCA example token nonce instead of a randomly generated one
    #[arg(short, long, default_value_t = false)]
    mock_challenge: bool,

    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Silence all output
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// File containing a JSON array with base64-encoded known-good RIM values
    #[arg(long, default_value = "reference-values.json")]
    reference_values: String,
}

struct ServerState {
    args: Args,
    endpoint: String,
    keystore: Mutex<KeyStore>,
    challenger: Mutex<Challenger>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    stderrlog::new()
        .quiet(args.quiet)
        .verbosity(1 + usize::from(args.verbosity))
        .init()
        .unwrap();

    let mut keystore = KeyStore::new();
    let challenger = Challenger::new();

    // TODO: Just storing one hard-coded item in the store. Would be better to read from an input file.
    keystore.store_key(
        "skywalker",
        "May the force be with you.".as_bytes().to_vec(),
    );

    let server_state = ServerState {
        args: args.clone(),
        endpoint: match args.endpoint {
            Some(url) => format!("{}:{}", url, args.port),
            None => format!("http://{}:{}", args.addr, args.port),
        },
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
    .bind((args.addr, args.port))?
    .run()
    .await
}

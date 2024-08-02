// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use ear::{Algorithm, Ear, TrustTier};
use veraison_apiclient::*;

pub fn verify_with_veraison_instance(
    verifier_base_url: &str,
    media_type: &str,
    challenge: &[u8],
    evidence: &[u8],
) -> bool {
    // Get the discovery URL from the base URL
    let discovery = Discovery::from_base_url(String::from(verifier_base_url))
        .expect("Failed to start API discovery with the service.");

    // Quiz the discovery endpoint for the verification endpoint
    let verification_api = discovery
        .get_verification_api()
        .expect("Failed to discover the verification endpoint details.");

    // Get the challenge-response endpoint from the verification endpoint
    let relative_endpoint = verification_api
        .get_api_endpoint("newChallengeResponseSession")
        .expect("Could not locate a newChallengeResponseSession endpoint.");

    let api_endpoint = format!("{}{}", verifier_base_url, relative_endpoint);

    // create a ChallengeResponse object
    let cr = ChallengeResponseBuilder::new()
        .with_new_session_url(api_endpoint)
        .build()
        .unwrap();

    let nonce = Nonce::Value(challenge.to_vec());

    let (session_url, _session) = cr.new_session(&nonce).unwrap();

    // Run the challenge-response session
    let ear_string = cr
        .challenge_response(evidence, media_type, &session_url)
        .unwrap();

    // EARs are signed by Veraison. The public verification key is conveyed within the
    // endpoint descriptor that we pulled from the discovery API before. We can grab this
    // as a JSON string, which will allow us to start using the rust-ear library to
    // parse and inspect the EAR token.
    let verification_key_string = verification_api.ear_verification_key_as_string();

    // We've finished talking to Veraison at this point. The rest of the code is concerned with
    // locally inspecting the EAR. We now start using the rust-ear library
    // from https://github.com/veraison/rust-ear
    // We start by getting the Ear structure from the JWT, which also does a signature
    // check.
    let ear =
        Ear::from_jwt_jwk(&ear_string, Algorithm::ES256, verification_key_string.as_bytes()).unwrap();

    // The simplest possible appraisal policy: accept if we have an AFFIRMING result from
    // every submodule of the token.
    ear.submods.iter().all(|(_module, appraisal)| appraisal.status == TrustTier::Affirming)
}

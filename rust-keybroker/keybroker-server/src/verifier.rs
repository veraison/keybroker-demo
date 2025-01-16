// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result, VerificationErrorKind};
use crate::policy;
use ear::{Algorithm, Ear};
use std::path::PathBuf;
use veraison_apiclient::*;

/// The trait that must be implemented to emit diagnostics for specific flavours of EAR.
pub trait EmitDiagnostic {
    fn emit_no_reference_values(&self, challenge_id: &u32, ear: &Ear) -> Result<()>;
    fn verbosity(&self) -> u8;
}

/// Provide diagnostics for the CCA flavour of EAR.
pub struct CcaDiagnostics {
    verbosity: u8,
}

impl CcaDiagnostics {
    pub fn new(verbosity: u8) -> Self {
        Self { verbosity }
    }
}

impl EmitDiagnostic for CcaDiagnostics {
    fn emit_no_reference_values(&self, challenge_id: &u32, ear: &Ear) -> Result<()> {
        match ear.submods.get("CCA_REALM") {
            None => Err(Error::Verification(VerificationErrorKind::EARCCAError(
                "No CCA_REALM in the ear".to_string(),
            ))),
            Some(cca_realm) => {
                if cca_realm.status == ear::TrustTier::Warning {
                    match cca_realm
                    .annotated_evidence
                    .get("cca-realm-initial-measurement") {
                        None => return Err(Error::Verification(
                            VerificationErrorKind::EARCCAError("No cca-realm-initial-measurement in the CCA_REALM annotated evidence claims".to_string())
                        )),
                    Some(rim) =>
                    {
                        log::info!("Known-good RIM values are missing. If you trust the client that submitted\n\
                            evidence for challenge {}, you should restart the keybroker-server with the following\n\
                            command-line option to populate it with known-good RIM values:\n\
                              --reference-values <(echo '{{ \"reference-values\": [ {} ] }}')",
                            challenge_id, serde_json::to_string(&rim)?);
                        return Ok(())
                    },
                }
                };
                Ok(())
            }
        }
    }

    fn verbosity(&self) -> u8 {
        self.verbosity
    }
}

pub struct Verifier {
    pub base_url: String,
    pub root_certificate: Option<PathBuf>,
}

pub async fn verify_with_veraison_instance<DE: EmitDiagnostic>(
    verifier: &Verifier,
    media_type: &str,
    challenge_id: &u32,
    challenge: &[u8],
    evidence: &[u8],
    reference_values: &Option<String>,
    diagnostics: &DE,
) -> Result<bool> {
    // Get the discovery endpoint.
    let mut discovery = DiscoveryBuilder::new().with_base_url(verifier.base_url.clone());

    if verifier.root_certificate.is_some() {
        discovery = discovery.with_root_certificate(verifier.root_certificate.clone().unwrap());
    }

    let discovery_endpoint = discovery.build()?;

    // Quiz the discovery endpoint for the verification endpoint
    let verification_api = discovery_endpoint.get_verification_api().await?;

    // Get the challenge-response endpoint from the verification endpoint
    let relative_endpoint = verification_api.get_api_endpoint("newChallengeResponseSession");

    if relative_endpoint.is_none() {
        return Err(Error::Verification(
            VerificationErrorKind::NoChallengeResponseEndpoint,
        ));
    }

    // Can't panic now
    let relative_endpoint = relative_endpoint.unwrap();

    let api_endpoint = format!("{}{}", verifier.base_url, relative_endpoint);

    // create a ChallengeResponse object.
    let mut crb = ChallengeResponseBuilder::new().with_new_session_url(api_endpoint);

    if verifier.root_certificate.is_some() {
        crb = crb.with_root_certificate(verifier.root_certificate.clone().unwrap());
    }

    let cr = crb.build()?;

    let nonce = Nonce::Value(challenge.to_vec());

    let (session_url, _session) = cr.new_session(&nonce).await?;

    // Run the challenge-response session
    let ear_string = cr
        .challenge_response(evidence, media_type, &session_url)
        .await?;

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
    let ear = Ear::from_jwt_jwk(
        &ear_string,
        Algorithm::ES256,
        verification_key_string.as_bytes(),
    )?;

    if diagnostics.verbosity() > 0 {
        let mut ear_log = format!("EAR profiles: {}\n", ear.profile);

        // Walk the sub-modules and log their appraisal status
        for (module, appraisal) in ear.submods.iter() {
            ear_log.push_str(format!("Appraisal for submod {}:\n", module).as_str());
            ear_log.push_str(format!("    Status: {:?}\n", appraisal.status).as_str());
            ear_log.push_str("    Annotated Evidence:\n");
            for (ek, ev) in appraisal.annotated_evidence.iter() {
                ear_log.push_str(format!("        {}: {:?}\n", ek, ev).as_str());
            }
            ear_log.push_str("    Policy Claims:\n");
            for (pk, pv) in appraisal.policy_claims.iter() {
                ear_log.push_str(format!("        {}: {:?}\n", pk, pv).as_str());
            }
        }

        log::info!("{}", ear_log);
    }

    let ear_claims = serde_json::to_string(&ear)?;

    let (policy, policy_rule) = policy::MEDIATYPES_TO_POLICY
        .get(media_type)
        .ok_or(VerificationErrorKind::PolicyNotFound)?;

    // Ensure we have known-good reference values. If not, provide a useful and actionnable
    // diagnostic to the user.
    if reference_values.is_none() {
        diagnostics.emit_no_reference_values(challenge_id, &ear)?;
        return Err(Error::Verification(
            VerificationErrorKind::NoReferenceValues,
        ));
    }

    // Appraise the received EAR using the embedded policy (see ./policy.rego)
    // unless a custom one has been provided on the command line.  The default
    // policy also wants to match the RIM value reported by the CCA token with
    // the known-good reference values supplied on the command line.
    let results = policy::rego_eval(
        policy,
        policy_rule,
        reference_values.as_ref().unwrap(),
        &ear_claims,
    )?;

    Ok(results.to_string() == "true")
}

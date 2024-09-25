// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use regorus::{self, Value};

use crate::error::Result;

// Evaluate an EAR claims-set against the appraisal policy and known-good RIM values
pub(crate) fn rego_eval(
    custom_policy: Option<String>,
    rims: &str,
    ear_claims: &str,
) -> Result<Value> {
    const POLICY: &str = include_str!("policy.rego");

    // Create engine.
    let mut engine = regorus::Engine::new();

    engine.set_rego_v1(true);
    engine.set_strict_builtin_errors(false);

    // Add the appraisal policy
    match custom_policy {
        None => {
            engine.add_policy(String::from("policy.rego"), String::from(POLICY))?;
        }
        Some(file) => {
            engine.add_policy_from_file(file)?;
        }
    }

    // Load the configured known good RIM values
    engine.add_data(Value::from_json_file(rims)?)?;

    // Set the EAR claims-set to be appraised
    engine.set_input(Value::from_json_str(ear_claims)?);

    let results = engine.eval_rule("data.arm_cca.allow".to_string())?;

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rego_eval_ear_default_policy_ok() {
        let ear_claims = include_str!("../../../testdata/ear-claims-ok.json");
        let rims = stringify_testdata_path("rims-matching.json");

        let results = rego_eval(None, &rims, ear_claims).expect("successful eval");

        assert_eq!(results.to_string(), "true");
    }

    #[test]
    fn rego_eval_default_policy_unmatched_rim() {
        let ear_claims = include_str!("../../../testdata/ear-claims-ok.json");
        let rims = stringify_testdata_path("rims-not-matching.json");

        let results = rego_eval(None, &rims, ear_claims).expect("successful eval");

        assert_eq!(results.to_string(), "false");
    }

    fn stringify_testdata_path(s: &str) -> String {
        let mut test_data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        test_data.push("../../testdata");
        test_data.push(s);

        test_data.into_os_string().into_string().unwrap()
    }
}

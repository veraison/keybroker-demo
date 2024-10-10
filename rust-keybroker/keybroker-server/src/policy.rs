// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;
use phf::{phf_map, Map};
use regorus::{self, Value};

pub static MEDIATYPES_TO_POLICY: Map<&'static str, (&'static str, &'static str)> = phf_map! {
    r#"application/eat-collection; profile="http://arm.com/CCA-SSD/1.0.0""# => ( include_str!("arm-cca.rego"), "data.arm_cca.allow" ),
    // Other, future mappings
};

// Evaluate an EAR claims-set against the appraisal policy and known-good reference values
pub(crate) fn rego_eval(
    policy: &str,
    policy_rule: &str,
    reference_values: &str,
    ear_claims: &str,
) -> Result<Value> {
    // Create engine.
    let mut engine = regorus::Engine::new();

    engine.set_rego_v1(true);
    engine.set_strict_builtin_errors(false);

    // Add the appraisal policy
    engine.add_policy(String::from("policy.rego"), String::from(policy))?;

    // Load the configured known-good reference values
    engine.add_data(Value::from_json_file(reference_values)?)?;

    // Set the EAR claims-set to be appraised
    engine.set_input(Value::from_json_str(ear_claims)?);

    let results = engine.eval_rule(policy_rule.to_string())?;

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rego_eval_ear_default_policy_ok() {
        let ear_claims = include_str!("../../../testdata/ear-claims-ok.json");
        let reference_values = stringify_testdata_path("rims-matching.json");

        let results = rego_eval(
            include_str!("arm-cca.rego"),
            "data.arm_cca.allow",
            &reference_values,
            ear_claims,
        )
        .expect("successful eval");

        assert_eq!(results.to_string(), "true");
    }

    #[test]
    fn rego_eval_default_policy_unmatched_rim() {
        let ear_claims = include_str!("../../../testdata/ear-claims-ok.json");
        let reference_values = stringify_testdata_path("rims-not-matching.json");

        let results = rego_eval(
            include_str!("arm-cca.rego"),
            "data.arm_cca.allow",
            &reference_values,
            ear_claims,
        )
        .expect("successful eval");

        assert_eq!(results.to_string(), "false");
    }

    fn stringify_testdata_path(s: &str) -> String {
        let mut test_data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        test_data.push("../../testdata");
        test_data.push(s);

        test_data.into_os_string().into_string().unwrap()
    }
}

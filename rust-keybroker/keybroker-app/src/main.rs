// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use keybroker_client::error::Error as KeybrokerError;
use keybroker_client::{CcaExampleToken, KeyBrokerClient, TsmAttestationReport};
use std::process;

/// Structure for parsing and storing the command-line arguments
#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The address this client should connect to to request a key.
    #[arg(short, long, default_value = "http://127.0.0.1:8088")]
    endpoint: String,

    /// Use a CCA example token (instead of the TSM report)
    #[arg(short, long, default_value_t = false)]
    mock_evidence: bool,

    /// Set the application verbosity
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// The key name to use
    key_name: String,
}

fn main() {
    let args = Args::parse();

    let client = KeyBrokerClient::new(&args.endpoint, args.verbose);

    let attestation_result = if args.mock_evidence {
        client.get_key(&args.key_name, &CcaExampleToken {})
    } else {
        client.get_key(&args.key_name, &TsmAttestationReport {})
    };

    // If the attestation was successful, print the key we got from the keybroker and exit with code 0.
    // If the attestation failed for genuine attestation related error, print the reason and exit with code 1.
    // For any other kind of error (crypto, network connectivity, ...), print an hopefully useful message to diagnose the issue and exit with code 2.
    let code = match attestation_result {
        Ok(key) => {
            let plainstring_key = String::from_utf8(key).unwrap();
            println!("Attestation success :-) ! The key returned from the keybroker is '{plainstring_key}'");
            0
        }

        Err(error) => {
            if let KeybrokerError::AttestationFailure(reason, details) = error {
                println!("Attestation failure :-( ! {reason}: {details}");
                1
            } else {
                eprintln!("The key request failed with: {error:?}");
                2
            }
        }
    };

    process::exit(code)
}

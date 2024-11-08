// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::{
    //io::Write,
    path::PathBuf,
    //process::{Command, Stdio},
};

use anyhow::Result;
use c2pa::{settings::load_settings_from_str, Builder, CallbackSigner, SigningAlg};
use clap::Parser;
use ed25519_dalek::{SecretKey, Signer, SigningKey};
use pem::parse;

const CERTS: &[u8] = include_bytes!("fixtures/ed25519.pub");
// this would normally be kept in a secure location such as an HSM
// and the signer might make a remote service call do the signing
const PRIVATE_KEY: &[u8] = include_bytes!("fixtures/ed25519.pem");
const SETTINGS: &str = r#"{ "verify": { "verify_after_sign": "false" } }"#;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the image file
    #[clap()]
    image: PathBuf,

    /// Path to the manifest file (optional)
    #[clap(short, long, env = "MANIFEST")]
    manifest: Option<PathBuf>,

    /// Path to the output file (optional)
    #[clap(short, long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    // We need to clear this to avoid calling a dummy verify function. (will fix this later)
    load_settings_from_str(SETTINGS, "json")?;
    let args = Args::parse();

    let image_path = args.image;
    let manifest_path = args
        .manifest
        .unwrap_or_else(|| "fixtures/manifest.json".into());
    let output_path = args.output.unwrap_or_else(|| "output.jpg".into());

    let manifest_json = std::fs::read_to_string(manifest_path)?;

    let mut source = std::fs::OpenOptions::new().read(true).open(&image_path)?;
    let mut dest = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&output_path)?;

    let format = image_path.extension().unwrap().to_str().unwrap();

    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let mut builder = Builder::from_json(&manifest_json)?;

    // Embed a manifest using the signer.
    let _manifest_bytes = builder.sign(&signer, format, &mut source, &mut dest)?;

    println!("Output written to {:?}", &output_path.display());
    Ok(())
}

/// Sign the given data using an external process.
/// This could be a remote service call or a local process.
/// We do not need to use the `context` parameter in this example.
// fn sign_external(_context: *const (), data: &[u8]) -> c2pa::Result<Vec<u8>> {
//     command_call("target/release/signer", data).map_err(|e| c2pa::Error::OtherError(e.into()))
// }

// /// Call an external executable with the given `stdin` and return the `stdout` as a Result<Vec<u8>>.
// fn command_call(name: &str, stdin: &[u8]) -> Result<Vec<u8>> {
//     let mut child = Command::new(name)
//         .stdin(Stdio::piped())
//         .stdout(Stdio::piped())
//         .stderr(Stdio::piped())
//         .spawn()?;

//     // Write claim bytes to spawned processes' `stdin`.
//     child.stdin.take().unwrap().write_all(stdin)?;
//     let output = child.wait_with_output()?;

//     if !output.status.success() {
//         let err_msg = String::from_utf8(output.stderr).unwrap_or_default();
//         Err(anyhow::anyhow!("{} failed: {}", name, err_msg))
//     } else {
//         Ok(output.stdout)
//     }
// }

fn ed_signer(_context: *const (), data: &[u8]) -> c2pa::Result<Vec<u8>> {
    Ok(ed_sign(data, PRIVATE_KEY).map_err(|e| c2pa::Error::OtherError(e.into()))?)
}

/// Sign the data with the using the Ed25519 private key.
/// The private key is in PEM format, so we need to parse it to get the key bytes.
/// We then create a keypair from the secret and public keys, and sign the data.
/// The signature is returned as a vector of bytes.
pub fn ed_sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    let pem = parse(private_key).unwrap();
    let secret: [u8; 32] = pem.contents()[16..].try_into().unwrap();
    let secret_key = SecretKey::from(secret);
    let signing_key = SigningKey::from(secret_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

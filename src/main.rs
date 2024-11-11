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

use std::{path::PathBuf, process::Command};

use anyhow::Result;
use c2pa::{settings::load_settings_from_str, Builder, CallbackSigner, SigningAlg};
use clap::{Parser, Subcommand};
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
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sign an image
    Sign {
        /// Path to the image file
        #[clap()]
        image: PathBuf,

        /// Path to the manifest file (optional)
        #[clap(short, long, env = "MANIFEST")]
        manifest: Option<PathBuf>,

        /// Path to the output file (optional)
        #[clap(short, long)]
        output: Option<PathBuf>,
    },
    /// Capture an image
    Capture {
        /// Path to the output file
        #[clap(short, long)]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    // We need to clear this to avoid calling a dummy verify function. (will fix this later)
    load_settings_from_str(SETTINGS, "json")?;
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
    //    .set_tsa_url("http://timestamp.digicert.com"); // todo: Figure out why this causes an error

    let args = Args::parse();

    let manifest_def = r#"{
        "claim_generator_info": [
            {
                "name": "CAI Pi Camera",
                "version": "0.1"
            }
        ],
        "assertions": [
            { 
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created"
                        }
                    ]
                }
            },
            {
                "label": "stds.exif",
                "data": {
                    "@context": {
                        "dc": "http://purl.org/dc/elements/1.1/",
                        "exif": "http://ns.adobe.com/exif/1.0/",
                        "exifEX": "http://cipa.jp/exif/2.32/",
                        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                        "tiff": "http://ns.adobe.com/tiff/1.0/",
                        "xmp": "http://ns.adobe.com/xap/1.0/"
                    },
                    "dc:creator": "",
                    "tiff:Make": "Raspberry Pi",
                    "exifEX:PhotographicSensitivity": 6400,
                    "exif:ExposureTime": "1/10",
                    "exif:FNumber": "4.5",
                    "tiff:Model": "Pi Camera v2.1"
                },
                "kind": "Json"
            }
        ]
    }"#;

    match args.command {
        Commands::Sign {
            image,
            manifest,
            output,
        } => {
            let image_path = image;
            let output_path = output.unwrap_or_else(|| "output.jpg".into());

            let manifest_json = match manifest.as_ref() {
                Some(manifest_path) => std::fs::read_to_string(manifest_path)?,
                None => manifest_def.to_string(),
            };

            let mut source = std::fs::OpenOptions::new().read(true).open(&image_path)?;
            let mut dest = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&output_path)?;

            let title = output_path.file_stem().unwrap().to_str().unwrap();
            let format = output_path.extension().unwrap().to_str().unwrap();

            let mut builder = Builder::from_json(&manifest_json)?;
            builder.definition.title = Some(title.to_string());

            // Embed a manifest using the signer.
            let _manifest_bytes = builder.sign(&signer, format, &mut source, &mut dest)?;

            println!("Output written to {:?}", &output_path.display());
        }
        Commands::Capture { output } => {
            let output_path = output;

            // Invoke the command line tool
            let output = Command::new("rpicam-jpeg")
                .arg("-o")
                .arg("temp.jpg")
                .arg("-t")
                .arg("1")
                .arg("-n")
                .output()
                .expect("Failed to execute command");

            if !output.status.success() {
                let err_msg = format!(
                    "Command failed with error: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Err(anyhow::anyhow!(err_msg));
            }

            println!(
                "Command executed successfully: {}",
                String::from_utf8_lossy(&output.stdout)
            );

            let image_path = "temp.jpg";

            let mut source = std::fs::OpenOptions::new().read(true).open(&image_path)?;
            let mut dest = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(&output_path)?;

            let title = output_path.file_stem().unwrap().to_str().unwrap();
            let format = output_path.extension().unwrap().to_str().unwrap();

            let mut builder = Builder::from_json(manifest_def)?;
            builder.definition.title = Some(title.to_string());

            // Embed a manifest using the signer.
            let _manifest_bytes = builder.sign(&signer, format, &mut source, &mut dest)?;

            println!("Captured Jpeg image {:?}", &output_path.display());
        }
    }
    Ok(())
}

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

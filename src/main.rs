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
    io::{Cursor, Write},
    process::{Command, Stdio},
};

use anyhow::Result;
use c2pa::{settings::load_settings_from_str, Builder, CallbackSigner, SigningAlg};

const CERTS: &[u8] = include_bytes!("fixtures/ed25519.pub");
const TSA_URL: &str = "https://freetsa.org/tsr";
const SETTINGS: &str = r#"{ "verify": { "verify_after_sign": "false" } }"#;
const MANIFEST: &str = include_str!("fixtures/manifest.json");
const IMAGE: &[u8] = include_bytes!("fixtures/A.jpg");
const FORMAT: &str = "image/jpeg";
const OUTPUT: &str = "target/output.jpg";

fn main() -> Result<()> {
    // We need to clear this to avoid calling a dummy verify function. (will fix this later)
    load_settings_from_str(SETTINGS, "json")?;

    //let _ed_signer = |data: &[u8]| ed_sign(data, PRIVATE_KEY);
    let signer =
        CallbackSigner::new(sign_external, SigningAlg::Ed25519, CERTS).set_tsa_url(TSA_URL);

    // convert image buffer to cursor with Read/Write/Seek capability
    let mut source = std::io::Cursor::new(IMAGE.to_vec());

    let mut builder = Builder::from_json(MANIFEST)?;

    // Embed a manifest using the signer.
    let mut dest = Cursor::new(Vec::new());
    let _manifest_bytes = builder.sign(&signer, FORMAT, &mut source, &mut dest)?;

    // The image is now signed and has a manifest embedded in it.
    // _manifest_bytes contains the manifest bytes if you need them.

    // In this example we now write the output to a file to see the result.
    dest.set_position(0); // reset the cursor to the beginning
    std::fs::write(OUTPUT, dest.get_ref())?;
    println!("Output written to {OUTPUT}");

    // We can display the resulting manifest for debugging, but it is not validated in this build.
    // It is better to use c2patool to verify the output file.
    // dest.set_position(0);
    // println!("Manifest store: {}", c2pa::Reader::from_stream(FORMAT, &mut dest)?);
    Ok(())
}

/// Sign the given data using an external process.
/// This could be a remote service call or a local process.
/// We do not need to use the `context` parameter in this example.
fn sign_external(_context: *const (), data: &[u8]) -> c2pa::Result<Vec<u8>> {
    command_call("target/release/signer", data).map_err(|e| c2pa::Error::OtherError(e.into()))
}

/// Call an external executable with the given `stdin` and return the `stdout` as a Result<Vec<u8>>.
fn command_call(name: &str, stdin: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Write claim bytes to spawned processes' `stdin`.
    child.stdin.take().unwrap().write_all(stdin)?;
    let output = child.wait_with_output()?;

    if !output.status.success() {
        let err_msg = String::from_utf8(output.stderr).unwrap_or_default();
        Err(anyhow::anyhow!("{} failed: {}", name, err_msg))
    } else {
        Ok(output.stdout)
    }
}

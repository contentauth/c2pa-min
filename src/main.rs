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
use c2pa::{Manifest, SigningAlg};

mod callback_signer;
use callback_signer::create_callback_signer;

const CERTS: &[u8] = include_bytes!("fixtures/ed25519.pub");
const TSA_URL: &str = "https://freetsa.org/tsr";
const IMAGE: &[u8] = include_bytes!("fixtures/A.jpg");
const MANIFEST: &str = include_str!("fixtures/manifest.json");

fn main() -> Result<()>
{
    //let _ed_signer = |data: &[u8]| ed_sign(data, PRIVATE_KEY);
    let signer = create_callback_signer(SigningAlg::Ed25519, CERTS, sign_external, Some(TSA_URL.to_string()))?;

    // convert image buffer to cursor with Read/Write/Seek capability
    let mut stream = std::io::Cursor::new(IMAGE.to_vec());

    let mut manifest = Manifest::from_json(MANIFEST)?; // new("my_app".to_owned());

    // Embed a manifest using the signer.
    let mut output = Cursor::new(Vec::new());
    let _bytes = manifest
        .embed_to_stream("jpeg", &mut stream, &mut output, signer.as_ref())?;

    // The image is now signed and has a manifest embedded in it.

    // Write the output to a file to see the result.
    output.set_position(0);
    std::fs::write("target/output.jpg", output.get_ref())?;

    // Read a manifest store from the output image to prove it worked
    //println!("Manifest store: {}", c2pa::ManifestStore::from_stream("jpeg", &mut output, true).unwrap());
    Ok(())
}


/// Sign the given data using an external process.
/// This could be a remote service call or a local process.
fn sign_external(data: &[u8]) -> c2pa::Result<Vec<u8>> {

    command_call("target/release/signer", data)
        .map_err(|e| c2pa::Error::OtherError(e.into()))
}

/// Call an external executable with the given `stdin` and return the `stdout` as a Result<Vec<u8>>.
fn command_call(name: &str, stdin: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Write claim bytes to spawned processes' `stdin`.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin)?;
    let output = child
        .wait_with_output()?;

    if !output.status.success() {
        let err_msg = String::from_utf8(output.stderr).unwrap_or_default();
        Err(anyhow::anyhow!("{} failed: {}", name, err_msg))
    } else {
        Ok(output.stdout)
    }
}

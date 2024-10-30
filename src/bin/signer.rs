// Copyright 2024 Adobe. All rights reserved.
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

/// A simple program demonstrating how to write an example CLI tool that signs C2PA manifests.
use std::{
    io,
    io::{Read, Write},
};

use ed25519_dalek::{SecretKey, Signer, SigningKey};
use pem::parse;

// The private key is only known by the singer
// this would normally be kept in a secure location such as an HSM
// and the signer might make a remote service call do the signing
const PRIVATE_KEY: &[u8] = include_bytes!("../fixtures/ed25519.pem");

/// This program reads bytes from `stdin`, signs them using the private key, and writes the signed
/// bytes to `stdout`.
fn main() -> io::Result<()> {
    let mut bytes_to_be_signed: Vec<u8> = vec![];
    // 1. Read the bytes to be signed from this process' `stdin`.
    io::stdin().read_to_end(&mut bytes_to_be_signed).unwrap();

    // 2. Sign the bytes using your private key.
    let signed = ed_sign(&bytes_to_be_signed, PRIVATE_KEY)?;

    // 3. Write the signed bytes to `stdout`.
    io::stdout().write_all(&signed)?;

    Ok(())
}

/// Sign the data with the using the Ed25519 private key.
/// The private key is in PEM format, so we need to parse it to get the key bytes.
/// We then create a keypair from the secret and public keys, and sign the data.
/// The signature is returned as a vector of bytes.
pub fn ed_sign(data: &[u8], private_key: &[u8]) -> io::Result<Vec<u8>> {
    let pem = parse(private_key).unwrap();
    let secret: [u8; 32] = pem.contents()[16..].try_into().unwrap();
    let secret_key = SecretKey::from(secret);
    let signing_key = SigningKey::from(secret_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

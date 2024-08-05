# c2pa_min - example to create a small c2pa Rust application

`c2pa_min` shows how to create a minimum sized app for signing only.

We sign with Ed25519 and associated certs without openssl.
The signing here is in a separate signer app, to show how to keep the private keys private.
This does not have the ability to validate.

To build and first build the signer binary and then run the release:

`cargo build --release --bin signer`

`cargo run --release`

The generated executable is `target/release/c2pa_min`

On an arm based Mac the file size is 3.6 MB.

With openssl this example is about 2MB larger and can validate



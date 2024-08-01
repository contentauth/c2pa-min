# C2PA Rust example application

[This repository](https://github.com/contentauth/c2pa-min) is an example of a minimal application using the [C2PA Rust library](https://opensource.contentauthenticity.org/docs/rust-sdk/) that signs assets with Ed25519 public key signature scheme and associated certificates without OpenSSL.

The application uses a separate signer app, to show how to keep the private keys private.
The application not have the ability to validate.

## Building the application

**Prerequisites**: Install [Rust](https://www.rust-lang.org/tools/install).


To build the application, first build the signer binary and then run the release:

```
cargo build --release --bin signer
```

## Running the application

Once you've built the app, run it by entering this command:

```
cargo run --release
```

The generated executable is `target/release/c2pa_min`

On an ARM-based Mac the file size is 3.6 MB.

With OpenSSL, this example is about 2MB larger and can perform validation.



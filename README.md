# Minimal C2PA Rust example application

[This repository](https://github.com/contentauth/c2pa-min) is an example of a minimal application using the 
[C2PA Rust library](https://opensource.contentauthenticity.org/docs/rust-sdk/) that illustrates how to use an external 
signing application and does not require OpenSSL.

The application uses a separate signer app to show how to keep the private keys secure.
It signs assets using the Ed25519 digital signature scheme and can validate with a trust list.

NOTE: The example was built and tested on macOS, and these instructions assume you are using macOS. 

## Overview

The app uses the [new C2PA Rust library API](https://opensource.contentauthenticity.org/docs/rust-sdk/#new-api), which has `Context`, `Settings`, `Builder`, and `Reader` data structures. All the code for the main program is in [`src/main.rs`](https://github.com/contentauth/c2pa-min/blob/main/src/main.rs), which calls out to the standalone singer app defined in [`src/bin/signer.rs`](https://github.com/contentauth/c2pa-min/blob/main/src/bin/signer.rs). 

The main program `sign_external` function calls the signer app. The signer app reads bytes from `stdin`, signs them using a private key, then  writes the signed bytes to `stdout`. The signer app uses a test/development private key and certificate in the `src/fixtures` directory.

All manifest configuration for this example is done through [`src/fixtures/settings.json`](https://github.com/contentauth/c2pa-min/blob/main/src/fixtures/settings.json) rather than the manifest definition passed to the `Builder`, so [`src/fixtures/manifest.json`](https://github.com/contentauth/c2pa-min/blob/main/src/fixtures/manifest.json) is empty and isn't needed for this example. The settings file:

- Configures `builder.claim_generator_info`, sets `builder.intent` to `digitalCapture` so the signed image is identified as a digital capture, and disables the generated thumbnail.
- Supplies a default set of trust anchors and trust config so the embedded certificate chain can be validated against a known trust list.
- Sets `verify.verify_after_sign` to `false` since this example doesn't validate the manifest immediately after signing (see the note on validation above).

## Building the application

**Prerequisites**: Install [Rust](https://www.rust-lang.org/tools/install).

First build the signer binary:

```
cargo build --release --bin signer
```

This commands builds signer binary, `target/release/signer`.  

## Running the application

Build and run the release application with:

```
cargo run --release
```

You'll see messages in the terminal like this:
```
   Compiling c2pa_min v0.2.0 (/path_to_repo/c2pa-min)
    Finished release [optimized] target(s) in 30.45s
     Running `target/release/c2pa_min`
Output written to target/output.jpg
```

The application executable is saved to `target/release/c2pa_min` and on an ARM-based Mac is about 5.2 MB in size.

Note that this size may change with different versions of the SDK.


You can confirm that Content Credentials were added to `target/output.jpg` by using C2PA Tool (with `c2patool target/output.jpg`) or by uploading the image to [Verify](https://contentcredentials.org/verify).








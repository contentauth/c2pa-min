# C2PA Rust example application

[This repository](https://github.com/contentauth/c2pa-min) is an example of a minimal application using the 
[C2PA Rust library](https://opensource.contentauthenticity.org/docs/rust-sdk/) that illustrates how to use an external 
signing application and does not require OpenSSL.

The application uses a separate signer app to show how to keep the private keys secure.
It signs assets using the Ed25519 digital signature scheme, but does not have the ability to 
[validate](https://opensource.contentauthenticity.org/docs/manifest/manifest-validation) manifests, since validation currently requires using OpenSSL.

NOTE: The example was built and tested on macOS, and these instructions assume you are using macOS. 

## Overview

The app uses the [new C2PA Rust library API](https://opensource.contentauthenticity.org/docs/rust-sdk/#new-api) which has `Builder` and `Reader` data structures. All the code for the main program is in [`src/main.rs`](https://github.com/contentauth/c2pa-min/blob/main/src/main.rs), which calls out to the standalone singer app defined in [`src/bin/signer.rs`](https://github.com/contentauth/c2pa-min/blob/main/src/bin/signer.rs). 

The main program `sign_external` function calls the signer app. The signer app reads bytes from `stdin`, signs them using a private key, then  writes the signed bytes to `stdout`. The signer app uses a test/development private key and certificate in the `src/fixtures` directory.

## Building the application

**Prerequisites**: Install [Rust](https://www.rust-lang.org/tools/install).

To build the application, first build the signer binary and then run the release:

```
cargo build --release --bin signer
```

You'll see a number of `Compiling` messages in the terminal, and finally:
```
Finished release [optimized] target(s) in 47.08s
```

This commands builds signer binary, `target/release/signer`.  

The application executable is saved to `target/release/c2pa_min` and on an ARM-based Mac is about 3.6 MB in size. With OpenSSL, this example is about 2MB larger and can perform validation.

## Running the application

Once you've built the app, run it by entering this command:

```
cargo run --release
```

You'll see messages in the terminal like this:
```
   Compiling c2pa_min v0.1.0 (/path_to_repo/c2pa-min)
    Finished release [optimized] target(s) in 30.45s
     Running `target/release/c2pa_min`
Output written to target/output.jpg
```

You can confirm that Content Credentials were added to `target/output.jpg` by using C2PA Tool (with `c2patool target/output.jpg`) or by uploading the image to [Verify](https://contentcredentials.org/verify).








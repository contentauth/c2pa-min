# c2pa_min - example to create a small c2pa Rust application

`c2pa_min` uses no file i/o and optimizes for size. 
We sign with Ed25519 and associated certs without openssl
This does not currently have the ability to validate.

To build and run use:

`cargo run --release`

The generated executable is `target/release/c2pa_min`

On an arm based Mac the file size is 2.3 MB.

With openssl this example is about 2MB larger and can validate



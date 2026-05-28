# rustls-tokio-postgres

[![Crates.io](https://img.shields.io/crates/v/rustls-tokio-postgres.svg)](https://crates.io/crates/rustls-tokio-postgres)
[![Docs.rs](https://docs.rs/rustls-tokio-postgres/badge.svg)](https://docs.rs/rustls-tokio-postgres)
[![License](https://img.shields.io/crates/l/rustls-tokio-postgres.svg)](#license)

A [`tokio_postgres`](https://crates.io/crates/tokio-postgres) TLS connector backed by [`rustls`](https://crates.io/crates/rustls).

## Usage

Prefer a verifying TLS configuration for normal application code. This crate
provides helpers for the OS-native trust store and the Mozilla WebPKI trust
store behind optional features.

### Native roots

Enable the `native-roots` feature to use the operating system's native
certificate store.

```rust
use rustls_tokio_postgres::{config_native_roots, MakeRustlsConnect};
use tokio_postgres::connect;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    static CONFIG: &str = "host=localhost user=postgres";

    let tls = MakeRustlsConnect::new(config_native_roots()?);

    let (_client, _conn) = connect(CONFIG, tls).await?;

    Ok(())
}
```

### WebPKI roots

Enable the `webpki-roots` feature to use the trust anchors from the
`webpki-roots` crate.

```rust
use rustls_tokio_postgres::{config_webpki_roots, MakeRustlsConnect};
use tokio_postgres::connect;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    static CONFIG: &str = "host=localhost user=postgres";

    let tls = MakeRustlsConnect::new(config_webpki_roots());

    let (_client, _conn) = connect(CONFIG, tls).await?;

    Ok(())
}
```

### Dangerous fallback: no certificate verification

`config_no_verify()` is dangerous because it disables server certificate and
hostname verification. TLS still encrypts traffic, but the client no longer
knows whether it is connected to the intended PostgreSQL server, which makes
man-in-the-middle attacks possible.

Use this only for local development, tests, or tightly controlled environments
where server identity is verified by another trusted mechanism. Prefer
`config_native_roots()`, `config_webpki_roots()`, or a custom
`rustls::ClientConfig` with an explicit root store for production systems.

```rust
use rustls_tokio_postgres::{config_no_verify, MakeRustlsConnect};
use tokio_postgres::connect;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    static CONFIG: &str = "host=localhost user=postgres";

    let tls = MakeRustlsConnect::new(config_no_verify());

    let (_client, _conn) = connect(CONFIG, tls).await?;

    Ok(())
}
```

## Features

- **aws-lc-rs**: enables rustls' AWS-LC-RS crypto provider. Enabled by default.
- **channel-binding**: enables TLS channel binding, if supported.
- **fips**: enables rustls' AWS-LC-RS FIPS provider support.
- **logging**: enables rustls logging. Enabled by default.
- **native-roots**: enables a function for creating a `rustls::ClientConfig` using the rustls-native-certs crate.
- **prefer-post-quantum**: enables rustls' post-quantum-preferred AWS-LC-RS key exchange ordering. Enabled by default.
- **ring**: enables rustls' ring crypto provider. Use `default-features = false` if you want ring without AWS-LC-RS.
- **tls12**: enables rustls TLS 1.2 support. Enabled by default.
- **webpki-roots**: enables a function for creating a `rustls::ClientConfig` using the webpki-roots crate.

## License

[Apache-2.0](./LICENSE)

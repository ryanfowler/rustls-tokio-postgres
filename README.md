# rustls-tokio-postgres

[![Crates.io](https://img.shields.io/crates/v/rustls-tokio-postgres.svg)](https://crates.io/crates/rustls-tokio-postgres)
[![Docs.rs](https://docs.rs/rustls-tokio-postgres/badge.svg)](https://docs.rs/rustls-tokio-postgres)
[![License](https://img.shields.io/crates/l/rustls-tokio-postgres.svg)](#license)

A [`tokio_postgres`](https://crates.io/crates/tokio-postgres) TLS connector backed by [`rustls`](https://crates.io/crates/rustls).

## Example

```rust
use rustls_tokio_postgres::{config_no_verify, MakeRustlsConnect};
use tokio_postgres::{connect, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    static CONFIG: &str = "host=localhost user=postgres";

    // This rustls config does not verify the server certificate.
    // You can construct your own rustls ClientConfig, if needed.
    let tls = MakeRustlsConnect::new(config_no_verify());

    // Create the client with the TLS configuration.
    let (_client, _conn) = connect(CONFIG, tls).await?;

    Ok(())
}
```

## Features

- **channel-binding**: enables TLS channel binding, if supported.
- **native-roots**: enables a function for creating a `rustls::ClientConfig` using the rustls-native-certs crate.
- **webpki-roots**: enables a function for creating a `rustls::ClientConfig` using the webpki-roots crate.

## License

[Apache-2.0](./LICENSE)

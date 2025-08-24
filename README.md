# rustls-tokio-postgres

A [`tokio_postgres`](https://crates.io/crates/tokio-postgres) TLS connector backed by [`rustls`](https://crates.io/crates/rustls).

# Example

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

# Features

- **channel-binding**: enables TLS channel binding, if supported.
- **native-roots**: enables a helper function for creating a `rustls::ClientConfig` using the native roots of your OS.
- **webpki-roots**: enables a helper function for creating a `rustls::ClientConfig` using the webpki roots.

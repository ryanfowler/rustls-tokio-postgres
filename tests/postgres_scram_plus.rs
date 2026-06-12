#![cfg(feature = "channel-binding")]

use std::{env, sync::Arc};

use rustls_tokio_postgres::MakeRustlsConnect;

#[tokio::test]
async fn scram_plus_channel_binding_required() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(config) = env::var("PG_SCRAM_PLUS_TEST_CONFIG") else {
        return Ok(());
    };

    if test_crypto_provider().is_none() {
        return Ok(());
    }

    let tls = MakeRustlsConnect::new(rustls_tokio_postgres::config_no_verify());
    let (client, connection) = tokio_postgres::connect(&config, tls).await?;
    let connection = tokio::spawn(connection);

    let row = client
        .query_one(
            "SELECT ssl, version IS NOT NULL AS version_present \
             FROM pg_stat_ssl \
             WHERE pid = pg_backend_pid()",
            &[],
        )
        .await?;
    assert!(row.get::<_, bool>("ssl"));
    assert!(row.get::<_, bool>("version_present"));

    let row = client.query_one("SELECT 1::INT4", &[]).await?;
    assert_eq!(row.get::<_, i32>(0), 1);

    drop(client);
    connection.await??;

    Ok(())
}

#[cfg(feature = "aws-lc-rs")]
fn test_crypto_provider() -> Option<Arc<rustls_tokio_postgres::rustls::crypto::CryptoProvider>> {
    Some(Arc::new(
        rustls_tokio_postgres::rustls::crypto::aws_lc_rs::default_provider(),
    ))
}

#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
fn test_crypto_provider() -> Option<Arc<rustls_tokio_postgres::rustls::crypto::CryptoProvider>> {
    Some(Arc::new(
        rustls_tokio_postgres::rustls::crypto::ring::default_provider(),
    ))
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
fn test_crypto_provider() -> Option<Arc<rustls_tokio_postgres::rustls::crypto::CryptoProvider>> {
    None
}

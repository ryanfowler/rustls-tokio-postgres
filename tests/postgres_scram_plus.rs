#![cfg(feature = "channel-binding")]

use std::env;

use rustls_tokio_postgres::MakeRustlsConnect;

#[tokio::test]
async fn scram_plus_channel_binding_required() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(config) = env::var("PG_SCRAM_PLUS_TEST_CONFIG") else {
        return Ok(());
    };

    install_test_crypto_provider();

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

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
fn install_test_crypto_provider() {
    use std::sync::Once;

    static INSTALL_PROVIDER: Once = Once::new();
    INSTALL_PROVIDER.call_once(|| {
        rustls_tokio_postgres::rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("failed to install rustls crypto provider for tests");
    });
}

#[cfg(not(all(feature = "aws-lc-rs", feature = "ring")))]
fn install_test_crypto_provider() {}

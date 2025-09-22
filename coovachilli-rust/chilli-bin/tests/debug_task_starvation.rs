use axum::{routing::get, Router, extract::State};
use axum_test::TestServer;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
async fn debug_channel_with_minimal_axum() {
    let _ = tracing_subscriber::fmt::try_init();

    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Spawn core loop
    let core = tokio::spawn(async move {
        tracing::info!("Core loop waiting...");
        match rx.recv().await {
            Some(msg) => {
                tracing::info!("Core received: {}", msg);
                msg
            }
            None => {
                tracing::error!("Channel closed!");
                panic!("Channel closed");
            }
        }
    });

    // Create a simple Axum app that sends a message
    let app = Router::new()
        .route("/", get(|State(tx): State<mpsc::Sender<String>>| async move {
            tracing::info!("Handler sending message...");
            tx.send("Hello from Axum".to_string()).await.unwrap();
            "Sent!"
        }))
        .with_state(tx);

    // Run it with TestServer
    let server = TestServer::new(app).unwrap();

    // Make the request that triggers the send
    let response = server.get("/").await;
    response.assert_status_ok();

    // Wait for the core loop to get the message
    let core_result = tokio::time::timeout(Duration::from_secs(2), core)
        .await
        .expect("Test timed out waiting for core task to finish");

    assert!(core_result.is_ok(), "Core task panicked");
    assert_eq!(core_result.unwrap(), "Hello from Axum");
}

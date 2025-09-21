use chilli_core::{Config, SessionManager};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;


async fn spawn_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind random port");
    let addr = listener.local_addr().unwrap();
    let address = format!("http://{}", addr);

    let config = Arc::new(Config::default());
    let session_manager = Arc::new(SessionManager::new());
    let (core_tx, _core_rx) = mpsc::channel(100);

    tokio::spawn(chilli_http::server::run_server(
        listener,
        config,
        core_tx,
        session_manager.clone(),
    ));

    address
}

#[tokio::test]
async fn unauthenticated_status_redirects_to_portal() {
    // Arrange
    let app_address = spawn_app().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Act
    let response = client
        .get(&format!("{}/status", &app_address))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(response.status().as_u16(), 303);
    assert_eq!(response.headers().get("Location").unwrap(), "/portal");
}

#[tokio::test]
async fn portal_returns_login_form() {
    // Arrange
    let app_address = spawn_app().await;
    let client = reqwest::Client::new();

    // Act
    let response = client
        .get(&format!("{}/portal", &app_address))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert_eq!(response.status().as_u16(), 200);
    let html = response.text().await.unwrap();
    assert!(html.contains("<form name=\"login\""));
    assert!(html.contains("Login"));
}

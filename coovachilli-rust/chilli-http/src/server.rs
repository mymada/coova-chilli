use axum::{
    extract::{ConnectInfo, State},
    response::Html,
    routing::{get, post},
    Form, Router,
};
use chilli_core::{AuthRequest, Config};
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_form() -> Html<&'static str> {
    Html(
        r#"
        <!doctype html>
        <html>
            <head>
                <title>Login</title>
            </head>
            <body>
                <h1>Login</h1>
                <form action="/login" method="post">
                    <label for="username">Username:</label><br>
                    <input type="text" id="username" name="username"><br>
                    <label for="password">Password:</label><br>
                    <input type="password" id="password" name="password"><br><br>
                    <input type="submit" value="Submit">
                </form>
            </body>
        </html>
        "#,
    )
}

async fn login(
    State(tx): State<mpsc::Sender<AuthRequest>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> &'static str {
    info!("Login attempt from {} for user '{}'", addr.ip(), form.username);
    if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
        let auth_request = AuthRequest {
            ip: ipv4_addr,
            username: form.username,
            password: form.password,
        };
        if let Err(e) = tx.send(auth_request).await {
            warn!("Failed to send auth request: {}", e);
            return "Login failed: internal server error.";
        }
        "Login request submitted. Please wait."
    } else {
        "Login failed: IPv6 not supported."
    }
}

pub async fn run_server(
    config: &Config,
    auth_tx: mpsc::Sender<AuthRequest>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/", get(login_form))
        .route("/login", post(login))
        .with_state(auth_tx);

    let addr = SocketAddr::new(config.uamlisten.into(), config.uamport);
    info!("UAM server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

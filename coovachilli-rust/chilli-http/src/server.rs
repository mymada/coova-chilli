use axum::{
    extract::{ConnectInfo, Query, State},
    http::Uri,
    response::{Html, Redirect},
    routing::{get, post},
    Form, Router,
};
use chilli_core::{AuthRequest, AuthType, Config, CoreRequest, LogoffRequest, SessionManager};
use md5::{Digest, Md5};
use serde::Deserialize;
use std::net::SocketAddr;
use hex;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    core_tx: mpsc::Sender<CoreRequest>,
    session_manager: Arc<SessionManager>,
    config: Arc<Config>,
}

#[derive(Deserialize)]
struct LoginQuery {
    username: String,
    challenge: String,
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login_form() -> Html<&'static str> {
    Html(
        r#"
        <!doctype html>
        <html>
            <head><title>Login</title></head>
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
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<LoginQuery>,
    Form(form): Form<LoginForm>,
) -> Result<Redirect, Html<String>> {
    info!(
        "Login attempt from {} for user '{}'",
        addr.ip(),
        query.username
    );

    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Err(Html("<h1>Error</h1><p>IPv6 not supported.</p>".to_string())),
    };

    let session = match state.session_manager.get_session(&ip).await {
        Some(s) => s,
        None => return Err(Html("<h1>Login Failed</h1><p>Session not found.</p>".to_string())),
    };

    if hex::encode(session.state.redir.uamchal) != query.challenge {
        return Err(Html("<h1>Login Failed</h1><p>Invalid challenge.</p>".to_string()));
    }

    let hashed_password = match hex::decode(form.password) {
        Ok(p) => p,
        Err(_) => return Err(Html("<h1>Login Failed</h1><p>Invalid password format.</p>".to_string())),
    };

    let mut chap_hasher = Md5::new();
    chap_hasher.update(session.state.redir.uamchal);
    if let Some(secret) = &state.config.uamsecret {
        chap_hasher.update(secret.as_bytes());
    }
    let chap_challenge = chap_hasher.finalize();

    let mut radius_password = Vec::with_capacity(hashed_password.len());
    for (i, byte) in hashed_password.iter().enumerate() {
        radius_password.push(byte ^ chap_challenge[i % 16]);
    }

    let (oneshot_tx, oneshot_rx) = oneshot::channel();
    let auth_request = AuthRequest {
        auth_type: AuthType::UamPap,
        ip,
        username: query.username,
        password: Some(radius_password),
        tx: oneshot_tx,
    };

    if state
        .core_tx
        .send(CoreRequest::Auth(auth_request))
        .await
        .is_err()
    {
        warn!("Failed to send auth request to main task");
        return Err(Html("<h1>Login Failed</h1><p>Internal server error.</p>".to_string()));
    }

    match tokio::time::timeout(tokio::time::Duration::from_secs(10), oneshot_rx).await {
        Ok(Ok(true)) => {
            let user_url = session
                .state
                .redir
                .userurl
                .unwrap_or_else(|| "/status".to_string());
            Ok(Redirect::to(&user_url))
        }
        Ok(Ok(false)) => Err(Html("<h1>Login Failed</h1><p>Invalid credentials.</p>".to_string())),
        _ => Err(Html("<h1>Login Failed</h1><p>Internal server error.</p>".to_string())),
    }
}

async fn status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Html<String>, Redirect> {
    info!("Status request from {}", addr.ip());

    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Ok(Html("<h1>Error</h1><p>IPv6 not supported.</p>".to_string())),
    };

    if let Some(session) = state.session_manager.get_session(&ip).await {
        if session.state.authenticated {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let session_time = now.saturating_sub(session.state.start_time);
            let idle_time = now.saturating_sub(session.state.last_up_time);

            let body = format!(
                r#"
                <!doctype html>
                <html>
                    <head><title>Status</title></head>
                    <body>
                        <h1>Authenticated</h1>
                        <p>Username: {}</p>
                        <p>Session Time: {}s</p>
                        <p>Idle Time: {}s</p>
                        <p>Uploaded: {} bytes</p>
                        <p>Downloaded: {} bytes</p>
                        <form action="/logoff" method="get"><input type="submit" value="Log Off"></form>
                    </body>
                </html>
                "#,
                session.state.redir.username.as_deref().unwrap_or("N/A"),
                session_time,
                idle_time,
                session.state.input_octets,
                session.state.output_octets,
            );
            return Ok(Html(body));
        }
    }

    Err(Redirect::to("/"))
}

async fn logoff(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Redirect, Html<String>> {
    info!("Logoff attempt from {}", addr.ip());

    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Err(Html("<h1>Error</h1><p>IPv6 not supported.</p>".to_string())),
    };

    let (oneshot_tx, oneshot_rx) = oneshot::channel();
    let logoff_request = LogoffRequest { ip, tx: oneshot_tx };

    if state
        .core_tx
        .send(CoreRequest::Logoff(logoff_request))
        .await
        .is_err()
    {
        warn!("Failed to send logoff request to main task");
    } else {
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), oneshot_rx).await;
    }

    Ok(Redirect::to("/"))
}

pub async fn run_server(
    config: Arc<Config>,
    core_tx: mpsc::Sender<CoreRequest>,
    session_manager: Arc<SessionManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app_state = AppState {
        core_tx,
        session_manager,
        config: config.clone(),
    };

    let app = Router::new()
        .route("/", get(login_form))
        .route("/login", post(login))
        .route("/logoff", get(logoff))
        .route("/status", get(status))
        .with_state(app_state);

    let addr = SocketAddr::new(config.uamlisten.into(), config.uamport);
    info!("UAM server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

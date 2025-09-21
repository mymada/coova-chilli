use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use chilli_core::{AuthRequest, AuthType, Config, CoreRequest, LogoffRequest, SessionManager};
use md5::{Digest, Md5};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tera::{Context, Tera};
use tokio::sync::{mpsc, oneshot};
use tower_http::services::ServeDir;
use tracing::{info, warn};

pub static TEMPLATES: Lazy<Tera> = Lazy::new(|| {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let template_path = format!("{}/templates/**/*.html", manifest_dir);
    let mut tera = match Tera::new(&template_path) {
        Ok(t) => t,
        Err(e) => {
            panic!("Tera parsing error(s): {}", e);
        }
    };
    tera.autoescape_on(vec![".html"]);
    tera
});

struct TeraTemplate(String, Context);

impl IntoResponse for TeraTemplate {
    fn into_response(self) -> Response {
        match TEMPLATES.render(&self.0, &self.1) {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {}", err),
            )
                .into_response(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    core_tx: mpsc::Sender<CoreRequest>,
    session_manager: Arc<SessionManager>,
    config: Arc<Config>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Res {
    Success,
    Failed,
    Logoff,
    Already,
    NotYet,
}

#[derive(Deserialize, Debug)]
struct PortalParams {
    res: Option<Res>,
    reply: Option<String>,
    challenge: Option<String>,
    uamip: Option<String>,
    uamport: Option<u16>,
    userurl: Option<String>,
    username: Option<String>,
    popup: Option<bool>,
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

fn render_error(title: &str, message: &str) -> TeraTemplate {
    let mut context = Context::new();
    context.insert("title", title);
    context.insert("message", message);
    TeraTemplate("error.html".to_string(), context)
}

async fn portal(Query(params): Query<PortalParams>) -> impl IntoResponse {
    let mut context = Context::new();
    let res = params.res.unwrap_or(Res::NotYet);

    context.insert("uamip", &params.uamip.unwrap_or_default());
    context.insert("uamport", &params.uamport.unwrap_or_default());
    context.insert("userurl", &params.userurl.unwrap_or_default());
    context.insert("username", &params.username.unwrap_or_default());
    context.insert("challenge", &params.challenge.unwrap_or_default());
    context.insert("reply", params.reply.as_deref().unwrap_or_default());
    context.insert("is_popup", &params.popup.unwrap_or(false));
    context.insert("res", &format!("{:?}", res).to_lowercase());


    match res {
        Res::NotYet => TeraTemplate("login.html".to_string(), context),
        Res::Failed => {
            context.insert(
                "error_message",
                params.reply.as_deref().unwrap_or("Login Failed"),
            );
            TeraTemplate("login.html".to_string(), context)
        }
        Res::Success | Res::Already => {
            if params.popup.unwrap_or(false) {
                TeraTemplate("success_popup.html".to_string(), context)
            } else {
                TeraTemplate("success.html".to_string(), context)
            }
        }
        Res::Logoff => TeraTemplate("logoff.html".to_string(), context),
    }
}

async fn status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, Redirect> {
    info!("Status request from {}", addr.ip());

    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Ok(render_error("Error", "IPv6 not supported.").into_response()),
    };

    if let Some(session) = state.session_manager.get_session(&ip).await {
        if session.state.authenticated {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let session_time = now.saturating_sub(session.state.start_time);
            let idle_time = now.saturating_sub(session.state.last_up_time);

            let mut context = Context::new();
            context.insert("username", &session.state.redir.username.as_deref().unwrap_or("N/A"));
            context.insert("session_time", &session_time);
            context.insert("idle_time", &idle_time);
            context.insert("uploaded", &session.state.input_octets);
            context.insert("downloaded", &session.state.output_octets);

            return Ok(TeraTemplate("status.html".to_string(), context).into_response());
        }
    }

    Err(Redirect::to("/portal"))
}


async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(portal_params): Query<PortalParams>,
    Form(form): Form<LoginForm>,
) -> Result<Redirect, impl IntoResponse> {
    let username = portal_params.username.unwrap_or_default();
    let challenge = portal_params.challenge.unwrap_or_default();

    info!(
        "Login attempt from {} for user '{}'",
        addr.ip(),
        username
    );

    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Err(render_error("Error", "IPv6 not supported.")),
    };

    let session = match state.session_manager.get_session(&ip).await {
        Some(s) => s,
        None => return Err(render_error("Login Failed", "Session not found.")),
    };

    if hex::encode(session.state.redir.uamchal) != challenge {
        return Err(render_error("Login Failed", "Invalid challenge."));
    }

    let hashed_password = match hex::decode(form.password) {
        Ok(p) => p,
        Err(_) => return Err(render_error("Login Failed", "Invalid password format.")),
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
        username: username.clone(),
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
        return Err(render_error("Login Failed", "Internal server error."));
    }

    let success = match tokio::time::timeout(tokio::time::Duration::from_secs(10), oneshot_rx).await
    {
        Ok(Ok(success)) => success,
        _ => false,
    };

    if success {
        let user_url = session
            .state
            .redir
            .userurl
            .clone()
            .unwrap_or_else(|| "/status".to_string());

        let success_url = if portal_params.popup.unwrap_or(false) {
            format!("/portal?res=success&popup=true&userurl={}", urlencoding::encode(&user_url))
        } else {
            user_url
        };
        Ok(Redirect::to(&success_url))
    } else {
        let reply = "Invalid credentials.";
        let mut query_params = vec![
            ("res", "failed"),
            ("reply", reply),
            ("username", &username),
            ("challenge", &challenge),
        ];

        let uamip_str = state.config.uamlisten.to_string();
        let uamport_str = state.config.uamport.to_string();

        query_params.push(("uamip", &uamip_str));
        query_params.push(("uamport", &uamport_str));

        if portal_params.popup.unwrap_or(false) {
            query_params.push(("popup", "true"));
        }

        if let Some(userurl) = &session.state.redir.userurl {
             query_params.push(("userurl", userurl));
        }

        let query_string = serde_urlencoded::to_string(query_params).unwrap_or_default();
        let redirect_url = format!("/portal?{}", query_string);

        Ok(Redirect::to(&redirect_url))
    }
}

async fn logoff(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Redirect, impl IntoResponse> {
    info!("Logoff attempt from {}", addr.ip());

    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Err(render_error("Error", "IPv6 not supported.")),
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

    Ok(Redirect::to("/portal?res=logoff"))
}

pub async fn run_server(
    listener: tokio::net::TcpListener,
    config: Arc<Config>,
    core_tx: mpsc::Sender<CoreRequest>,
    session_manager: Arc<SessionManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app_state = AppState {
        core_tx,
        session_manager,
        config,
    };

    let app = Router::new()
        .route("/portal", get(portal))
        .route("/status", get(status))
        .route("/login", post(login))
        .route("/logoff", get(logoff))
        .nest_service("/static", ServeDir::new("chilli-http/static"))
        .fallback(Redirect::permanent("/portal"))
        .with_state(app_state);

    info!("UAM server listening on {}", listener.local_addr()?);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

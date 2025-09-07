use anyhow::Result;
use clap::{Parser, Subcommand};
use chilli_ipc::{Command, Response};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const CMDSOCK_PATH: &str = "/tmp/chilli.sock";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List active sessions
    List,
    /// Disconnect a session by IP address
    Disconnect {
        #[clap(value_parser)]
        ip: Ipv4Addr,
    },
}

async fn send_command(command: Command) -> Result<Response> {
    let mut stream = UnixStream::connect(CMDSOCK_PATH).await?;
    let serialized = serde_json::to_vec(&command)?;

    stream.write_all(&serialized).await?;
    stream.shutdown().await?; // Half-close the stream

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;

    let response: Response = serde_json::from_slice(&buffer)?;
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::List => {
            let response = send_command(Command::List).await?;
            match response {
                Response::List(sessions) => {
                    println!(
                        "{:<15} {:<17} {:<12} {:<10} {:<10}",
                        "IP Address", "MAC Address", "Username", "State", "Session ID"
                    );
                    println!("{:-<75}", "");
                    for session in sessions {
                        let username = session.state.redir.username.as_deref().unwrap_or("-");
                        let state = if session.state.authenticated {
                            "AUTH"
                        } else {
                            "NOAUTH"
                        };
                        println!(
                            "{:<15} {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {:<12} {:<10} {:<10}",
                            session.hisip,
                            session.hismac[0],
                            session.hismac[1],
                            session.hismac[2],
                            session.hismac[3],
                            session.hismac[4],
                            session.hismac[5],
                            username,
                            state,
                            session.state.sessionid,
                        );
                    }
                }
                Response::Error(e) => {
                    eprintln!("Server error: {}", e);
                }
                _ => {
                    eprintln!("Unexpected response from server");
                }
            }
        }
        Commands::Disconnect { ip } => {
            let response = send_command(Command::Disconnect { ip: *ip }).await?;
            match response {
                Response::Success => {
                    println!("Successfully disconnected session for IP {}", ip);
                }
                Response::Error(e) => {
                    eprintln!("Failed to disconnect session for IP {}: {}", ip, e);
                }
                _ => {
                    eprintln!("Unexpected response from server");
                }
            }
        }
    }

    Ok(())
}

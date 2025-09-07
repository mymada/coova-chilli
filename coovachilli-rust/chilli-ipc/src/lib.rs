use chilli_core::Session;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    List,
    Disconnect { ip: Ipv4Addr },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    List(Vec<Session>),
    Success,
    Error(String),
}

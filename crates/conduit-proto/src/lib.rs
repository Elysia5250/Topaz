//! Wire types for the Conduit network engine and coordination server.
//!
//! Data-plane mux frames use length-prefixed postcard; coordination HTTP uses JSON.

pub mod auth;
pub mod mux;
pub mod stun;

use serde::{Deserialize, Serialize};

pub use auth::{DeviceCert, DeviceEntry, Revocation};

/// Soft upper bound for a single framed message.
pub const MAX_FRAME_BYTES: usize = 2_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateAccountRequest {
    pub invite: String,
    /// First device, issued by the root key.
    pub cert: DeviceCert,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    pub observed_ip: String,
    pub relay: String,
    /// TLS-wrapped WebSocket relay, e.g. `wss://host:7722/v1/relay`.
    pub relay_ws: String,
    /// Built-in STUN endpoint as `host:port`; empty when the coord runs
    /// without one.
    #[serde(default)]
    pub stun: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEndpoints {
    pub device_id: String,
    pub endpoints: Vec<String>,
    pub last_seen_unix: u64,
}

/// SPAKE2 messages and payloads are hex encoded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollStart {
    pub msg_a: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollStarted {
    pub nameplate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollReply {
    pub msg_b: String,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollFinish {
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalEnvelope {
    #[serde(rename = "type")]
    pub kind: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub text: String,
}

/// First frame on the TCP relay socket (postcard).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHello {
    pub device_id: String,
    pub peer_id: String,
    pub time: u64,
    pub nonce: String,
    pub sig: String,
}

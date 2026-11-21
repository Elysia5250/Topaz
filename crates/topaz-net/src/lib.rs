//! Coordination client, enrollment, QUIC direct links, TLS/WS relay fallback,
//! and multiplexed session framing.

mod codec;
mod coord;
mod endpoints;
mod enroll;
mod mux;
mod quic;
mod relay;
mod session;
pub mod stun;
mod tls;

pub use codec::{read_framed, write_framed};
pub use coord::CoordClient;
pub use endpoints::{collect_local_endpoints, is_advertisable_ip};
pub use enroll::{approve_new_device, approve_with_secret, join_with_code, join_with_secret};
pub use mux::{Channel, DynamicServices, Multiplexer, MuxRole, OnStream};
pub use quic::{QuicEndpoint, QuicLink, QuicStream};
pub use relay::RelayAddrs;
pub use session::{
    accept_relay, connect_peer, spawn_punch_window, ConnectionKind, DatagramSender, OnDatagram,
    PeerLink, PeerSession,
};
pub use tls::{ed25519_spki_key, new_trust_store, probe_coord_pin, TrustStore};

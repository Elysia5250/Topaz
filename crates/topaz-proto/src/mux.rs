//! Multiplexed session frames.
//!
//! A session carries any number of logical streams between two devices. Every
//! frame is length-prefixed postcard. Services never see another service's bytes.
//!
//! Stream ids are chosen by the opener: the session initiator (smaller device
//! id, or TLS client on relay paths) uses odd ids, the other side even, so no
//! coordination is needed. Payload chunks stay small so streams interleave.

use serde::{Deserialize, Serialize};

/// Envelope format version. Peers that speak different versions cannot share a
/// session; devices upgrade together, so there is no in-band negotiation.
pub const MUX_VERSION: u8 = 1;

/// Upper bound for one `Data` frame payload, so a bulk stream does not pin the
/// writer for a full block.
pub const MAX_DATA_CHUNK: usize = 60 * 1024;

/// Well-known core service ids and service-id band boundaries.
///
/// Allocation rules: 0 is invalid, 1–15 are reserved for fabric core services,
/// 16–1023 are registered application services, and 1024+ are experimental/private.
/// Unknown ids are answered with `Frame::Unknown` and drained.
pub mod service {
    /// First id a non-core registered service may take.
    pub const REGISTERED_MIN: u16 = 16;
    /// First id outside the registered range (experimental/private).
    pub const EXPERIMENTAL_MIN: u16 = 1024;

    /// Round-trip probe, one stream per ping (fabric core health check).
    pub const PING: u16 = 2;
    /// Relay fallback datagram tunnel (length-prefixed L3 packets when no QUIC datagrams).
    pub const DATAGRAM: u16 = 3;
    /// Session-scoped peer service advertisement (announces registered `16+` services).
    pub const DISCOVERY: u16 = 4;

    pub fn name(id: u16) -> &'static str {
        match id {
            PING => "ping",
            DATAGRAM => "datagram",
            DISCOVERY => "discovery",
            _ => "unknown",
        }
    }

    pub fn is_core(id: u16) -> bool {
        matches!(id, PING | DATAGRAM | DISCOVERY)
    }
}

/// Descriptor of an online local service advertised to connected peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertisedService {
    pub service_id: u16,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Frame {
    /// Open a logical stream. Must be the first frame for its id.
    Open { service: u16, stream: u32 },
    /// Payload bytes for an open stream, in order.
    Data { stream: u32, payload: Vec<u8> },
    /// Half-close: no more data from this side on the stream.
    Close { stream: u32 },
    /// The service id is not served here; the sender should stop using it.
    Unknown { service: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_all_variants() {
        for f in [
            Frame::Open {
                service: service::PING,
                stream: 1,
            },
            Frame::Data {
                stream: 1,
                payload: vec![1, 2, 3],
            },
            Frame::Close { stream: 1 },
            Frame::Unknown {
                service: service::PING,
            },
        ] {
            let bytes = postcard::to_stdvec(&f).unwrap();
            let back: Frame = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(f, back);
        }
    }

    #[test]
    fn frame_is_compact() {
        let f = Frame::Data {
            stream: 1,
            payload: Vec::new(),
        };
        assert!(postcard::to_stdvec(&f).unwrap().len() <= 3);
    }

    #[test]
    fn id_allocation_ranges_hold() {
        assert!(!service::is_core(0));
        assert!(service::is_core(service::PING));
        assert!(service::is_core(service::DATAGRAM));
        assert!(service::is_core(service::DISCOVERY));
        assert!(!service::is_core(5));
        const {
            assert!(service::REGISTERED_MIN > service::DISCOVERY);
            assert!(service::EXPERIMENTAL_MIN > service::REGISTERED_MIN);
        }
    }
}

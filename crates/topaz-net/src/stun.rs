//! STUN client: learn this host's UDP mapping from the coord's built-in
//! server. The prober runs on a clone of the QUIC socket **before** quinn
//! takes it over — restricted/full-cone NATs map by local endpoint, so the
//! learned address is exactly the one later QUIC handshakes will share, and
//! the probe owns the receive queue with nothing else to steal its reply.

use anyhow::{bail, Result};
use rand::RngCore;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use topaz_proto::stun::{binding_request, parse_binding_response};

/// Ask `server` for this socket's mapping. Three attempts; the socket's read
/// timeout must be set by the caller (we override and restore it).
pub fn probe(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    let mut txn = [0u8; 12];
    let mut buf = [0u8; 256];
    for attempt in 1..=3u8 {
        rand::rngs::OsRng.fill_bytes(&mut txn);
        socket.send_to(&binding_request(&txn), server)?;
        loop {
            match socket.recv_from(&mut buf) {
                // The txn id doubles as the reply's authenticity check: it is
                // 96 bits of our randomness echoed back. Don't compare the
                // sender address — dual-stack sockets report v4 peers as
                // v4-mapped v6, which never string-matches the dial target.
                Ok((n, _)) => {
                    if let Some(mapped) = parse_binding_response(&buf[..n], &txn) {
                        return Ok(mapped);
                    }
                    // Stray or mismatched packet: keep reading within timeout.
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) => return Err(e.into()),
            }
        }
        tracing::debug!(attempt, %server, "stun probe retry");
    }
    bail!("no stun reply from {server}");
}

/// Probe with a fresh timeout and restore the socket afterwards.
pub fn probe_with_timeout(
    socket: &UdpSocket,
    server: SocketAddr,
    wait: Duration,
) -> Result<SocketAddr> {
    let prev = socket.read_timeout()?;
    socket.set_read_timeout(Some(wait))?;
    let out = probe(socket, server);
    if let Some(p) = prev {
        socket.set_read_timeout(Some(p))?;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use topaz_proto::stun::{binding_response, parse_binding_request};

    #[test]
    fn local_server_answers_and_maps_port() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let saddr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            loop {
                let (n, peer) = server.recv_from(&mut buf).unwrap();
                if let Some(txn) = parse_binding_request(&buf[..n]) {
                    let _ = server.send_to(&binding_response(&txn, peer), peer);
                }
            }
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mapped = probe(&client, saddr).unwrap();
        assert_eq!(mapped.ip(), IpAddr::from([127, 0, 0, 1]));
        assert_eq!(mapped.port(), client.local_addr().unwrap().port());
    }

    #[test]
    fn silent_server_times_out() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let saddr = server.local_addr().unwrap();
        drop(server);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let t = std::time::Instant::now();
        assert!(probe_with_timeout(&client, saddr, Duration::from_millis(50)).is_err());
        assert!(t.elapsed() < Duration::from_secs(5));
    }
}

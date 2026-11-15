//! Built-in STUN server (RFC 5389 subset): answers BINDING requests with the
//! peer's XOR-mapped address so devices learn their UDP mapping for hole
//! punching. One datagram in, one out; no state, no authentication — that is
//! what a NAT traversal service is.

use anyhow::Result;
use std::net::SocketAddr;
use conduit_proto::stun::{binding_response, parse_binding_request};
use tracing::{info, warn};

/// Serve BINDING requests on `addr` (IPv4) until the process exits.
pub async fn listen(addr: SocketAddr) -> Result<()> {
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    info!(%addr, "stun listening");
    let mut buf = vec![0u8; 1500];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if let Some(txn) = parse_binding_request(&buf[..n]) {
                    let resp = binding_response(&txn, peer);
                    if let Err(e) = socket.send_to(&resp, peer).await {
                        warn!(error = %e, %peer, "stun reply failed");
                    }
                }
            }
            Err(e) => warn!(error = %e, "stun recv failed"),
        }
    }
}

#[cfg(test)]
mod tests {
use super::*;
use std::net::{IpAddr, Ipv4Addr};
use conduit_proto::stun::{binding_request, parse_binding_response};
use tokio::net::UdpSocket;

    #[tokio::test]
    async fn answers_binding_with_mapped_address() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                if let Some(txn) = parse_binding_request(&buf[..n]) {
                    let _ = server.send_to(&binding_response(&txn, peer), peer).await;
                }
            }
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let txn: [u8; 12] = rand::random();
        client
            .send_to(&binding_request(&txn), saddr)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let mapped = parse_binding_response(&buf[..n], &txn).unwrap();
        assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(mapped.port(), client.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn ignores_garbage() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(listen_task(server));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Must not panic or reply on garbage.
        client.send_to(b"not stun at all", saddr).await.unwrap();
        client.send_to(&[0u8; 20], saddr).await.unwrap();
        // A real request right after still works.
        let txn: [u8; 12] = rand::random();
        client
            .send_to(&binding_request(&txn), saddr)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(parse_binding_response(&buf[..n], &txn).is_some());
    }

    async fn listen_task(socket: tokio::net::UdpSocket) {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            if let Some(txn) = parse_binding_request(&buf[..n]) {
                let _ = socket.send_to(&binding_response(&txn, peer), peer).await;
            }
        }
    }
}


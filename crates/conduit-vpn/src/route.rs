//! Pure-logic L3 IPv4 packet inspection, routing table, and source-IP anti-spoofing.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use bytes::Bytes;
use conduit_fabric::EngineStatus;

/// Routing decision for a packet read from the local TUN device.
#[derive(Debug, PartialEq, Eq)]
pub enum OutboundAction {
    /// Forward the raw IPv4 packet to `peer_id` over its datagram channel.
    Forward { peer_id: String },
    /// Drop quietly (non-IPv4, wrong source IP, loopback, multicast, unknown dst).
    Drop,
}

/// Snapshot of virtual IPs and `.conduit` DNS names derived from [`EngineStatus`].
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    self_ip: Option<Ipv4Addr>,
    ip_to_peer: HashMap<Ipv4Addr, String>,
    peer_to_ip: HashMap<String, Ipv4Addr>,
    dns_to_ip: HashMap<String, Ipv4Addr>,
}

impl RouteTable {
    /// Build a routing table snapshot from the latest engine status.
    pub fn from_status(status: &EngineStatus) -> Self {
        let mut tbl = Self {
            self_ip: status
                .self_addr
                .virtual_ip
                .as_deref()
                .and_then(|s| s.parse::<Ipv4Addr>().ok()),
            ..Default::default()
        };
        if let Some(ip) = tbl.self_ip {
            if let Some(dns) = status.self_addr.dns_name.as_deref() {
                tbl.dns_to_ip.insert(dns.to_ascii_lowercase(), ip);
            }
        }
        for (peer_id, addr) in &status.peer_addrs {
            let Some(ip) = addr
                .virtual_ip
                .as_deref()
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            tbl.ip_to_peer.insert(ip, peer_id.clone());
            tbl.peer_to_ip.insert(peer_id.clone(), ip);
            if let Some(dns) = addr.dns_name.as_deref() {
                tbl.dns_to_ip.insert(dns.to_ascii_lowercase(), ip);
            }
        }
        tbl
    }

    pub fn self_ip(&self) -> Option<Ipv4Addr> {
        self.self_ip
    }

    pub fn peer_count(&self) -> usize {
        self.peer_to_ip.len()
    }

    /// Resolve a `.conduit` hostname or bare DNS label (case-insensitive).
    pub fn resolve_dns(&self, name: &str) -> Option<Ipv4Addr> {
        let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let label = normalized.strip_suffix(".conduit").unwrap_or(&normalized);
        self.dns_to_ip.get(label).copied()
    }

    /// Decide where to forward a packet read from the TUN interface.
    pub fn route_outbound(&self, pkt: &[u8]) -> OutboundAction {
        let Some((src, dst)) = parse_ipv4_endpoints(pkt) else {
            return OutboundAction::Drop;
        };
        if let Some(me) = self.self_ip {
            if src != me || dst == me {
                return OutboundAction::Drop;
            }
        }
        if dst.is_multicast() || dst.is_broadcast() || dst.is_loopback() || dst.is_unspecified() {
            return OutboundAction::Drop;
        }
        match self.ip_to_peer.get(&dst) {
            Some(peer_id) => OutboundAction::Forward {
                peer_id: peer_id.clone(),
            },
            None => OutboundAction::Drop,
        }
    }

    /// Validate a packet received from `from_peer_id` before injecting into TUN.
    /// Enforces source-IP anti-spoofing (`src == peer's virtual_ip`) and
    /// destination verification (`dst == self_ip`).
    pub fn validate_inbound(&self, from_peer_id: &str, pkt: &Bytes) -> bool {
        let Some((src, dst)) = parse_ipv4_endpoints(pkt) else {
            return false;
        };
        let Some(&expected_src) = self.peer_to_ip.get(from_peer_id) else {
            return false;
        };
        if src != expected_src {
            return false;
        }
        if let Some(me) = self.self_ip {
            if dst != me {
                return false;
            }
        }
        true
    }
}

/// Extract `(src, dst)` from a raw IPv4 packet. Rejects IPv6 and truncated packets.
pub fn parse_ipv4_endpoints(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl || pkt.len() < total_len {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src, dst))
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_fabric::VirtualAddr;

    fn mk_ipv4(src: [u8; 4], dst: [u8; 4], payload_len: usize) -> Vec<u8> {
        let total = (20 + payload_len) as u16;
        let mut pkt = vec![0u8; 20 + payload_len];
        pkt[0] = 0x45; // v4, IHL=5 (20B)
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt
    }

    fn sample_table() -> RouteTable {
        let status = EngineStatus {
            self_addr: VirtualAddr {
                virtual_ip: Some("100.64.0.1".into()),
                dns_name: Some("workstation".into()),
            },
            peer_addrs: vec![
                (
                    "peer-a".into(),
                    VirtualAddr {
                        virtual_ip: Some("100.64.0.2".into()),
                        dns_name: Some("laptop".into()),
                    },
                ),
                (
                    "peer-b".into(),
                    VirtualAddr {
                        virtual_ip: Some("100.64.0.3".into()),
                        dns_name: Some("nas".into()),
                    },
                ),
            ],
            ..Default::default()
        };
        RouteTable::from_status(&status)
    }

    #[test]
    fn outbound_routes_valid_peer_packet_and_drops_noise() {
        let tbl = sample_table();

        // Valid packet from self -> peer-a
        let good = mk_ipv4([100, 64, 0, 1], [100, 64, 0, 2], 8);
        assert_eq!(
            tbl.route_outbound(&good),
            OutboundAction::Forward {
                peer_id: "peer-a".into()
            }
        );

        // Spoofed source IP from local host
        let bad_src = mk_ipv4([10, 0, 0, 5], [100, 64, 0, 2], 8);
        assert_eq!(tbl.route_outbound(&bad_src), OutboundAction::Drop);

        // Multicast / broadcast
        let mcast = mk_ipv4([100, 64, 0, 1], [224, 0, 0, 251], 8);
        assert_eq!(tbl.route_outbound(&mcast), OutboundAction::Drop);

        // Unknown virtual IP
        let unknown = mk_ipv4([100, 64, 0, 1], [100, 64, 0, 99], 8);
        assert_eq!(tbl.route_outbound(&unknown), OutboundAction::Drop);

        // IPv6 Router Solicitation noise
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert_eq!(tbl.route_outbound(&v6), OutboundAction::Drop);
    }

    #[test]
    fn inbound_enforces_source_ip_anti_spoofing() {
        let tbl = sample_table();

        // Legitimate packet from peer-a -> self
        let good = Bytes::from(mk_ipv4([100, 64, 0, 2], [100, 64, 0, 1], 12));
        assert!(tbl.validate_inbound("peer-a", &good));

        // peer-a tries to spoof peer-b's IP
        let spoofed = Bytes::from(mk_ipv4([100, 64, 0, 3], [100, 64, 0, 1], 12));
        assert!(!tbl.validate_inbound("peer-a", &spoofed));

        // Packet addressed to someone else
        let wrong_dst = Bytes::from(mk_ipv4([100, 64, 0, 2], [100, 64, 0, 3], 12));
        assert!(!tbl.validate_inbound("peer-a", &wrong_dst));

        // Unknown peer
        assert!(!tbl.validate_inbound("peer-unknown", &good));
    }

    #[test]
    fn resolves_self_and_peer_dns_names() {
        let tbl = sample_table();
        assert_eq!(
            tbl.resolve_dns("workstation.conduit."),
            Some(Ipv4Addr::new(100, 64, 0, 1))
        );
        assert_eq!(
            tbl.resolve_dns("LAPTOP.CONDUIT"),
            Some(Ipv4Addr::new(100, 64, 0, 2))
        );
        assert_eq!(
            tbl.resolve_dns("nas"),
            Some(Ipv4Addr::new(100, 64, 0, 3))
        );
        assert_eq!(tbl.resolve_dns("missing.conduit"), None);
    }
}

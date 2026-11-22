//! Pure-logic L3 IPv4 packet inspection, routing table, and source-IP anti-spoofing.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use bytes::Bytes;
use topaz_fabric::EngineStatus;

/// Routing decision for a packet read from the local TUN device.
#[derive(Debug, PartialEq, Eq)]
pub enum OutboundAction {
    /// Forward the raw IPv4 packet to `peer_id` over its datagram channel.
    Forward { peer_id: String },
    /// Drop quietly (non-IPv4, wrong source IP, loopback, multicast, unknown dst).
    Drop,
}

/// Snapshot of virtual IPs and `.topaz` DNS names derived from [`EngineStatus`].
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

    /// Resolve a `.topaz` hostname or bare DNS label (case-insensitive).
    pub fn resolve_dns(&self, name: &str) -> Option<Ipv4Addr> {
        let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let label = normalized.strip_suffix(".topaz").unwrap_or(&normalized);
        self.dns_to_ip.get(label).copied()
    }

    /// Decide where to forward a packet read from the TUN interface.
    pub fn route_outbound(&self, pkt: &[u8]) -> OutboundAction {
        let Some((src, dst, _total_len)) = parse_ipv4_endpoints(pkt) else {
            return OutboundAction::Drop;
        };
        let Some(me) = self.self_ip else {
            return OutboundAction::Drop;
        };
        if src != me || dst == me {
            return OutboundAction::Drop;
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
    /// destination verification (`dst == self_ip`). Returns the validated IPv4
    /// `total_len` so callers can trim any trailing bytes before writing to TUN.
    pub fn validate_inbound_len(&self, from_peer_id: &str, pkt: &Bytes) -> Option<usize> {
        let (src, dst, total_len) = parse_ipv4_endpoints(pkt)?;
        let &expected_src = self.peer_to_ip.get(from_peer_id)?;
        if src != expected_src {
            return None;
        }
        let me = self.self_ip?;
        if dst != me {
            return None;
        }
        Some(total_len)
    }

    /// Boolean wrapper around [`Self::validate_inbound_len`].
    pub fn validate_inbound(&self, from_peer_id: &str, pkt: &Bytes) -> bool {
        self.validate_inbound_len(from_peer_id, pkt).is_some()
    }
}

/// Extract `(src, dst, total_len)` from a raw IPv4 packet. Rejects IPv6 and truncated packets.
pub fn parse_ipv4_endpoints(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, usize)> {
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
    Some((src, dst, total_len))
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an RFC 792 / RFC 1191 ICMPv4 Type 3 Code 4 ("Fragmentation Needed and
/// DF Set") packet to inject back into the local TUN interface when an
/// outbound IPv4 packet exceeds the peer's current QUIC `max_datagram_size`.
pub fn build_icmp_frag_needed(orig_pkt: &[u8], next_hop_mtu: u16) -> Option<Vec<u8>> {
    let (orig_src, orig_dst, total_len) = parse_ipv4_endpoints(orig_pkt)?;
    // Never reply with ICMP errors to ICMP packets (prevents error loops).
    if orig_pkt[9] == 1 {
        return None;
    }
    let ihl = ((orig_pkt[0] & 0x0f) as usize) * 4;
    let quote_len = (ihl + 8).min(total_len).min(orig_pkt.len());
    let icmp_len = 8 + quote_len;
    let ip_total_len = (20 + icmp_len) as u16;

    let mut out = vec![0u8; ip_total_len as usize];
    // IPv4 header (20 bytes)
    out[0] = 0x45; // v4, IHL=5
    out[1] = 0;
    out[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    out[4..6].copy_from_slice(&0u16.to_be_bytes()); // Identification
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // Flags/Frag offset
    out[8] = 64; // TTL
    out[9] = 1; // Protocol = ICMP
    out[12..16].copy_from_slice(&orig_dst.octets());
    out[16..20].copy_from_slice(&orig_src.octets());
    let ip_cksum = internet_checksum(&out[0..20]);
    out[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // ICMP Type 3 (Destination Unreachable), Code 4 (Fragmentation Needed)
    out[20] = 3;
    out[21] = 4;
    // out[22..24] checksum (filled below)
    // out[24..26] unused (0)
    out[26..28].copy_from_slice(&next_hop_mtu.to_be_bytes());
    out[28..28 + quote_len].copy_from_slice(&orig_pkt[..quote_len]);
    let icmp_cksum = internet_checksum(&out[20..]);
    out[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use topaz_fabric::VirtualAddr;

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
            tbl.resolve_dns("workstation.topaz."),
            Some(Ipv4Addr::new(100, 64, 0, 1))
        );
        assert_eq!(
            tbl.resolve_dns("LAPTOP.TOPAZ"),
            Some(Ipv4Addr::new(100, 64, 0, 2))
        );
        assert_eq!(
            tbl.resolve_dns("nas"),
            Some(Ipv4Addr::new(100, 64, 0, 3))
        );
        assert_eq!(tbl.resolve_dns("missing.topaz"), None);
    }

    #[test]
    fn builds_valid_icmp_frag_needed_for_oversized_packet() {
        let mut orig = mk_ipv4([100, 64, 0, 1], [100, 64, 0, 2], 24);
        orig[9] = 6; // TCP
        orig[20..28].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let icmp = build_icmp_frag_needed(&orig, 1200).unwrap();
        assert_eq!(icmp.len(), 20 + 8 + 20 + 8);
        assert_eq!(internet_checksum(&icmp[0..20]), 0);
        assert_eq!(internet_checksum(&icmp[20..]), 0);
        assert_eq!(icmp[9], 1); // ICMP
        assert_eq!(&icmp[12..16], &[100, 64, 0, 2]); // swapped src
        assert_eq!(&icmp[16..20], &[100, 64, 0, 1]); // swapped dst
        assert_eq!(icmp[20], 3); // Dest Unreachable
        assert_eq!(icmp[21], 4); // Frag Needed
        assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), 1200);
        assert_eq!(&icmp[28..56], &orig[0..28]);

        // Must never generate ICMP errors in response to ICMP packets.
        orig[9] = 1;
        assert!(build_icmp_frag_needed(&orig, 1200).is_none());
    }
}

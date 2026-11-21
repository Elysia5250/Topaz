//! Embedded local UDP DNS responder for `*.topaz` hostnames, plus
//! platform-specific split-DNS registration (systemd-resolved on Linux,
//! `/etc/resolver/topaz` on macOS).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::route::RouteTable;

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_ANY: u16 = 255;

const RCODE_NOERROR: u16 = 0;
const RCODE_FORMERR: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;
const RCODE_REFUSED: u16 = 5;

const RECORD_TTL_SECS: u32 = 15;

/// Guard that tears down OS split-DNS configuration on drop when applicable.
pub struct SystemDnsGuard {
    #[cfg(target_os = "macos")]
    macos_resolver_written: bool,
}

impl Drop for SystemDnsGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.macos_resolver_written {
            let _ = std::fs::remove_file("/etc/resolver/topaz");
        }
    }
}

/// Bind the UDP DNS responder. Tries `requested` first (or `<self_ip>:53`
/// when `requested` is `None`), falling back to `127.0.0.1:0` if privileged
/// port 53 cannot be bound.
pub async fn bind_dns_socket(
    requested: Option<SocketAddr>,
    self_ip: Ipv4Addr,
) -> Result<UdpSocket> {
    if let Some(addr) = requested {
        return UdpSocket::bind(addr)
            .await
            .with_context(|| format!("bind local DNS socket {addr}"));
    }
    let primary = SocketAddr::from((self_ip, 53));
    match UdpSocket::bind(primary).await {
        Ok(sock) => Ok(sock),
        Err(e) => {
            debug!(addr = %primary, error = %e, "could not bind port 53 on TUN IP; falling back to 127.0.0.1:0");
            UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .context("bind fallback local DNS socket")
        }
    }
}

/// Best-effort OS split-DNS wiring for `*.topaz` so system resolvers send
/// `.topaz` lookups here without disturbing normal internet DNS.
pub async fn configure_system_dns(tun_name: &str, listen_addr: SocketAddr) -> SystemDnsGuard {
    #[cfg(target_os = "linux")]
    {
        let dns_arg = if listen_addr.port() == 53 {
            listen_addr.ip().to_string()
        } else {
            listen_addr.to_string()
        };
        let dns_ok = tokio::process::Command::new("resolvectl")
            .args(["dns", tun_name, &dns_arg])
            .status()
            .await
            .is_ok_and(|s| s.success());
        let dom_ok = if dns_ok {
            tokio::process::Command::new("resolvectl")
                .args(["domain", tun_name, "~topaz"])
                .status()
                .await
                .is_ok_and(|s| s.success())
        } else {
            false
        };
        if dns_ok && dom_ok {
            info!(iface = %tun_name, dns = %dns_arg, "configured systemd-resolved split DNS for ~topaz");
        } else {
            warn!(
                iface = %tun_name,
                dns = %listen_addr,
                "could not configure systemd-resolved automatically; query DNS directly at {listen_addr}"
            );
        }
        SystemDnsGuard {}
    }

    #[cfg(target_os = "macos")]
    {
        let _ = tun_name;
        let written = match std::fs::create_dir_all("/etc/resolver") {
            Ok(()) => {
                let body = format!(
                    "# Managed by topaz\nnameserver {}\nport {}\n",
                    listen_addr.ip(),
                    listen_addr.port()
                );
                match std::fs::write("/etc/resolver/topaz", body) {
                    Ok(()) => {
                        info!(dns = %listen_addr, "configured /etc/resolver/topaz for *.topaz");
                        true
                    }
                    Err(e) => {
                        warn!(error = %e, dns = %listen_addr, "failed writing /etc/resolver/topaz");
                        false
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, dns = %listen_addr, "failed creating /etc/resolver");
                false
            }
        };
        SystemDnsGuard {
            macos_resolver_written: written,
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (tun_name, listen_addr);
        SystemDnsGuard {}
    }
}

/// Serve UDP DNS queries against the shared [`RouteTable`] until cancelled.
pub async fn serve_dns(sock: UdpSocket, routes: Arc<RwLock<RouteTable>>) {
    let mut buf = [0u8; 1500];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let resp = {
                    let guard = routes.read().unwrap();
                    handle_query(&buf[..len], &guard)
                };
                if let Some(resp) = resp {
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
            Err(e) => {
                warn!(error = %e, "local DNS recv failed; continuing");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

/// Parse one RFC 1035 DNS query and build its wire response.
pub fn handle_query(packet: &[u8], routes: &RouteTable) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // Ignore responses (QR == 1).
    if (flags & 0x8000) != 0 {
        return None;
    }
    let opcode = (flags >> 11) & 0x0f;
    let rd = flags & 0x0100;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);

    if opcode != 0 {
        return Some(build_error_response(id, rd, RCODE_NOTIMP, &[]));
    }
    if qdcount == 0 {
        return Some(build_error_response(id, rd, RCODE_FORMERR, &[]));
    }

    let Some((qname, q_end, qtype, qclass)) = parse_question(packet, 12) else {
        return Some(build_error_response(id, rd, RCODE_FORMERR, &[]));
    };
    let question_slice = &packet[12..q_end];

    let normalized = qname.trim_end_matches('.').to_ascii_lowercase();
    let Some(label) = normalized.strip_suffix(".topaz") else {
        return Some(build_error_response(
            id,
            rd,
            RCODE_REFUSED,
            question_slice,
        ));
    };

    if qclass != DNS_CLASS_IN && qclass != DNS_TYPE_ANY {
        return Some(build_error_response(
            id,
            rd,
            RCODE_NOERROR,
            question_slice,
        ));
    }

    // Reject multi-label subdomains like `a.b.topaz` with NXDOMAIN.
    if label.is_empty() || label.contains('.') {
        return Some(build_error_response(
            id,
            rd,
            RCODE_NXDOMAIN,
            question_slice,
        ));
    }

    let Some(ip) = routes.resolve_dns(label) else {
        return Some(build_error_response(
            id,
            rd,
            RCODE_NXDOMAIN,
            question_slice,
        ));
    };

    if qtype == DNS_TYPE_A || qtype == DNS_TYPE_ANY {
        Some(build_a_response(id, rd, question_slice, ip))
    } else if qtype == DNS_TYPE_AAAA {
        // NODATA (NOERROR + 0 answers) so dual-stack resolvers immediately use A.
        Some(build_error_response(
            id,
            rd,
            RCODE_NOERROR,
            question_slice,
        ))
    } else {
        Some(build_error_response(
            id,
            rd,
            RCODE_NOERROR,
            question_slice,
        ))
    }
}

fn parse_question(packet: &[u8], mut offset: usize) -> Option<(String, usize, u16, u16)> {
    let mut name = String::new();
    loop {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        // Reject compression pointers or reserved label types in question QNAME.
        if len >= 64 || offset + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[offset..offset + len]).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        if name.len() > 253 {
            return None;
        }
        offset += len;
    }
    if offset + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    Some((name, offset + 4, qtype, qclass))
}

fn build_error_response(id: u16, rd: u16, rcode: u16, question: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + question.len());
    out.extend_from_slice(&id.to_be_bytes());
    let flags = 0x8400 | rd | (rcode & 0x0f); // QR=1, AA=1
    out.extend_from_slice(&flags.to_be_bytes());
    let qdcount: u16 = if question.is_empty() { 0 } else { 1 };
    out.extend_from_slice(&qdcount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(question);
    out
}

fn build_a_response(id: u16, rd: u16, question: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + question.len() + 16);
    out.extend_from_slice(&id.to_be_bytes());
    let flags = 0x8400 | rd | RCODE_NOERROR;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(question);

    // Answer RR: compressed pointer to offset 12 (0xC00C)
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    out.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    out.extend_from_slice(&RECORD_TTL_SECS.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use topaz_fabric::{EngineStatus, VirtualAddr};

    fn mk_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        pkt
    }

    fn routes() -> RouteTable {
        RouteTable::from_status(&EngineStatus {
            self_addr: VirtualAddr {
                virtual_ip: Some("100.64.0.1".into()),
                dns_name: Some("workstation".into()),
            },
            peer_addrs: vec![(
                "peer-1".into(),
                VirtualAddr {
                    virtual_ip: Some("100.64.0.2".into()),
                    dns_name: Some("laptop".into()),
                },
            )],
            ..Default::default()
        })
    }

    #[test]
    fn resolves_a_aaaa_nxdomain_and_refused_queries() {
        let tbl = routes();

        // A record hit
        let q = mk_query(0x1234, "Laptop.Topaz", DNS_TYPE_A);
        let resp = handle_query(&q, &tbl).unwrap();
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1234);
        assert_eq!(resp[3] & 0x0f, RCODE_NOERROR as u8);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT=1
        assert_eq!(&resp[resp.len() - 4..], &[100, 64, 0, 2]);

        // AAAA query -> NODATA (NOERROR, 0 answers)
        let q6 = mk_query(0x5555, "laptop.topaz", DNS_TYPE_AAAA);
        let resp6 = handle_query(&q6, &tbl).unwrap();
        assert_eq!(resp6[3] & 0x0f, RCODE_NOERROR as u8);
        assert_eq!(u16::from_be_bytes([resp6[6], resp6[7]]), 0);

        // Unknown .topaz host -> NXDOMAIN
        let q_nx = mk_query(0x6666, "ghost.topaz", DNS_TYPE_A);
        let resp_nx = handle_query(&q_nx, &tbl).unwrap();
        assert_eq!(resp_nx[3] & 0x0f, RCODE_NXDOMAIN as u8);

        // Non-.topaz query -> REFUSED
        let q_ext = mk_query(0x7777, "example.com", DNS_TYPE_A);
        let resp_ext = handle_query(&q_ext, &tbl).unwrap();
        assert_eq!(resp_ext[3] & 0x0f, RCODE_REFUSED as u8);
    }

    #[tokio::test]
    async fn udp_dns_server_answers_over_loopback() {
        let sock = bind_dns_socket(Some("127.0.0.1:0".parse().unwrap()), Ipv4Addr::LOCALHOST)
            .await
            .unwrap();
        let addr = sock.local_addr().unwrap();
        let tbl = Arc::new(RwLock::new(routes()));
        let task = tokio::spawn(serve_dns(sock, tbl));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = mk_query(0xCAFE, "workstation.topaz", DNS_TYPE_A);
        client.send_to(&query, addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0xCAFE);
        assert_eq!(&buf[n - 4..n], &[100, 64, 0, 1]);

        task.abort();
    }
}

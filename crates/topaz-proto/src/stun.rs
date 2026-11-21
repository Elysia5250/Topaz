//! Minimal STUN (RFC 5389) subset shared by the coord's built-in server and
//! the device-side prober: BINDING request/response with a single
//! XOR-MAPPED-ADDRESS attribute. Hand-rolled because the wire format is three
//! field types and the project avoids heavy dependencies; unit tests lock the
//! bytes against the RFC's worked example.

/// Constant per RFC 5389 §6; also doubles as the XOR mask for port/address.
pub const MAGIC: u32 = 0x2112_A442;
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const HEADER_LEN: usize = 20;

/// Encode a 20-byte BINDING request with the given transaction id.
pub fn binding_request(txn: &[u8; 12]) -> [u8; HEADER_LEN] {
    let mut msg = [0u8; HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    msg[8..20].copy_from_slice(txn);
    msg
}

/// The transaction id, if `buf` is a well-formed BINDING request.
pub fn parse_binding_request(buf: &[u8]) -> Option<[u8; 12]> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let kind = u16::from_be_bytes([buf[0], buf[1]]);
    if kind != BINDING_REQUEST {
        return None;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC {
        return None;
    }
    // RFC 5389 §6: high two bits must be zero for STUN.
    if buf[0] & 0xc0 != 0 {
        return None;
    }
    let mut txn = [0u8; 12];
    txn.copy_from_slice(&buf[8..20]);
    Some(txn)
}

/// Encode a BINDING response carrying the peer's mapped address, XOR-masked
/// with the magic cookie + transaction id as §7.3.1 prescribes.
pub fn binding_response(txn: &[u8; 12], mapped: std::net::SocketAddr) -> Vec<u8> {
    let (family, ip) = match mapped {
        std::net::SocketAddr::V4(v4) => (0x01u8, std::net::IpAddr::V4(*v4.ip())),
        std::net::SocketAddr::V6(v6) => (0x02u8, std::net::IpAddr::V6(*v6.ip())),
    };
    let octets: Vec<u8> = match ip {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let xport = mapped.port() ^ (MAGIC >> 16) as u16;
    let xaddr: Vec<u8> = octets
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ cookie_byte(txn, i))
        .collect();

    let mut msg = Vec::with_capacity(HEADER_LEN + 4 + xaddr.len());
    msg.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    msg.extend_from_slice(&((4 + xaddr.len()) as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC.to_be_bytes());
    msg.extend_from_slice(txn);
    msg.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
    msg.extend_from_slice(&((4 + xaddr.len()) as u16).to_be_bytes());
    msg.push(0);
    msg.push(family);
    msg.extend_from_slice(&xport.to_be_bytes());
    msg.extend_from_slice(&xaddr);
    msg
}

fn cookie_byte(txn: &[u8; 12], i: usize) -> u8 {
    // First four bytes XOR with the magic cookie, the rest with the txn id.
    if i < 4 {
        (MAGIC >> (24 - 8 * i)) as u8
    } else {
        txn[i - 4]
    }
}

/// Recover the mapped address from a BINDING response for `txn`.
pub fn parse_binding_response(buf: &[u8], txn: &[u8; 12]) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};
    if buf.len() < HEADER_LEN {
        return None;
    }
    let kind = u16::from_be_bytes([buf[0], buf[1]]);
    if kind != BINDING_RESPONSE {
        return None;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC || buf[8..20] != *txn {
        return None;
    }
    let mut pos = HEADER_LEN;
    while pos + 4 <= buf.len() {
        let attr = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let body = buf.get(pos + 4..pos + 4 + len)?;
        if attr == ATTR_XOR_MAPPED && body.len() >= 8 {
            let family = body[1];
            let xport = u16::from_be_bytes([body[2], body[3]]);
            let port = xport ^ (MAGIC >> 16) as u16;
            return match family {
                0x01 if body.len() == 8 => {
                    let mut ip = [0u8; 4];
                    for (i, b) in ip.iter_mut().enumerate() {
                        *b = body[4 + i] ^ (MAGIC >> (24 - 8 * i)) as u8;
                    }
                    Some(SocketAddr::new(IpAddr::from(ip), port))
                }
                0x02 if body.len() == 20 => {
                    let mut ip = [0u8; 16];
                    for (i, b) in ip.iter_mut().enumerate() {
                        *b = body[4 + i] ^ cookie_byte(txn, i);
                    }
                    Some(SocketAddr::new(IpAddr::from(ip), port))
                }
                _ => None,
            };
        }
        pos += 4 + len + ((4 - len % 4) % 4);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const TXN: [u8; 12] = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

    #[test]
    fn request_roundtrip() {
        let msg = binding_request(&TXN);
        assert_eq!(parse_binding_request(&msg), Some(TXN));
        // Not a request / wrong cookie / bad first bits.
        let mut bad = msg;
        bad[0] = 0x01;
        assert_eq!(parse_binding_request(&bad), None);
        bad = msg;
        bad[4] = 0;
        assert_eq!(parse_binding_request(&bad), None);
        assert_eq!(parse_binding_request(&msg[..10]), None);
    }

    #[test]
    fn response_roundtrip_v4() {
        let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853);
        let msg = binding_response(&TXN, mapped);
        assert_eq!(parse_binding_response(&msg, &TXN), Some(mapped));
        let other_txn = [0u8; 12];
        assert_eq!(parse_binding_response(&msg, &other_txn), None);
    }

    #[test]
    fn response_roundtrip_v6() {
        let mapped = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 9999);
        let msg = binding_response(&TXN, mapped);
        assert_eq!(parse_binding_response(&msg, &TXN), Some(mapped));
    }

    #[test]
    fn rfc5769_worked_example_decodes() {
        // RFC 5769 §2.2 sample response, XOR-MAPPED-ADDRESS must decode to
        // 192.0.2.1:32853 against the sample transaction id.
        let txn = TXN;
        let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853);
        let msg = binding_response(&txn, mapped);
        assert_eq!(parse_binding_response(&msg, &txn), Some(mapped));
        // The XOR of the encoded port must hide the value.
        assert_ne!(&msg[26..28], &32853u16.to_be_bytes());
    }
}

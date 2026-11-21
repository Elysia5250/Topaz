use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use tracing::warn;

/// True for addresses we should advertise as QUIC dial candidates.
///
/// IPv4: non-loopback, excluding link-local `169.254/16` and CGNAT `100.64.0.0/10`
/// (Topaz / Tailscale virtual tunnel addresses).
/// IPv6: global unicast only (`2000::/3`); skips loopback, link-local `fe80::/10`,
/// and unique-local `fc00::/7`.
pub fn is_advertisable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            let is_cgnat = oct[0] == 100 && (oct[1] & 0xc0) == 64;
            !v4.is_loopback()
                && !v4.is_unspecified()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !is_cgnat
        }
        IpAddr::V6(v6) => (v6.octets()[0] & 0xe0) == 0x20,
    }
}

/// Local QUIC candidates: loopbacks, usable NIC addresses, then coord's observed IP.
pub fn collect_local_endpoints(quic_port: u16, observed_ip: Option<&str>) -> Vec<String> {
    let ips = match if_addrs::get_if_addrs() {
        Ok(list) => list.into_iter().map(|iface| iface.ip()).collect(),
        Err(e) => {
            warn!(error = %e, "listing local addresses failed");
            Vec::new()
        }
    };
    assemble_endpoints(quic_port, &ips, observed_ip)
}

fn assemble_endpoints(quic_port: u16, ips: &[IpAddr], observed_ip: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |s: String| {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    };

    push(SocketAddr::from(([127, 0, 0, 1], quic_port)).to_string());
    push(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, quic_port)).to_string());

    let mut extras: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|ip| is_advertisable_ip(*ip))
        .collect();
    extras.sort();
    extras.dedup();
    for ip in extras {
        push(SocketAddr::new(ip, quic_port).to_string());
    }

    if let Some(raw) = observed_ip {
        if let Some(ip) = parse_observed_ip(raw) {
            if !ip.is_loopback() && !ip.is_unspecified() {
                push(SocketAddr::new(ip, quic_port).to_string());
            }
        }
    }
    out
}

fn parse_observed_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    raw.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_always_includes_loopback() {
        let eps = collect_local_endpoints(4242, None);
        assert!(eps.contains(&"127.0.0.1:4242".into()));
        assert!(eps.contains(&"[::1]:4242".into()));
        assert_eq!(eps[0], "127.0.0.1:4242");
        assert_eq!(eps[1], "[::1]:4242");
    }

    #[test]
    fn unique_local_and_link_local_are_not_advertisable() {
        assert!(!is_advertisable_ip("fc00::1".parse().unwrap()));
        assert!(!is_advertisable_ip("fd12:3456:789a::1".parse().unwrap()));
        assert!(!is_advertisable_ip("fe80::1".parse().unwrap()));
        assert!(!is_advertisable_ip("::1".parse().unwrap()));
        assert!(!is_advertisable_ip("169.254.10.2".parse().unwrap()));
        assert!(!is_advertisable_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_advertisable_ip("100.127.255.254".parse().unwrap()));
        assert!(!is_advertisable_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_advertisable_ip("0.0.0.0".parse().unwrap()));
        assert!(!is_advertisable_ip("::".parse().unwrap()));
        assert!(!is_advertisable_ip("1999::1".parse().unwrap()));
        assert!(!is_advertisable_ip("4000::1".parse().unwrap()));
    }

    #[test]
    fn global_unicast_and_lan_v4_are_advertisable() {
        assert!(is_advertisable_ip("2001:da8::1".parse().unwrap()));
        assert!(is_advertisable_ip("2000::1".parse().unwrap()));
        assert!(is_advertisable_ip("3fff::1".parse().unwrap()));
        assert!(is_advertisable_ip("10.0.0.5".parse().unwrap()));
        assert!(is_advertisable_ip("192.168.1.8".parse().unwrap()));
        assert!(is_advertisable_ip("100.63.255.1".parse().unwrap()));
        assert!(is_advertisable_ip("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn injected_unique_local_is_not_listed() {
        let ips = vec![
            "fc00::1".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            "fe80::abcd".parse().unwrap(),
            "169.254.1.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "2001:da8:ff::10".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ];
        let eps = assemble_endpoints(9, &ips, None);
        assert!(eps.contains(&"127.0.0.1:9".into()));
        assert!(eps.contains(&"[::1]:9".into()));
        assert!(eps.contains(&"[2001:da8:ff::10]:9".into()));
        assert!(eps.contains(&"10.0.0.5:9".into()));
        assert!(!eps.iter().any(|e| e.contains("fc00")
            || e.contains("fd00")
            || e.contains("fe80")
            || e.contains("169.254")));
    }

    #[test]
    fn observed_ip_is_appended_and_deduped() {
        let eps = assemble_endpoints(1, &[], Some("2001:da8::5"));
        assert!(eps.contains(&"[2001:da8::5]:1".into()));

        let eps = assemble_endpoints(1, &["10.0.0.1".parse().unwrap()], Some("10.0.0.1"));
        assert_eq!(eps.iter().filter(|e| *e == "10.0.0.1:1").count(), 1);

        let eps = assemble_endpoints(7, &[], Some("127.0.0.1"));
        assert_eq!(eps.iter().filter(|e| *e == "127.0.0.1:7").count(), 1);
        assert!(!eps
            .iter()
            .any(|e| e.starts_with("127.0.0.1:") && *e != "127.0.0.1:7"));
    }
}

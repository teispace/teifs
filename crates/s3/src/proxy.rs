//! Reverse proxies: who the client really is when a request comes through a proxy the
//! server trusts.
//!
//! Only a request whose peer is a trusted proxy is looked at. Its forwarding header
//! lists the addresses the request passed through, each proxy appending the one it got
//! it from; walking that list from the right, past the trusted proxies, the first
//! address that isn't one is the client. Anything to its left was written by the client
//! itself, so it's never believed.

use std::{fmt, net::IpAddr, str::FromStr};

use http::HeaderMap;
use ipnet::IpNet;

/// The most addresses of one forwarding header looked at, from the right.
const MAX_HOPS: usize = 20;

/// Which header trusted proxies name the client in. It must be one they append to (or,
/// for `X-Real-IP`, overwrite): a header a proxy passes through untouched is the
/// client's own word.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxyHeader {
    /// `X-Forwarded-For`, which nginx, HAProxy, Traefik, Caddy, Envoy and AWS load
    /// balancers append to; the scheme comes from `X-Forwarded-Proto`.
    #[default]
    XForwardedFor,
    /// RFC 7239's `Forwarded`, each hop with its own `proto`.
    Forwarded,
    /// `X-Real-IP`, one address the proxy sets; the scheme comes from
    /// `X-Forwarded-Proto`.
    XRealIp,
}

impl ProxyHeader {
    /// Its name, as the setting takes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::XForwardedFor => "x-forwarded-for",
            Self::Forwarded => "forwarded",
            Self::XRealIp => "x-real-ip",
        }
    }
}

impl FromStr for ProxyHeader {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::XForwardedFor, Self::Forwarded, Self::XRealIp]
            .into_iter()
            .find(|h| h.name().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| format!("`{s}` isn't x-forwarded-for, forwarded or x-real-ip"))
    }
}

/// The proxies trusted to say who their clients are, and how they say it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    networks: Vec<IpNet>,
    header: ProxyHeader,
}

impl fmt::Display for TrustedProxies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let networks: Vec<String> = self.networks.iter().map(ToString::to_string).collect();
        write!(f, "{} ({})", networks.join(", "), self.header.name())
    }
}

impl TrustedProxies {
    /// Proxies at these addresses or networks (`10.0.0.5`, `10.0.0.0/8`, `fd00::/8`),
    /// naming clients in `header`.
    pub fn new<S: AsRef<str>>(networks: &[S], header: ProxyHeader) -> Result<Self, String> {
        let networks = networks
            .iter()
            .map(|n| {
                let n = n.as_ref().trim();
                n.parse::<IpNet>()
                    .or_else(|_| n.parse::<IpAddr>().map(IpNet::from))
                    .map(|net| net.trunc())
                    .map_err(|_| format!("`{n}` isn't an IP address or network like 10.0.0.0/8"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { networks, header })
    }

    /// Whether any proxy is trusted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    /// The networks trusted, as given.
    #[must_use]
    pub fn networks(&self) -> Vec<String> {
        self.networks.iter().map(ToString::to_string).collect()
    }

    /// The header they name clients in.
    #[must_use]
    pub const fn header(&self) -> ProxyHeader {
        self.header
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(&ip))
    }

    /// The client of a request that came from `peer` with `headers`: `peer` itself
    /// unless it's a trusted proxy.
    #[must_use]
    pub fn client(&self, peer: crate::Client, headers: &HeaderMap) -> crate::Client {
        let Some(ip) = peer.ip.map(|ip| ip.to_canonical()) else {
            return peer;
        };
        if !self.trusts(ip) {
            return peer;
        }
        let hops = match self.header {
            ProxyHeader::XForwardedFor => hops(headers, "x-forwarded-for", |entry| Hop {
                ip: address(entry),
                secure: None,
            }),
            ProxyHeader::XRealIp => hops(headers, "x-real-ip", |entry| Hop {
                ip: address(entry),
                secure: None,
            }),
            ProxyHeader::Forwarded => hops(headers, "forwarded", forwarded),
        };
        // The proxy we're talking to, then each one before it.
        let mut client = Hop {
            ip: Some(ip),
            secure: None,
        };
        for hop in hops.iter().rev().take(MAX_HOPS) {
            let Some(address) = hop.ip else {
                // "unknown", an obfuscated name or garbage: the last proxy that could be
                // trusted is as close to the client as anyone can say.
                break;
            };
            client = *hop;
            if !self.trusts(address) {
                break;
            }
        }
        let secure = match self.header {
            ProxyHeader::Forwarded => client.secure,
            ProxyHeader::XForwardedFor | ProxyHeader::XRealIp => headers
                .get_all("x-forwarded-proto")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .next_back()
                .map(|proto| proto.trim().eq_ignore_ascii_case("https")),
        };
        // The connection's TLS version is the client's only when the client is the
        // proxy itself and nothing says otherwise.
        let own = client.ip == Some(ip) && secure.is_none();
        crate::Client {
            ip: client.ip,
            // Without a word on the scheme, the proxy's own connection decides.
            secure: secure.unwrap_or(peer.secure),
            tls: if own { peer.tls } else { None },
        }
    }
}

/// One address a request came through, and the scheme it was sent there with, if said.
#[derive(Debug, Clone, Copy)]
struct Hop {
    ip: Option<IpAddr>,
    secure: Option<bool>,
}

/// Every comma-separated entry of every `name` header, in order.
fn hops(headers: &HeaderMap, name: &str, parse: impl Fn(&str) -> Hop) -> Vec<Hop> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap_or(","))
        .flat_map(|v| v.split(','))
        .map(|entry| parse(entry.trim()))
        .collect()
}

/// An address as proxies write it: bare, with a port, or in brackets (IPv6).
fn address(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim().trim_matches('"');
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(socket) = entry.parse::<std::net::SocketAddr>() {
        return Some(socket.ip().to_canonical());
    }
    // `[2001:db8::1]` without a port, or `1.2.3.4:80`.
    let bare = entry.strip_prefix('[').and_then(|e| e.strip_suffix(']'));
    let bare = bare.or_else(|| entry.rsplit_once(':').map(|(host, _)| host));
    bare.and_then(|b| b.parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
}

/// One element of a `Forwarded` header: `for=…;proto=…;by=…`.
fn forwarded(element: &str) -> Hop {
    let mut hop = Hop {
        ip: None,
        secure: None,
    };
    for pair in element.split(';') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim().to_ascii_lowercase().as_str() {
            "for" => hop.ip = address(value),
            "proto" => hop.secure = Some(value.eq_ignore_ascii_case("https")),
            _ => {}
        }
    }
    hop
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn peer(ip: &str, secure: bool) -> crate::Client {
        crate::Client {
            ip: Some(ip.parse().unwrap()),
            secure,
            tls: secure.then_some("1.3"),
        }
    }

    fn client(
        proxies: &TrustedProxies,
        from: &str,
        pairs: &[(&'static str, &str)],
    ) -> (String, bool) {
        let client = proxies.client(peer(from, false), &headers(pairs));
        (client.ip.unwrap().to_string(), client.secure)
    }

    #[test]
    fn only_trusted_proxies_are_believed() {
        let proxies =
            TrustedProxies::new(&["10.0.0.0/8", "192.0.2.7"], ProxyHeader::default()).unwrap();
        let spoofed = [
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-proto", "https"),
        ];
        assert_eq!(
            client(&proxies, "198.51.100.1", &spoofed),
            ("198.51.100.1".into(), false)
        );
        assert_eq!(
            client(&proxies, "10.1.2.3", &spoofed),
            ("203.0.113.9".into(), true)
        );
        assert_eq!(
            client(&proxies, "192.0.2.7", &spoofed),
            ("203.0.113.9".into(), true)
        );
        assert_eq!(
            client(&proxies, "192.0.2.8", &spoofed),
            ("192.0.2.8".into(), false)
        );
        // No proxies trusted, nothing is believed.
        let none = TrustedProxies::default();
        assert!(none.is_empty());
        assert_eq!(
            client(&none, "10.1.2.3", &spoofed),
            ("10.1.2.3".into(), false)
        );
        // No peer address, nothing to decide.
        let unknown = crate::Client::default();
        assert_eq!(proxies.client(unknown, &headers(&spoofed)), unknown);
    }

    #[test]
    fn a_tls_version_is_kept_only_for_the_connection_it_describes() {
        let proxies = TrustedProxies::new(&["10.0.0.0/8"], ProxyHeader::XForwardedFor).unwrap();
        let tls = |from: &str, pairs: &[(&'static str, &str)]| {
            proxies.client(peer(from, true), &headers(pairs)).tls
        };
        // A client of its own, or a proxy that says nothing: its own connection's.
        assert_eq!(
            tls("198.51.100.1", &[("x-forwarded-for", "1.1.1.1")]),
            Some("1.3")
        );
        assert_eq!(tls("10.0.0.1", &[]), Some("1.3"));
        // A client the proxy names, or a scheme it states: the proxy's hop says nothing
        // of the client's.
        assert_eq!(tls("10.0.0.1", &[("x-forwarded-for", "203.0.113.9")]), None);
        assert_eq!(tls("10.0.0.1", &[("x-forwarded-proto", "https")]), None);
    }

    #[test]
    fn the_client_is_the_first_untrusted_address_from_the_right() {
        let proxies = TrustedProxies::new(&["10.0.0.0/8"], ProxyHeader::XForwardedFor).unwrap();
        // The client wrote 1.1.1.1 itself; the edge proxy appended its real address.
        let xff = |v| [("x-forwarded-for", v)];
        assert_eq!(
            client(&proxies, "10.0.0.1", &xff("1.1.1.1, 203.0.113.9, 10.0.0.2")).0,
            "203.0.113.9"
        );
        // Several header lines are one list.
        assert_eq!(
            client(
                &proxies,
                "10.0.0.1",
                &[
                    ("x-forwarded-for", "1.1.1.1"),
                    ("x-forwarded-for", "203.0.113.9, 10.0.0.2")
                ]
            )
            .0,
            "203.0.113.9"
        );
        // All trusted: the leftmost.
        assert_eq!(
            client(&proxies, "10.0.0.1", &xff("10.9.9.9, 10.0.0.2")).0,
            "10.9.9.9"
        );
        // Garbage stops the walk at the last trusted proxy.
        assert_eq!(
            client(&proxies, "10.0.0.1", &xff("203.0.113.9, unknown, 10.0.0.2")).0,
            "10.0.0.2"
        );
        assert_eq!(client(&proxies, "10.0.0.1", &xff("nonsense")).0, "10.0.0.1");
        // No header: the proxy itself.
        assert_eq!(client(&proxies, "10.0.0.1", &[]).0, "10.0.0.1");
        // Ports, brackets and IPv4 in IPv6 are understood.
        assert_eq!(
            client(&proxies, "10.0.0.1", &xff("203.0.113.9:4711")).0,
            "203.0.113.9"
        );
        assert_eq!(
            client(&proxies, "10.0.0.1", &xff("[2001:db8::1]:80")).0,
            "2001:db8::1"
        );
        assert_eq!(
            client(&proxies, "10.0.0.1", &xff("[2001:db8::1]")).0,
            "2001:db8::1"
        );
        assert_eq!(
            client(&proxies, "::ffff:10.0.0.1", &xff("::ffff:203.0.113.9")).0,
            "203.0.113.9"
        );
        // Only the last MAX_HOPS addresses are looked at.
        let mut long = vec!["203.0.113.9".to_owned()];
        long.extend((0..MAX_HOPS).map(|i| format!("10.0.0.{i}")));
        assert_eq!(
            client(&proxies, "10.0.0.1", &xff(&long.join(","))).0,
            "10.0.0.0"
        );
    }

    #[test]
    fn the_scheme_comes_from_the_nearest_proxy() {
        let proxies = TrustedProxies::new(&["10.0.0.0/8"], ProxyHeader::XForwardedFor).unwrap();
        let with = |proto| {
            client(
                &proxies,
                "10.0.0.1",
                &[
                    ("x-forwarded-for", "203.0.113.9"),
                    ("x-forwarded-proto", proto),
                ],
            )
            .1
        };
        assert!(with("https"));
        assert!(with("HTTPS"));
        assert!(!with("http"));
        assert!(with("http, https"));
        assert!(!with("https, http"));
        // Unsaid: the proxy's own connection.
        let over_tls = proxies.client(
            peer("10.0.0.1", true),
            &headers(&[("x-forwarded-for", "203.0.113.9")]),
        );
        assert!(over_tls.secure);
    }

    #[test]
    fn forwarded_and_x_real_ip_when_chosen() {
        let proxies = TrustedProxies::new(&["10.0.0.0/8"], ProxyHeader::Forwarded).unwrap();
        let fwd = |v| [("forwarded", v)];
        assert_eq!(
            client(
                &proxies,
                "10.0.0.1",
                &fwd(
                    r#"for=1.1.1.1;proto=http, for="[2001:db8:cafe::17]:4711";proto=https, For=10.0.0.2;Proto=http"#
                )
            ),
            ("2001:db8:cafe::17".into(), true)
        );
        assert_eq!(
            client(
                &proxies,
                "10.0.0.1",
                &fwd("for=_hidden;proto=https, for=10.0.0.2")
            ),
            ("10.0.0.2".into(), false)
        );
        // Values may be quoted strings.
        assert_eq!(
            client(
                &proxies,
                "10.0.0.1",
                &fwd(r#"for="203.0.113.9";proto="https""#)
            ),
            ("203.0.113.9".into(), true)
        );
        // In this mode X-Forwarded-For is the client's own word.
        assert_eq!(
            client(&proxies, "10.0.0.1", &[("x-forwarded-for", "203.0.113.9")]).0,
            "10.0.0.1"
        );
        let real = TrustedProxies::new(&["10.0.0.0/8"], ProxyHeader::XRealIp).unwrap();
        assert_eq!(
            client(
                &real,
                "10.0.0.1",
                &[
                    ("x-real-ip", "203.0.113.9"),
                    ("x-forwarded-for", "1.1.1.1"),
                    ("x-forwarded-proto", "https")
                ]
            ),
            ("203.0.113.9".into(), true)
        );
    }

    #[test]
    fn settings_are_checked() {
        assert!(TrustedProxies::new(&["10.0.0.0/33"], ProxyHeader::default()).is_err());
        assert!(TrustedProxies::new(&["proxy.local"], ProxyHeader::default()).is_err());
        let proxies =
            TrustedProxies::new(&[" 10.1.2.3/8 ", "::1"], ProxyHeader::Forwarded).unwrap();
        assert_eq!(proxies.networks(), ["10.0.0.0/8", "::1/128"]);
        assert_eq!(proxies.to_string(), "10.0.0.0/8, ::1/128 (forwarded)");
        assert_eq!("X-Real-IP".parse::<ProxyHeader>(), Ok(ProxyHeader::XRealIp));
        assert!("via".parse::<ProxyHeader>().is_err());
    }
}

/// Common service names for well-known ports, from the IANA Service Name and
/// Transport Protocol Port Number Registry (public data).
public enum ServiceNames {
    public static func name(port: UInt16, isUDP: Bool) -> String? {
        if isUDP, let n = udp[port] { return n }
        if !isUDP, let n = tcp[port] { return n }
        return shared[port]
    }

    static let shared: [UInt16: String] = [
        7: "echo", 22: "ssh", 53: "domain", 80: "http", 123: "ntp", 143: "imap", 443: "https",
        465: "submissions", 587: "submission", 853: "domain-s", 993: "imaps", 995: "pop3s",
        1194: "openvpn", 1883: "mqtt", 3478: "stun", 3479: "stun", 5060: "sip", 5061: "sips",
        5222: "xmpp-client", 5223: "apple-push", 5228: "google-push", 8080: "http-alt", 8443: "https-alt",
        8883: "secure-mqtt",
    ]

    static let tcp: [UInt16: String] = [
        21: "ftp", 23: "telnet", 25: "smtp", 110: "pop3", 3389: "ms-wbt-server", 5900: "vnc",
    ]

    static let udp: [UInt16: String] = [
        67: "dhcp-server", 68: "dhcp-client", 137: "netbios-ns", 161: "snmp", 500: "isakmp",
        1900: "ssdp", 4500: "ipsec-nat-t", 5353: "mdns", 5355: "llmnr", 51820: "wireguard",
    ]
}

/// Domains Apple uses for its own services, for the "Hide Apple" filter.
public enum AppleDomains {
    public static let registrable: Set<String> = [
        "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "apple-dns.net",
        "aaplimg.com", "cdn-apple.com", "apple-cloudkit.com", "apple.news", "itunes.com",
        "me.com", "mac.com", "apple-mapkit.com", "applemusic.com", "apple-livephotoskit.com",
        "push-apple.com.akadns.net", "safebrowsing.apple", "apple",
    ]

    public static func contains(_ host: String) -> Bool {
        Domain.firstMatch(of: host, in: registrable) != nil
    }
}

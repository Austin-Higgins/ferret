/// Learn mode: short, plain explanations for fields, keyed by the same names the
/// dissector uses (Wireshark's display-filter vocabulary).
public enum Glossary {
    public struct Entry: Hashable, Sendable {
        public var title: String
        public var explanation: String
    }

    public static func entry(for key: String) -> Entry? {
        if let e = entries[key] { return e }
        // Fall back to the protocol prefix, e.g. "tcp.options.sack" → "tcp".
        if let prefix = key.split(separator: ".").first, let e = entries[String(prefix)] { return e }
        return nil
    }

    static let entries: [String: Entry] = [
        "ip": Entry(title: "Internet Protocol", explanation: "The envelope every packet travels in. It carries the sender and receiver addresses."),
        "ipv6": Entry(title: "IPv6", explanation: "The newer version of the Internet Protocol, with much longer addresses."),
        "ip.src": Entry(title: "Source address", explanation: "Who sent this packet. For outgoing traffic, that's your phone's address inside the tunnel."),
        "ip.dst": Entry(title: "Destination address", explanation: "Where this packet is going."),
        "ipv6.src": Entry(title: "Source address", explanation: "Who sent this packet."),
        "ipv6.dst": Entry(title: "Destination address", explanation: "Where this packet is going."),
        "ip.ttl": Entry(title: "Time to live", explanation: "How many routers the packet may pass through before it is thrown away. It stops packets looping forever."),
        "ipv6.hlim": Entry(title: "Hop limit", explanation: "IPv6's name for time to live: how many routers the packet may cross."),
        "ip.id": Entry(title: "Identification", explanation: "A number used to put the pieces back together if a packet is split up on the way."),
        "ip.flags.df": Entry(title: "Don't fragment", explanation: "Asks routers not to split this packet. Used to discover the largest packet a path can carry."),
        "ip.checksum": Entry(title: "Header checksum", explanation: "A quick sum that lets routers spot a corrupted header."),
        "ip.proto": Entry(title: "Protocol", explanation: "What's inside: 6 means TCP, 17 means UDP, 1 means ICMP."),
        "ipv6.nxt": Entry(title: "Next header", explanation: "What comes after the IPv6 header: 6 means TCP, 17 means UDP, 58 means ICMPv6."),
        "ipv6.flow": Entry(title: "Flow label", explanation: "An optional tag that helps routers keep packets from the same conversation together."),
        "tcp": Entry(title: "TCP", explanation: "A reliable, ordered stream between two programs. Web pages and most apps use it."),
        "tcp.srcport": Entry(title: "Source port", explanation: "Which conversation on the sending device this packet belongs to."),
        "tcp.dstport": Entry(title: "Destination port", explanation: "Which service on the other end: 443 is HTTPS, 80 is plain HTTP."),
        "tcp.seq_raw": Entry(title: "Sequence number", explanation: "Numbers every byte sent so the receiver can put data back in order."),
        "tcp.ack_raw": Entry(title: "Acknowledgment number", explanation: "Tells the other side which bytes arrived safely."),
        "tcp.flags": Entry(title: "Flags", explanation: "SYN opens a connection, ACK confirms data, FIN closes politely and RST hangs up abruptly."),
        "tcp.window_size_value": Entry(title: "Window", explanation: "How much more data the sender is ready to receive right now."),
        "tcp.len": Entry(title: "Segment length", explanation: "How many bytes of actual data this packet carries."),
        "tcp.options.mss_val": Entry(title: "Maximum segment size", explanation: "The biggest chunk of data this side wants to receive in one packet."),
        "udp": Entry(title: "UDP", explanation: "Fire-and-forget messages with no built-in delivery guarantee. DNS and QUIC use it."),
        "udp.length": Entry(title: "Length", explanation: "Size of the UDP header plus its data."),
        "icmp": Entry(title: "ICMP", explanation: "Control messages such as ping and 'destination unreachable'."),
        "icmpv6": Entry(title: "ICMPv6", explanation: "IPv6's control messages, including neighbour discovery on the local network."),
        "dns": Entry(title: "DNS", explanation: "The internet's phone book: turns names like example.com into addresses."),
        "dns.id": Entry(title: "Transaction ID", explanation: "Matches each answer to the question that asked for it."),
        "dns.qry.name": Entry(title: "Query name", explanation: "The name your phone asked about."),
        "dns.qry.type": Entry(title: "Query type", explanation: "What was asked for: 1 (A) is an IPv4 address, 28 (AAAA) is IPv6, 65 (HTTPS) is service details."),
        "dns.flags.rcode": Entry(title: "Reply code", explanation: "0 means success. 3 means the name doesn't exist."),
        "dns.a": Entry(title: "IPv4 address", explanation: "An address the name resolved to."),
        "dns.aaaa": Entry(title: "IPv6 address", explanation: "An IPv6 address the name resolved to."),
        "dns.cname": Entry(title: "CNAME", explanation: "An alias: the name points to another name, often a CDN."),
        "dns.resp.ttl": Entry(title: "Time to live", explanation: "How many seconds the answer may be cached before asking again."),
        "tls": Entry(title: "TLS", explanation: "The encryption behind HTTPS. Ferret can see the handshake but not the encrypted content."),
        "tls.record.content_type": Entry(title: "Content type", explanation: "22 is handshake, 23 is encrypted application data, 21 is an alert."),
        "tls.record.opaque_type": Entry(title: "Content type", explanation: "In TLS 1.3 every encrypted record claims to be application data, hiding what it really is."),
        "tls.handshake.type": Entry(title: "Handshake type", explanation: "1 is Client Hello, the first message your phone sends to start encryption. 2 is the server's reply."),
        "tls.handshake.extensions_server_name": Entry(title: "Server name (SNI)", explanation: "The site name your phone asked for, sent before encryption starts. It is why Ferret can name encrypted connections."),
        "tls.handshake.extensions_alpn_str": Entry(title: "ALPN", explanation: "Which protocol will run inside the encryption, such as h2 (HTTP/2) or h3 (HTTP/3)."),
        "tls.handshake.ciphersuite": Entry(title: "Cipher suite", explanation: "A combination of encryption algorithms. The client offers a list and the server picks one."),
        "tls.handshake.version": Entry(title: "Version", explanation: "A legacy version number. TLS 1.3 hides its real version in an extension for compatibility."),
        "tls.handshake.extensions.supported_version": Entry(title: "Supported versions", explanation: "The TLS versions offered or chosen. 0x0304 is TLS 1.3."),
        "quic": Entry(title: "QUIC", explanation: "A newer encrypted transport over UDP, used by HTTP/3. It sets up faster than TCP plus TLS."),
        "quic.dcid": Entry(title: "Destination connection ID", explanation: "Identifies the connection even if your phone switches networks."),
        "quic.scid": Entry(title: "Source connection ID", explanation: "The ID the sender wants to be reached at."),
        "quic.long.packet_type": Entry(title: "Packet type", explanation: "0 is Initial, the first packet of a connection. 2 is Handshake."),
        "quic.version": Entry(title: "Version", explanation: "0x00000001 is QUIC version 1."),
        "http": Entry(title: "HTTP", explanation: "Unencrypted web traffic. Anyone on the network path can read it."),
        "http.host": Entry(title: "Host", explanation: "The site this request is for."),
        "http.request.method": Entry(title: "Method", explanation: "What the request wants to do: GET fetches, POST sends data."),
        "http.request.uri": Entry(title: "Request URI", explanation: "The path and query being requested."),
        "http.response.code": Entry(title: "Status code", explanation: "200 means OK, 404 means not found, 3xx redirects."),
        "frame.len": Entry(title: "Frame length", explanation: "The packet's total size in bytes."),
    ]
}

import FerretParsers

/// Collar tags shown on traffic rows.
public enum ProtocolTag: String, Codable, CaseIterable, Hashable, Sendable {
    case dns = "DNS"
    case tls = "TLS"
    case quic = "QUIC"
    case http = "HTTP"
}

public enum TransportKind: String, Codable, Hashable, Sendable {
    case tcp = "TCP"
    case udp = "UDP"
    case icmp = "ICMP"
    case other = "IP"
}

/// Direction relative to the phone.
public typealias PacketDirection = CaptureDirection

public struct Endpoint: Hashable, Codable, Sendable, CustomStringConvertible {
    public var address: IPAddress
    public var port: UInt16

    public init(address: IPAddress, port: UInt16) {
        self.address = address
        self.port = port
    }

    public var description: String {
        address.isV4 ? "\(address):\(port)" : "[\(address)]:\(port)"
    }
}

public struct FlowKey: Hashable, Codable, Sendable {
    public var transport: TransportKind
    /// The phone's side.
    public var local: Endpoint
    public var remote: Endpoint
}

/// One point on a connection's timeline.
public struct PacketSample: Hashable, Codable, Sendable {
    public var timestamp: CaptureTimestamp
    public var direction: PacketDirection
    /// IP datagram length.
    public var size: Int
    /// Index of the frame in the capture archive, for hex view and export.
    public var frameIndex: Int
    public var tcpFlags: UInt16?
}

public struct HTTPRequestSummary: Hashable, Codable, Sendable {
    public var timestamp: CaptureTimestamp
    public var method: String
    public var host: String?
    public var path: String
}

/// A DNS question and, once seen, its answer.
public struct DNSLookup: Identifiable, Hashable, Codable, Sendable {
    public var id: Int
    public var name: String
    public var type: UInt16
    public var transactionID: UInt16
    public var resolver: IPAddress
    public var queriedAt: CaptureTimestamp
    public var answeredAt: CaptureTimestamp?
    public var addresses: [IPAddress]
    public var cnames: [String]
    public var responseCode: UInt8?
    public var frameIndices: [Int]

    public var typeName: String { DNSRecordType(rawValue: type).description }

    /// Round-trip time in milliseconds, when answered.
    public var latencyMilliseconds: Double? {
        answeredAt.map { Double($0.nanoseconds(since: queriedAt)) / 1_000_000 }
    }

    public var failed: Bool { (responseCode ?? 0) != 0 }
}

public struct Connection: Identifiable, Hashable, Codable, Sendable {
    public var id: Int
    public var key: FlowKey
    public var firstSeen: CaptureTimestamp
    public var lastSeen: CaptureTimestamp
    public var packetsOut = 0
    public var packetsIn = 0
    public var bytesOut = 0
    public var bytesIn = 0
    public var tags: Set<ProtocolTag> = []
    public var serverName: String?
    public var alpn: [String] = []
    public var tlsVersion: String?
    public var encryptedClientHello = false
    public var quicVersion: String?
    public var httpRequests: [HTTPRequestSummary] = []
    /// The DNS name that resolved to the remote address before this connection opened.
    public var dnsName: String?
    public var dnsLookupID: Int?
    /// Names queried on this flow, when it is itself DNS.
    public var dnsQueries: [String] = []
    public var samples: [PacketSample] = []
    public var droppedSamples = 0
    public var closed = false

    public init(id: Int, key: FlowKey, firstSeen: CaptureTimestamp) {
        self.id = id
        self.key = key
        self.firstSeen = firstSeen
        self.lastSeen = firstSeen
    }

    /// The best name for the remote side: TLS/QUIC server name, then HTTP Host, then DNS.
    public var host: String? {
        serverName ?? httpRequests.first?.host ?? dnsName
    }

    public var displayName: String { host ?? key.remote.address.description }

    public var packets: Int { packetsOut + packetsIn }
    public var bytes: Int { bytesOut + bytesIn }

    public var durationSeconds: Double {
        Double(lastSeen.nanoseconds(since: firstSeen)) / 1e9
    }

    public var serviceName: String? {
        ServiceNames.name(port: key.remote.port, isUDP: key.transport == .udp)
    }
}

public struct CaptureStats: Hashable, Codable, Sendable {
    public var packets = 0
    public var bytes = 0
    public var connections = 0
    public var dnsLookups = 0
    public var firstPacket: CaptureTimestamp?
    public var lastPacket: CaptureTimestamp?

    public init() {}
}

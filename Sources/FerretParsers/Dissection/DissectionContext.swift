/// Per-capture state that lets the dissector reassemble TCP streams, so TLS
/// records split across segments are reported on the frame that completes
/// them, as Wireshark does. Feed frames in capture order.
public final class DissectionContext {
    struct Endpoint: Hashable {
        var address: IPAddress
        var port: UInt16
    }

    struct Direction: Hashable {
        var source: Endpoint
        var destination: Endpoint
    }

    struct Connection: Hashable {
        var a: Endpoint
        var b: Endpoint

        init(_ x: Endpoint, _ y: Endpoint) {
            if (x.address, x.port) < (y.address, y.port) { a = x; b = y } else { a = y; b = x }
        }
    }

    struct StreamState {
        var reassembler = TCPStreamReassembler()
        var buffer: [UInt8] = []
        var isTLS: Bool?
        var afterChangeCipherSpec = false
    }

    private var streams: [Direction: StreamState] = [:]
    private var tlsVersions: [Connection: TLSVersionState] = [:]
    /// Streams with more buffered bytes than this stop being dissected as TLS.
    public var maxBufferedBytes = 128 * 1024

    public init() {}

    /// Returns the TLS records completed by this segment, or nil if the stream is not TLS.
    func tlsRecords(ip: IPPacket, tcp: TCPSegment) -> [TLSRecord]? {
        let dir = Direction(
            source: Endpoint(address: ip.source, port: tcp.sourcePort),
            destination: Endpoint(address: ip.destination, port: tcp.destinationPort))
        var state = streams[dir] ?? StreamState()
        defer { streams[dir] = state }
        let fresh = state.reassembler.accept(sequence: tcp.sequenceNumber, flags: tcp.flags, payload: tcp.payload)
        if state.isTLS == false { return nil }
        state.buffer.append(contentsOf: fresh)
        if state.isTLS == nil {
            guard state.buffer.count >= 3 else { return state.buffer.isEmpty ? nil : [] }
            state.isTLS = TLS.looksLikeTLS(state.buffer[...])
            if state.isTLS == false {
                state.buffer = []
                return nil
            }
        }
        let records = TLS.records(in: state.buffer[...]).map {
            TLSRecord(contentType: $0.contentType, version: $0.version, fragment: ArraySlice(Array($0.fragment)))
        }
        let consumed = records.reduce(0) { $0 + 5 + $1.fragment.count }
        state.buffer.removeFirst(consumed)
        if state.buffer.count > maxBufferedBytes {
            state.isTLS = false
            state.buffer = []
        }
        return records
    }

    func afterChangeCipherSpec(ip: IPPacket, tcp: TCPSegment) -> Bool {
        streams[direction(ip, tcp)]?.afterChangeCipherSpec ?? false
    }

    func setAfterChangeCipherSpec(ip: IPPacket, tcp: TCPSegment) {
        streams[direction(ip, tcp), default: StreamState()].afterChangeCipherSpec = true
    }

    func tlsVersionState(ip: IPPacket, tcp: TCPSegment) -> TLSVersionState {
        tlsVersions[connection(ip, tcp)] ?? TLSVersionState()
    }

    func setTLSVersionState(_ state: TLSVersionState, ip: IPPacket, tcp: TCPSegment) {
        tlsVersions[connection(ip, tcp)] = state
    }

    private func direction(_ ip: IPPacket, _ tcp: TCPSegment) -> Direction {
        Direction(
            source: Endpoint(address: ip.source, port: tcp.sourcePort),
            destination: Endpoint(address: ip.destination, port: tcp.destinationPort))
    }

    private func connection(_ ip: IPPacket, _ tcp: TCPSegment) -> Connection {
        Connection(Endpoint(address: ip.source, port: tcp.sourcePort), Endpoint(address: ip.destination, port: tcp.destinationPort))
    }
}

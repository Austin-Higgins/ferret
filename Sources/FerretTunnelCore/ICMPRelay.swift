import FerretParsers
import Foundation

#if canImport(Darwin)
import Darwin

/// Relays ICMP/ICMPv6 echo requests (ping) using unprivileged ICMP datagram
/// sockets, and rebuilds the replies for the phone. Other ICMP types are dropped.
public final class ICMPRelay {
    public let queue: DispatchQueue
    public var output: (([UInt8]) -> Void)?

    private var sockets: [Bool: (fd: Int32, source: DispatchSourceRead)] = [:]
    /// (destination, identifier) → phone address, so replies go to the right place.
    private var pending: [PendingKey: IPAddress] = [:]

    struct PendingKey: Hashable {
        var remote: IPAddress
        var identifier: UInt16
    }

    public init(queue: DispatchQueue) {
        self.queue = queue
    }

    public func stop() {
        for (_, s) in sockets {
            s.source.cancel()
        }
        sockets.removeAll()
        pending.removeAll()
    }

    /// Returns true if the packet was an echo request and was sent.
    @discardableResult
    public func input(ip: IPPacket) -> Bool {
        let v6 = ip.version == 6
        guard let icmp = try? ICMPMessage.parse(ip.payload, isV6: v6) else { return false }
        let echoRequest: UInt8 = v6 ? 128 : 8
        guard icmp.type == echoRequest, icmp.body.count >= 4, let fd = socketFor(v6: v6) else { return false }
        let identifier = UInt16(icmp.body[icmp.body.startIndex]) << 8 | UInt16(icmp.body[icmp.body.startIndex + 1])
        pending[PendingKey(remote: ip.destination, identifier: identifier)] = ip.source

        // The kernel fills in the checksum (and, on Darwin, may rewrite the identifier).
        var message = Array(ip.payload)
        message[2] = 0
        message[3] = 0
        if !v6 {
            let sum = InternetChecksum.checksum(message)
            message[2] = UInt8(sum >> 8)
            message[3] = UInt8(sum & 0xFF)
        }
        var storage = sockaddr_storage()
        let length = Self.fill(&storage, address: ip.destination)
        let sent = withUnsafePointer(to: &storage) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, message, message.count, 0, $0, length)
            }
        }
        return sent == message.count
    }

    private func socketFor(v6: Bool) -> Int32? {
        if let s = sockets[v6] { return s.fd }
        let fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP)
        guard fd >= 0 else { return nil }
        let flags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.drain(fd: fd, v6: v6) }
        source.setCancelHandler { close(fd) }
        source.resume()
        sockets[v6] = (fd, source)
        return fd
    }

    private func drain(fd: Int32, v6: Bool) {
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while true {
            var storage = sockaddr_storage()
            var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &storage) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(fd, &buffer, buffer.count, 0, $0, &length)
                }
            }
            guard n > 0 else { return }
            var reply = Array(buffer[0..<n])
            // IPv4 ICMP datagram sockets deliver the IP header too; strip it.
            if !v6, let first = reply.first, first >> 4 == 4 {
                let ihl = Int(first & 0x0F) * 4
                guard reply.count > ihl else { continue }
                reply = Array(reply[ihl...])
            }
            guard reply.count >= 8, let remote = Self.address(from: storage) else { continue }
            let identifier = UInt16(reply[4]) << 8 | UInt16(reply[5])
            guard let phone = pending[PendingKey(remote: remote, identifier: identifier)] else { continue }
            output?(Self.packet(from: remote, to: phone, icmp: reply, v6: v6))
        }
    }

    static func packet(from source: IPAddress, to destination: IPAddress, icmp: [UInt8], v6: Bool) -> [UInt8] {
        var body = icmp
        body[2] = 0
        body[3] = 0
        let sum = v6
            ? InternetChecksum.transportChecksum(source: source, destination: destination, protocolNumber: IPProtocolNumber.icmpv6, segment: body)
            : InternetChecksum.checksum(body)
        body[2] = UInt8(sum >> 8)
        body[3] = UInt8(sum & 0xFF)
        let header = v6
            ? IPPacketBuilder.ipv6Header(source: source, destination: destination, nextHeader: IPProtocolNumber.icmpv6, payloadLength: body.count)
            : IPPacketBuilder.ipv4Header(source: source, destination: destination, protocolNumber: IPProtocolNumber.icmp, payloadLength: body.count)
        return header + body
    }

    static func fill(_ storage: inout sockaddr_storage, address: IPAddress) -> socklen_t {
        withUnsafeMutablePointer(to: &storage) { ptr -> socklen_t in
            switch address {
            case .v4:
                return ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee.sin_family = sa_family_t(AF_INET)
                    sin.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    withUnsafeMutableBytes(of: &sin.pointee.sin_addr) { $0.copyBytes(from: address.bytes) }
                    return socklen_t(MemoryLayout<sockaddr_in>.size)
                }
            case .v6:
                return ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                    sin6.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    withUnsafeMutableBytes(of: &sin6.pointee.sin6_addr) { $0.copyBytes(from: address.bytes) }
                    return socklen_t(MemoryLayout<sockaddr_in6>.size)
                }
            }
        }
    }

    static func address(from storage: sockaddr_storage) -> IPAddress? {
        var storage = storage
        let family = Int32(storage.ss_family)
        return withUnsafePointer(to: &storage) { ptr -> IPAddress? in
            switch family {
            case AF_INET:
                return ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    withUnsafeBytes(of: sin.pointee.sin_addr) { IPAddress(bytes: $0) }
                }
            case AF_INET6:
                return ptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    withUnsafeBytes(of: sin6.pointee.sin6_addr) { IPAddress(bytes: $0) }
                }
            default:
                return nil
            }
        }
    }
}
#endif

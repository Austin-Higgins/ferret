import FerretKit
import FerretParsers
import FerretTunnelCore
import Foundation
import NetworkExtension
import os

/// Ferret's packet tunnel. It only captures and forwards: every packet is written
/// to the capture segments untouched and relayed to its real destination.
/// Parsing, storage management and display all happen in the app.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "Ferret", category: "Tunnel")
    private let queue = DispatchQueue(label: "ferret.tunnel", qos: .userInitiated)

    private var tcp: TCPRelay?
    private var udp: UDPRelay?
    private var icmp: ICMPRelay?
    private var router: PacketRouter?
    private var writer: CaptureSegmentWriter?
    private var status: SharedCaptureStatus?
    private var housekeeping: DispatchSourceTimer?

    private var outgoing: [Data] = []
    private var outgoingProtocols: [NSNumber] = []
    private var flushScheduled = false
    private var running = false

    static let tunnelIPv4 = "10.111.0.2"
    static let tunnelIPv6 = "fd66:6572:7265::2"

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let sessionID = (options?[SharedContainer.StartOption.sessionID] as? String) ?? UUID().uuidString
        let cap = (options?[SharedContainer.StartOption.storageCap] as? NSNumber)?.intValue ?? FerretSettings.storageCapBytes
        do {
            let status = try SharedCaptureStatus(url: SharedContainer.statusURL)
            status.state = .starting
            self.status = status
            writer = try CaptureSegmentWriter(directory: SharedContainer.captureDirectory(sessionID: sessionID), storageCap: cap)
        } catch {
            log.error("Could not open capture storage: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
            return
        }

        // Read the real resolvers before our settings replace them.
        let detected = SystemResolvers.current().filter { !$0.isMulticast }
        let resolvers = detected.isEmpty ? SystemResolvers.fallback : detected

        setTunnelNetworkSettings(Self.settings(resolvers: resolvers)) { [weak self] error in
            guard let self else { return }
            if let error {
                self.status?.state = .failed
                completionHandler(error)
                return
            }
            self.queue.async {
                do {
                    try self.startRelays()
                } catch {
                    self.status?.state = .failed
                    completionHandler(error)
                    return
                }
                self.status?.beginSession(id: UInt64(truncatingIfNeeded: sessionID.hashValue))
                self.running = true
                completionHandler(nil)
                self.readPackets()
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.running = false
            self.housekeeping?.cancel()
            self.tcp?.stop()
            self.udp?.stop()
            self.icmp?.stop()
            try? self.writer?.close()
            self.status?.store(.bytesOnDisk, UInt64(self.writer?.bytesOnDisk ?? 0))
            self.status?.state = .idle
            completionHandler()
        }
    }

    /// The app asks for a flush before reading so it sees the latest packets.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        queue.async {
            try? self.writer?.flush()
            completionHandler?(Data("ok".utf8))
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        queue.async {
            try? self.writer?.flush()
            completionHandler()
        }
    }

    // MARK: - Setup

    static func settings(resolvers: [IPAddress]) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let v4 = NEIPv4Settings(addresses: [tunnelIPv4], subnetMasks: ["255.255.255.0"])
        // Host routes make sure DNS to a LAN resolver still enters the tunnel.
        v4.includedRoutes = [NEIPv4Route.default()] + resolvers.filter(\.isV4).map {
            NEIPv4Route(destinationAddress: $0.description, subnetMask: "255.255.255.255")
        }
        settings.ipv4Settings = v4

        let v6 = NEIPv6Settings(addresses: [tunnelIPv6], networkPrefixLengths: [64])
        v6.includedRoutes = [NEIPv6Route.default()] + resolvers.filter { !$0.isV4 }.map {
            NEIPv6Route(destinationAddress: $0.description, networkPrefixLength: 128)
        }
        settings.ipv6Settings = v6

        // Same resolvers as before, so lookups are captured but answered unchanged.
        let dns = NEDNSSettings(servers: resolvers.map(\.description))
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = 1500
        return settings
    }

    private func startRelays() throws {
        let factory = NetworkUpstreamFactory(queue: queue)
        let tcp = TCPRelay(factory: factory, queue: queue)
        let udp = UDPRelay(factory: factory, queue: queue)
        tcp.output = { [weak self] packet in self?.sendToPhone(packet) }
        udp.output = { [weak self] packet in self?.sendToPhone(packet) }
        tcp.onFlowOpened = { [weak self] _ in self?.status?.add(.connections, 1) }
        udp.onFlowOpened = { [weak self] _ in self?.status?.add(.connections, 1) }
        try tcp.start()
        udp.start()
        self.tcp = tcp
        self.udp = udp
        let icmp = ICMPRelay(queue: queue)
        icmp.output = { [weak self] packet in self?.sendToPhone(packet) }
        self.icmp = icmp
        let router = PacketRouter(tcp: tcp, udp: udp)
        router.icmp = { [weak icmp] ip in icmp?.input(ip: ip) ?? false }
        self.router = router

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in self?.tickHousekeeping() }
        timer.resume()
        housekeeping = timer
    }

    // MARK: - Packet paths

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                guard self.running else { return }
                let now = CaptureTimestamp(date: Date())
                for data in packets {
                    let bytes = [UInt8](data)
                    self.record(bytes, direction: .outbound, at: now)
                    self.router?.routeFromPhone(bytes)
                }
                self.readPackets()
            }
        }
    }

    private func sendToPhone(_ packet: [UInt8]) {
        guard let first = packet.first else { return }
        record(packet, direction: .inbound, at: CaptureTimestamp(date: Date()))
        outgoing.append(Data(packet))
        outgoingProtocols.append(NSNumber(value: first >> 4 == 6 ? AF_INET6 : AF_INET))
        if !flushScheduled {
            flushScheduled = true
            queue.async { self.flushToPhone() }
        }
    }

    private func flushToPhone() {
        flushScheduled = false
        guard !outgoing.isEmpty else { return }
        packetFlow.writePackets(outgoing, withProtocols: outgoingProtocols)
        outgoing.removeAll(keepingCapacity: true)
        outgoingProtocols.removeAll(keepingCapacity: true)
    }

    private func record(_ packet: [UInt8], direction: CaptureDirection, at time: CaptureTimestamp) {
        status?.add(.packets, 1)
        status?.add(.bytes, UInt64(packet.count))
        do {
            try writer?.append(packet[...], timestamp: time, direction: direction)
        } catch {
            status?.add(.droppedPackets, 1)
        }
    }

    private func tickHousekeeping() {
        try? writer?.flush()
        status?.store(.lastPacketAtNanos, UInt64(Date().timeIntervalSince1970 * 1e9))
        status?.store(.bytesOnDisk, UInt64(writer?.bytesOnDisk ?? 0))
    }
}

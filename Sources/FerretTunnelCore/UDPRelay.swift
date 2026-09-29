import FerretParsers
import Foundation

/// Relays UDP datagrams (DNS, QUIC, NTP...) without a TCP/IP stack: each
/// five-tuple gets an upstream socket, and replies are wrapped in fresh IP/UDP
/// headers addressed back to the phone.
public final class UDPRelay {
    final class Flow {
        let endpoints: FlowEndpoints
        let upstream: UDPUpstream
        var lastActivity: DispatchTime

        init(endpoints: FlowEndpoints, upstream: UDPUpstream) {
            self.endpoints = endpoints
            self.upstream = upstream
            self.lastActivity = .now()
        }
    }

    public let queue: DispatchQueue
    public var output: (([UInt8]) -> Void)?
    public var onFlowOpened: ((FlowEndpoints) -> Void)?
    public var maxFlows = 512
    public var idleTimeout: DispatchTimeInterval = .seconds(60)

    private let factory: UpstreamFactory
    private var flows: [FlowEndpoints: Flow] = [:]
    private var sweeper: DispatchSourceTimer?

    public init(factory: UpstreamFactory, queue: DispatchQueue) {
        self.factory = factory
        self.queue = queue
    }

    public var activeFlows: Int { flows.count }

    public func start() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .seconds(10), repeating: .seconds(10))
        t.setEventHandler { [weak self] in self?.sweep() }
        t.resume()
        sweeper = t
    }

    public func stop() {
        sweeper?.cancel()
        sweeper = nil
        for flow in flows.values { flow.upstream.cancel() }
        flows.removeAll()
    }

    /// Handles one UDP packet from the phone.
    public func input(ip: IPPacket, udp: UDPDatagram) {
        dispatchPrecondition(condition: .onQueue(queue))
        let endpoints = FlowEndpoints(
            source: ip.source, sourcePort: udp.sourcePort,
            destination: ip.destination, destinationPort: udp.destinationPort)
        let flow: Flow
        if let existing = flows[endpoints] {
            flow = existing
        } else {
            if flows.count >= maxFlows { evictOldest() }
            let upstream = factory.makeUDP(to: endpoints)
            flow = Flow(endpoints: endpoints, upstream: upstream)
            flows[endpoints] = flow
            upstream.onReceive = { [weak self, weak flow] datagram in
                guard let self, let flow else { return }
                flow.lastActivity = .now()
                self.output?(IPPacketBuilder.udpPacket(
                    source: flow.endpoints.destination, sourcePort: flow.endpoints.destinationPort,
                    destination: flow.endpoints.source, destinationPort: flow.endpoints.sourcePort,
                    payload: datagram))
            }
            upstream.onClose = { [weak self, weak flow] _ in
                guard let self, let flow else { return }
                self.flows[flow.endpoints] = nil
            }
            onFlowOpened?(endpoints)
            upstream.start()
        }
        flow.lastActivity = .now()
        flow.upstream.send(Array(udp.payload))
    }

    private func sweep() {
        let now = DispatchTime.now()
        for (key, flow) in flows where flow.lastActivity + idleTimeout < now {
            flow.upstream.cancel()
            flows[key] = nil
        }
    }

    private func evictOldest() {
        guard let oldest = flows.min(by: { $0.value.lastActivity < $1.value.lastActivity }) else { return }
        oldest.value.upstream.cancel()
        flows[oldest.key] = nil
    }
}

/// Splits packets from the phone between the TCP and UDP relays.
public final class PacketRouter {
    public let tcp: TCPRelay
    public let udp: UDPRelay
    public private(set) var droppedPackets = 0

    public init(tcp: TCPRelay, udp: UDPRelay) {
        self.tcp = tcp
        self.udp = udp
    }

    public func routeFromPhone(_ packet: [UInt8]) {
        guard let ip = try? IPPacket.parse(packet) else {
            droppedPackets += 1
            return
        }
        switch ip.protocolNumber {
        case IPProtocolNumber.tcp:
            tcp.input(packet)
        case IPProtocolNumber.udp where ip.fragmentOffset == 0 && !ip.moreFragments:
            guard let datagram = try? UDPDatagram.parse(ip.payload) else {
                droppedPackets += 1
                return
            }
            udp.input(ip: ip, udp: datagram)
        default:
            // ICMP and fragmented UDP can't be relayed without raw sockets.
            droppedPackets += 1
        }
    }
}

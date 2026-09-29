#if canImport(Network)
import FerretParsers
import Foundation
import Network

/// Real connections opened by the extension. The extension's own sockets bypass
/// its tunnel, so these go straight out over Wi-Fi or cellular.
public final class NetworkUpstreamFactory: UpstreamFactory {
    let queue: DispatchQueue

    public init(queue: DispatchQueue) {
        self.queue = queue
    }

    public func makeTCP(to endpoints: FlowEndpoints) -> TCPUpstream {
        NWTCPUpstream(endpoints: endpoints, queue: queue)
    }

    public func makeUDP(to endpoints: FlowEndpoints) -> UDPUpstream {
        NWUDPUpstream(endpoints: endpoints, queue: queue)
    }

    static func endpoint(_ e: FlowEndpoints) -> NWEndpoint {
        let host: NWEndpoint.Host
        switch e.destination {
        case .v4: host = .ipv4(IPv4Address(Data(e.destination.bytes))!)
        case .v6: host = .ipv6(IPv6Address(Data(e.destination.bytes))!)
        }
        return .hostPort(host: host, port: NWEndpoint.Port(rawValue: e.destinationPort) ?? .any)
    }
}

final class NWTCPUpstream: TCPUpstream {
    var onReady: ((Error?) -> Void)?
    var onReceive: (([UInt8]) -> Void)?
    var onClose: ((Error?) -> Void)?

    private let connection: NWConnection
    private let queue: DispatchQueue
    private var receiving = false
    private var reportedReady = false
    private var finished = false

    init(endpoints: FlowEndpoints, queue: DispatchQueue) {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = 15
        let params = NWParameters(tls: nil, tcp: tcp)
        params.preferNoProxies = true
        connection = NWConnection(to: NetworkUpstreamFactory.endpoint(endpoints), using: params)
        self.queue = queue
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if !self.reportedReady {
                    self.reportedReady = true
                    self.onReady?(nil)
                }
            case .failed(let error):
                if !self.reportedReady {
                    self.reportedReady = true
                    self.onReady?(error)
                } else {
                    self.onClose?(error)
                }
            case .cancelled:
                if !self.finished { self.onClose?(nil) }
                self.finished = true
            case .waiting(let error):
                // No route right now; fail fast rather than hang the app's connection.
                if !self.reportedReady {
                    self.reportedReady = true
                    self.onReady?(error)
                    self.connection.cancel()
                }
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func send(_ bytes: [UInt8], completion: @escaping (Error?) -> Void) {
        connection.send(content: Data(bytes), completion: .contentProcessed { error in completion(error) })
    }

    func receiveMore() {
        guard !receiving, !finished else { return }
        receiving = true
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.receiving = false
            if let data, !data.isEmpty { self.onReceive?([UInt8](data)) }
            if isComplete {
                self.onReceive?([])
            } else if let error {
                self.onClose?(error)
            }
        }
    }

    func shutdownWrite() {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
    }

    func cancel() {
        finished = true
        connection.cancel()
    }
}

final class NWUDPUpstream: UDPUpstream {
    var onReceive: (([UInt8]) -> Void)?
    var onClose: ((Error?) -> Void)?

    private let connection: NWConnection
    private let queue: DispatchQueue
    private var pending: [[UInt8]] = []
    private var ready = false

    init(endpoints: FlowEndpoints, queue: DispatchQueue) {
        connection = NWConnection(to: NetworkUpstreamFactory.endpoint(endpoints), using: .udp)
        self.queue = queue
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.ready = true
                for d in self.pending { self.transmit(d) }
                self.pending = []
                self.receiveLoop()
            case .failed(let error):
                self.onClose?(error)
            case .cancelled:
                self.onClose?(nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func send(_ datagram: [UInt8]) {
        if ready {
            transmit(datagram)
        } else if pending.count < 32 {
            pending.append(datagram)
        }
    }

    private func transmit(_ datagram: [UInt8]) {
        connection.send(content: Data(datagram), completion: .idempotent)
    }

    private func receiveLoop() {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.onReceive?([UInt8](data)) }
            if error == nil { self.receiveLoop() }
        }
    }

    func cancel() {
        connection.cancel()
    }
}
#endif

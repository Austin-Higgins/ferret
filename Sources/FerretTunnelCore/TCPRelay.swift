import CLwIP
import FerretParsers
import Foundation

/// Terminates the phone's TCP connections in lwIP and relays each one to a real
/// connection opened with an `UpstreamFactory`. Confined to one serial queue.
public final class TCPRelay {
    public struct Limits: Sendable {
        /// Connections beyond this are reset, protecting the extension's memory.
        public var maxConnections = 768
        /// Bytes from the server buffered while the phone's window is full.
        public var maxPendingToPhone = 256 * 1024

        public init() {}
    }

    final class Flow {
        let id: UInt
        let pcb: UnsafeMutableRawPointer
        let endpoints: FlowEndpoints
        let upstream: TCPUpstream
        var connected = false
        /// Phone → server bytes waiting for the upstream to connect or drain.
        var toServer: [UInt8] = []
        var sendingToServer = false
        var phoneClosed = false
        /// Server → phone bytes waiting for lwIP send buffer space.
        var toPhone: [UInt8] = []
        var serverClosed = false
        var receivePaused = false

        init(id: UInt, pcb: UnsafeMutableRawPointer, endpoints: FlowEndpoints, upstream: TCPUpstream) {
            self.id = id
            self.pcb = pcb
            self.endpoints = endpoints
            self.upstream = upstream
        }
    }

    public let queue: DispatchQueue
    public var limits = Limits()
    /// Emits packets for the phone.
    public var output: (([UInt8]) -> Void)?
    /// Reports new and finished flows (for counters and logs).
    public var onFlowOpened: ((FlowEndpoints) -> Void)?
    public var onFlowClosed: ((FlowEndpoints) -> Void)?

    private let factory: UpstreamFactory
    private var flows: [UInt: Flow] = [:]
    private var nextID: UInt = 1
    private var timer: DispatchSourceTimer?
    private var started = false

    public init(factory: UpstreamFactory, queue: DispatchQueue) {
        self.factory = factory
        self.queue = queue
    }

    public var activeFlows: Int { flows.count }

    /// Starts lwIP. lwIP is process-global, so only one relay may run at a time.
    public func start() throws {
        dispatchPrecondition(condition: .onQueue(queue))
        var callbacks = ferret_tcp_callbacks()
        callbacks.context = Unmanaged.passUnretained(self).toOpaque()
        callbacks.output = { context, packet, length in
            guard let context, let packet else { return }
            let relay = Unmanaged<TCPRelay>.fromOpaque(context).takeUnretainedValue()
            relay.output?(Array(UnsafeBufferPointer(start: packet, count: length)))
        }
        callbacks.accept = { context, connection in
            guard let context, let connection else { return 0 }
            return Unmanaged<TCPRelay>.fromOpaque(context).takeUnretainedValue().accept(connection)
        }
        callbacks.received = { context, id, data, length in
            guard let context else { return }
            let relay = Unmanaged<TCPRelay>.fromOpaque(context).takeUnretainedValue()
            relay.receivedFromPhone(id: UInt(id), bytes: data.map { Array(UnsafeBufferPointer(start: $0, count: length)) })
        }
        callbacks.sent = { context, id, _ in
            guard let context else { return }
            Unmanaged<TCPRelay>.fromOpaque(context).takeUnretainedValue().phoneAcknowledged(id: UInt(id))
        }
        callbacks.failed = { context, id, _ in
            guard let context else { return }
            Unmanaged<TCPRelay>.fromOpaque(context).takeUnretainedValue().lwipFailed(id: UInt(id))
        }
        let status = ferret_lwip_start(&callbacks)
        guard status == 0 else { throw TunnelCoreError.lwipStartFailed(Int(status)) }
        started = true

        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        t.setEventHandler { ferret_lwip_check_timeouts() }
        t.resume()
        timer = t
    }

    public func stop() {
        dispatchPrecondition(condition: .onQueue(queue))
        timer?.cancel()
        timer = nil
        for flow in flows.values { flow.upstream.cancel() }
        if started { ferret_lwip_stop() }
        flows.removeAll()
        started = false
    }

    /// Feeds a TCP packet from the phone.
    public func input(_ packet: [UInt8]) {
        dispatchPrecondition(condition: .onQueue(queue))
        packet.withUnsafeBufferPointer { ferret_lwip_input($0.baseAddress, $0.count) }
    }

    /// Runs lwIP timers immediately (tests use this instead of waiting).
    public func tick() {
        ferret_lwip_check_timeouts()
    }

    // MARK: - lwIP callbacks

    private func accept(_ pcb: UnsafeMutableRawPointer) -> UInt {
        guard flows.count < limits.maxConnections else { return 0 }
        var raw = ferret_tcp_endpoints()
        ferret_tcp_get_endpoints(pcb, &raw)
        let length = raw.is_ipv6 != 0 ? 16 : 4
        let local = withUnsafeBytes(of: raw.local_address) { IPAddress(bytes: $0.prefix(length)) }
        let remote = withUnsafeBytes(of: raw.remote_address) { IPAddress(bytes: $0.prefix(length)) }
        guard let destination = local, let source = remote else { return 0 }
        let endpoints = FlowEndpoints(
            source: source, sourcePort: raw.remote_port,
            destination: destination, destinationPort: raw.local_port)

        let id = nextID
        nextID += 1
        let upstream = factory.makeTCP(to: endpoints)
        let flow = Flow(id: id, pcb: pcb, endpoints: endpoints, upstream: upstream)
        flows[id] = flow

        upstream.onReady = { [weak self, weak flow] error in
            guard let self, let flow, self.flows[flow.id] != nil else { return }
            if error != nil {
                self.reset(flow)
                return
            }
            flow.connected = true
            self.pumpToServer(flow)
            flow.upstream.receiveMore()
        }
        upstream.onReceive = { [weak self, weak flow] bytes in
            guard let self, let flow, self.flows[flow.id] != nil else { return }
            if bytes.isEmpty {
                flow.serverClosed = true
            } else {
                flow.toPhone += bytes
            }
            self.pumpToPhone(flow)
        }
        upstream.onClose = { [weak self, weak flow] error in
            guard let self, let flow, self.flows[flow.id] != nil else { return }
            if error != nil && !flow.serverClosed {
                self.reset(flow)
            } else {
                flow.serverClosed = true
                self.pumpToPhone(flow)
            }
        }
        onFlowOpened?(endpoints)
        upstream.start()
        return id
    }

    private func receivedFromPhone(id: UInt, bytes: [UInt8]?) {
        guard let flow = flows[id] else { return }
        guard let bytes else {
            flow.phoneClosed = true
            pumpToServer(flow)
            return
        }
        flow.toServer += bytes
        pumpToServer(flow)
    }

    private func phoneAcknowledged(id: UInt) {
        guard let flow = flows[id] else { return }
        pumpToPhone(flow)
    }

    private func lwipFailed(id: UInt) {
        // The pcb is already gone; only the upstream needs closing.
        guard let flow = flows.removeValue(forKey: id) else { return }
        flow.upstream.cancel()
        onFlowClosed?(flow.endpoints)
    }

    // MARK: - Pumps

    private func pumpToServer(_ flow: Flow) {
        guard flow.connected, !flow.sendingToServer else { return }
        if flow.toServer.isEmpty {
            if flow.phoneClosed {
                flow.upstream.shutdownWrite()
                finishIfDone(flow)
            }
            return
        }
        let chunk = flow.toServer
        flow.toServer = []
        flow.sendingToServer = true
        flow.upstream.send(chunk) { [weak self, weak flow] error in
            guard let self, let flow, self.flows[flow.id] != nil else { return }
            flow.sendingToServer = false
            if error != nil {
                self.reset(flow)
                return
            }
            // Only now reopen the phone's window: backpressure end to end.
            ferret_tcp_consumed(flow.pcb, chunk.count)
            self.pumpToServer(flow)
        }
    }

    private func pumpToPhone(_ flow: Flow) {
        if !flow.toPhone.isEmpty {
            let written = flow.toPhone.withUnsafeBufferPointer { ferret_tcp_write(flow.pcb, $0.baseAddress, $0.count) }
            if written > 0 {
                flow.toPhone.removeFirst(written)
                ferret_tcp_flush(flow.pcb)
            }
        }
        if flow.toPhone.count < limits.maxPendingToPhone / 2, !flow.serverClosed, flow.connected {
            flow.upstream.receiveMore()
        }
        if flow.toPhone.isEmpty && flow.serverClosed {
            ferret_tcp_shutdown_write(flow.pcb)
            finishIfDone(flow)
        }
    }

    private func finishIfDone(_ flow: Flow) {
        guard flow.phoneClosed, flow.serverClosed, flow.toPhone.isEmpty, flow.toServer.isEmpty, !flow.sendingToServer else { return }
        flows[flow.id] = nil
        if ferret_tcp_close(flow.pcb) != 0 {
            ferret_tcp_abort(flow.pcb)
        }
        flow.upstream.cancel()
        onFlowClosed?(flow.endpoints)
    }

    private func reset(_ flow: Flow) {
        flows[flow.id] = nil
        ferret_tcp_abort(flow.pcb)
        flow.upstream.cancel()
        onFlowClosed?(flow.endpoints)
    }
}

public enum TunnelCoreError: Error, Equatable {
    case lwipStartFailed(Int)
}

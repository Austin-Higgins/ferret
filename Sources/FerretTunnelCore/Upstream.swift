import FerretParsers
import Foundation

/// A flow the phone opened, identified by where it was going.
public struct FlowEndpoints: Hashable, Sendable, CustomStringConvertible {
    public var source: IPAddress
    public var sourcePort: UInt16
    public var destination: IPAddress
    public var destinationPort: UInt16

    public init(source: IPAddress, sourcePort: UInt16, destination: IPAddress, destinationPort: UInt16) {
        self.source = source
        self.sourcePort = sourcePort
        self.destination = destination
        self.destinationPort = destinationPort
    }

    public var description: String { "\(source):\(sourcePort) → \(destination):\(destinationPort)" }
}

/// The real-network side of a relayed TCP connection. Implementations call
/// their handlers on the relay's queue.
public protocol TCPUpstream: AnyObject {
    /// Called once when connected, or with an error if the connection failed.
    var onReady: ((Error?) -> Void)? { get set }
    /// Data from the server. An empty array means the server closed its side.
    var onReceive: (([UInt8]) -> Void)? { get set }
    /// The connection ended, cleanly or not.
    var onClose: ((Error?) -> Void)? { get set }

    func start()
    /// Sends data; `completion` runs when the bytes have been handed to the OS.
    func send(_ bytes: [UInt8], completion: @escaping (Error?) -> Void)
    /// Asks for more data once the relay has room for it.
    func receiveMore()
    func shutdownWrite()
    func cancel()
}

/// The real-network side of a relayed UDP flow.
public protocol UDPUpstream: AnyObject {
    var onReceive: (([UInt8]) -> Void)? { get set }
    var onClose: ((Error?) -> Void)? { get set }
    func start()
    func send(_ datagram: [UInt8])
    func cancel()
}

/// Creates upstream connections. The tunnel uses Network.framework; tests use fakes.
public protocol UpstreamFactory: AnyObject {
    func makeTCP(to endpoints: FlowEndpoints) -> TCPUpstream
    func makeUDP(to endpoints: FlowEndpoints) -> UDPUpstream
}

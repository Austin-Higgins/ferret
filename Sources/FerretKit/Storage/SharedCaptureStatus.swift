import CFerretAtomics
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Live counters shared between the tunnel extension (writer) and the app
/// (reader), backed by a small memory-mapped file in the App Group container.
/// Every field is a 64-bit atomic, so no locks cross the process boundary.
public final class SharedCaptureStatus: @unchecked Sendable {
    public enum Field: Int, CaseIterable {
        case magic = 0
        case state
        case packets
        case bytes
        case connections
        case droppedPackets
        case startedAtNanos
        case lastPacketAtNanos
        case segmentsWritten
        case bytesOnDisk
        case sessionID
        /// The extension's physical memory footprint, sampled every second.
        case memoryFootprint
        case peakMemoryFootprint
    }

    public enum State: UInt64, Sendable {
        case idle = 0
        case starting = 1
        case capturing = 2
        case stopping = 3
        case failed = 4
    }

    static let magicValue: UInt64 = 0x4645_5252_4554_0001  // "FERRET" + version 1
    static let size = 4096

    private let base: UnsafeMutableRawPointer
    private let fd: Int32

    /// Opens (creating if needed) the status file. Both processes use the same URL.
    public init(url: URL) throws {
        fd = open(url.path, O_RDWR | O_CREAT, 0o644)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        guard ftruncate(fd, off_t(Self.size)) == 0 else {
            close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        guard let p = mmap(nil, Self.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0),
              p != UnsafeMutableRawPointer(bitPattern: -1) else {
            close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        base = p
        if load(.magic) != Self.magicValue {
            for f in Field.allCases { store(f, 0) }
            store(.magic, Self.magicValue)
        }
    }

    deinit {
        munmap(base, Self.size)
        close(fd)
    }

    private func pointer(_ field: Field) -> UnsafeMutablePointer<UInt64> {
        // One field per 64-byte line keeps writer and reader from false sharing.
        (base + field.rawValue * 64).assumingMemoryBound(to: UInt64.self)
    }

    public func load(_ field: Field) -> UInt64 { ferret_atomic_load_u64(pointer(field)) }
    public func store(_ field: Field, _ value: UInt64) { ferret_atomic_store_u64(pointer(field), value) }
    @discardableResult
    public func add(_ field: Field, _ value: UInt64) -> UInt64 { ferret_atomic_add_u64(pointer(field), value) }

    public var state: State {
        get { State(rawValue: load(.state)) ?? .idle }
        set { store(.state, newValue.rawValue) }
    }

    /// Resets counters for a new capture session.
    public func beginSession(id: UInt64, at date: Date = Date()) {
        for f in Field.allCases where f != .magic { store(f, 0) }
        store(.sessionID, id)
        store(.startedAtNanos, Self.nanos(date))
        state = .capturing
    }

    public var snapshot: CaptureCounters {
        CaptureCounters(
            state: state,
            packets: Int(load(.packets)), bytes: Int(load(.bytes)),
            connections: Int(load(.connections)), droppedPackets: Int(load(.droppedPackets)),
            startedAt: Self.date(load(.startedAtNanos)), lastPacketAt: Self.date(load(.lastPacketAtNanos)),
            bytesOnDisk: Int(load(.bytesOnDisk)), sessionID: load(.sessionID),
            memoryFootprint: Int(load(.memoryFootprint)), peakMemoryFootprint: Int(load(.peakMemoryFootprint)))
    }

    static func nanos(_ date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970 * 1e9))
    }

    static func date(_ nanos: UInt64) -> Date? {
        nanos == 0 ? nil : Date(timeIntervalSince1970: Double(nanos) / 1e9)
    }
}

/// A point-in-time copy of the shared counters, for UI and the Live Activity.
public struct CaptureCounters: Hashable, Codable, Sendable {
    public var state: SharedCaptureStatus.State
    public var packets: Int
    public var bytes: Int
    public var connections: Int
    public var droppedPackets: Int
    public var startedAt: Date?
    public var lastPacketAt: Date?
    public var bytesOnDisk: Int
    public var sessionID: UInt64
    public var memoryFootprint: Int
    public var peakMemoryFootprint: Int

    public init(
        state: SharedCaptureStatus.State = .idle, packets: Int = 0, bytes: Int = 0, connections: Int = 0,
        droppedPackets: Int = 0, startedAt: Date? = nil, lastPacketAt: Date? = nil, bytesOnDisk: Int = 0,
        sessionID: UInt64 = 0, memoryFootprint: Int = 0, peakMemoryFootprint: Int = 0
    ) {
        self.state = state
        self.packets = packets
        self.bytes = bytes
        self.connections = connections
        self.droppedPackets = droppedPackets
        self.startedAt = startedAt
        self.lastPacketAt = lastPacketAt
        self.bytesOnDisk = bytesOnDisk
        self.sessionID = sessionID
        self.memoryFootprint = memoryFootprint
        self.peakMemoryFootprint = peakMemoryFootprint
    }
}

extension SharedCaptureStatus.State: Codable {}

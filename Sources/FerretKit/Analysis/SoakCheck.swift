import Foundation

/// The spec's capture done-when test: 30 minutes without breaking connectivity,
/// with the tunnel extension under 50 MB. Evaluated live from the shared counters.
public struct SoakCheck: Hashable, Sendable {
    public static let requiredDuration: TimeInterval = 30 * 60
    public static let memoryBudget = 50 * 1024 * 1024

    public enum State: Hashable, Sendable {
        case notRunning
        case running(elapsed: TimeInterval)
        case passed
        case overBudget
    }

    public var state: State
    public var peakMemory: Int
    /// Seconds since the tunnel last saw a packet, a hint that connectivity broke.
    public var secondsSinceLastPacket: TimeInterval?

    public init(counters: CaptureCounters, capturing: Bool, now: Date = Date()) {
        peakMemory = counters.peakMemoryFootprint
        secondsSinceLastPacket = counters.lastPacketAt.map { now.timeIntervalSince($0) }
        guard let start = counters.startedAt, capturing || counters.packets > 0 else {
            state = .notRunning
            return
        }
        let end = capturing ? now : (counters.lastPacketAt ?? now)
        let elapsed = end.timeIntervalSince(start)
        if counters.peakMemoryFootprint > Self.memoryBudget {
            state = .overBudget
        } else if elapsed >= Self.requiredDuration {
            state = .passed
        } else {
            state = capturing ? .running(elapsed: elapsed) : .notRunning
        }
    }
}

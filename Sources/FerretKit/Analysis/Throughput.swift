import Foundation

public struct ThroughputSample: Identifiable, Hashable, Sendable {
    public var time: Date
    public var bytesPerSecond: Double
    public var packetsPerSecond: Double

    public var id: Date { time }
}

/// Turns the tunnel's cumulative byte and packet counters into a rolling
/// per-second rate for the capture screen's live graph.
public struct ThroughputSampler: Sendable {
    public private(set) var samples: [ThroughputSample] = []
    public var capacity: Int
    private var last: (time: Date, bytes: Int, packets: Int)?

    public init(capacity: Int = 120) {
        self.capacity = capacity
    }

    public var peakBytesPerSecond: Double { samples.map(\.bytesPerSecond).max() ?? 0 }
    public var current: ThroughputSample? { samples.last }

    public mutating func add(bytes: Int, packets: Int, at time: Date) {
        defer { last = (time, bytes, packets) }
        guard let last else { return }
        // A new session resets the counters: start the graph again.
        if bytes < last.bytes || packets < last.packets {
            samples.removeAll()
            return
        }
        let dt = time.timeIntervalSince(last.time)
        guard dt > 0.2 else { return }
        samples.append(ThroughputSample(
            time: time,
            bytesPerSecond: Double(bytes - last.bytes) / dt,
            packetsPerSecond: Double(packets - last.packets) / dt))
        if samples.count > capacity { samples.removeFirst(samples.count - capacity) }
    }

    public mutating func reset() {
        samples.removeAll()
        last = nil
    }
}

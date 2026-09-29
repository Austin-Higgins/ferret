import FerretKit
import FerretParsers
import Foundation

/// A point-in-time copy of analysis results for the UI.
struct TrafficSnapshot: Sendable {
    var connections: [Connection] = []
    var lookups: [DNSLookup] = []
    var stats = CaptureStats()
    var frameCount = 0
}

/// Owns the analyzer and the raw frames. Runs off the main thread; the UI reads snapshots.
actor AnalysisEngine {
    private var analyzer = TrafficAnalyzer()
    private var reader: CaptureSegmentReader?
    private var frames: [Int: CaptureRecord] = [:]
    private var frameOrder: [Int] = []
    private var frameBytes = 0
    private var frameCount = 0
    private var dirty = false

    /// Raw bytes kept for the hex view; older frames stay on disk and in exports.
    let maxFrameBytes = 48 * 1024 * 1024

    func reset() {
        analyzer = TrafficAnalyzer()
        analyzer.setLocalAddresses([IPAddress("10.111.0.2")!, IPAddress("fd66:6572:7265::2")!])
        reader = nil
        frames = [:]
        frameOrder = []
        frameBytes = 0
        frameCount = 0
        dirty = true
    }

    /// Follows a capture directory the tunnel is writing to.
    func follow(_ directory: CaptureDirectory) {
        reset()
        reader = CaptureSegmentReader(directory: directory)
    }

    /// Reads any new frames. Returns a snapshot when something changed.
    func poll() -> TrafficSnapshot? {
        if let reader {
            let records = reader.readNew(limit: 20_000)
            for r in records { ingest(r) }
        }
        guard dirty else { return nil }
        dirty = false
        return snapshot()
    }

    /// Loads a whole capture file (Files, AirDrop or a closed case).
    func load(records: [CaptureRecord]) -> TrafficSnapshot {
        reset()
        analyzer.setLocalAddresses([])
        for r in records { ingest(r) }
        dirty = false
        return snapshot()
    }

    func load(fileData: Data) throws -> TrafficSnapshot {
        load(records: try CaptureFileReader.read(fileData))
    }

    /// Loads every segment of a finished capture.
    func load(directory: CaptureDirectory) -> TrafficSnapshot {
        reset()
        let reader = CaptureSegmentReader(directory: directory)
        while true {
            let batch = reader.readNew()
            if batch.isEmpty { break }
            for r in batch { ingest(r) }
        }
        dirty = false
        return snapshot()
    }

    func snapshot() -> TrafficSnapshot {
        TrafficSnapshot(connections: analyzer.connections, lookups: analyzer.dnsLookups, stats: analyzer.stats, frameCount: frameCount)
    }

    func frame(_ index: Int) -> CaptureRecord? { frames[index] }

    func dissect(_ index: Int) -> PacketDissection? {
        frames[index].map { Dissector.dissect($0) }
    }

    private func ingest(_ record: CaptureRecord) {
        let index = frameCount
        frameCount += 1
        if let ip = record.ipBytes {
            analyzer.ingest(ipPacket: ip, timestamp: record.timestamp, direction: record.direction, frameIndex: index)
        }
        frames[index] = record
        frameOrder.append(index)
        frameBytes += record.data.count
        while frameBytes > maxFrameBytes, !frameOrder.isEmpty {
            let old = frameOrder.removeFirst()
            frameBytes -= frames.removeValue(forKey: old)?.data.count ?? 0
        }
        dirty = true
    }
}

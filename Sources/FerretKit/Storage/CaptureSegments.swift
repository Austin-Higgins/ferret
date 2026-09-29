import FerretParsers
import Foundation

/// On-disk layout of a capture: numbered pcapng segments in one directory.
/// The extension appends; the app reads, exports and deletes.
public struct CaptureDirectory: Sendable {
    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    static let prefix = "segment-"
    static let suffix = ".pcapng"

    public func segmentURL(_ index: Int) -> URL {
        url.appendingPathComponent(String(format: "%@%08d%@", Self.prefix, index, Self.suffix))
    }

    /// Segment indices currently on disk, oldest first.
    public func segmentIndices() -> [Int] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
        return names.compactMap { name -> Int? in
            guard name.hasPrefix(Self.prefix), name.hasSuffix(Self.suffix) else { return nil }
            return Int(name.dropFirst(Self.prefix.count).dropLast(Self.suffix.count))
        }.sorted()
    }

    public func totalBytes() -> Int {
        segmentIndices().reduce(0) { sum, i in
            let size = (try? FileManager.default.attributesOfItem(atPath: segmentURL(i).path)[.size] as? NSNumber)??.intValue ?? 0
            return sum + size
        }
    }

    /// Deletes every segment: "captures deleted on request in one tap".
    public func deleteAll() throws {
        for i in segmentIndices() {
            try FileManager.default.removeItem(at: segmentURL(i))
        }
    }
}

/// Appends packets to rotating pcapng segments, deleting the oldest segments
/// to stay under a storage cap. Designed for the tunnel extension: small fixed
/// buffer, no parsing, no allocation per packet beyond the record bytes.
public final class CaptureSegmentWriter {
    public let directory: CaptureDirectory
    /// Total bytes allowed on disk across all segments.
    public var storageCap: Int
    public var segmentSize: Int
    public var flushThreshold: Int

    private let writer = PcapNGWriter()
    private var handle: FileHandle?
    private var currentIndex: Int
    private var currentSize = 0
    private var buffer: [UInt8] = []
    private var segmentSizes: [Int: Int] = [:]

    public init(directory: CaptureDirectory, storageCap: Int, segmentSize: Int = 4 * 1024 * 1024, flushThreshold: Int = 64 * 1024) throws {
        self.directory = directory
        self.storageCap = max(storageCap, segmentSize * 2)
        self.segmentSize = segmentSize
        self.flushThreshold = flushThreshold
        try FileManager.default.createDirectory(at: directory.url, withIntermediateDirectories: true)
        let existing = directory.segmentIndices()
        for i in existing {
            segmentSizes[i] = (try? FileManager.default.attributesOfItem(atPath: directory.segmentURL(i).path)[.size] as? NSNumber)??.intValue ?? 0
        }
        currentIndex = (existing.last ?? 0) + 1
        buffer.reserveCapacity(flushThreshold + 2048)
        try openSegment()
    }

    deinit {
        try? close()
    }

    public var bytesOnDisk: Int { segmentSizes.values.reduce(0, +) + buffer.count }

    public func append(_ packet: ArraySlice<UInt8>, timestamp: CaptureTimestamp, direction: CaptureDirection) throws {
        let record = CaptureRecord(timestamp: timestamp, data: Array(packet), direction: direction)
        buffer += writer.record(record)
        if buffer.count >= flushThreshold { try flush() }
    }

    public func flush() throws {
        guard !buffer.isEmpty else { return }
        if currentSize + buffer.count > segmentSize && currentSize > 0 {
            try rotate()
        }
        try handle?.write(contentsOf: buffer)
        currentSize += buffer.count
        segmentSizes[currentIndex] = currentSize
        buffer.removeAll(keepingCapacity: true)
        enforceCap()
    }

    public func close() throws {
        try flush()
        try handle?.synchronize()
        try handle?.close()
        handle = nil
    }

    private func openSegment() throws {
        let url = directory.segmentURL(currentIndex)
        let header = writer.fileHeader()
        FileManager.default.createFile(atPath: url.path, contents: Data(header))
        handle = try FileHandle(forWritingTo: url)
        try handle?.seekToEnd()
        currentSize = header.count
        segmentSizes[currentIndex] = currentSize
    }

    private func rotate() throws {
        try handle?.close()
        currentIndex += 1
        try openSegment()
    }

    private func enforceCap() {
        var total = segmentSizes.values.reduce(0, +)
        for index in segmentSizes.keys.sorted() where total > storageCap && index != currentIndex {
            try? FileManager.default.removeItem(at: directory.segmentURL(index))
            total -= segmentSizes[index] ?? 0
            segmentSizes[index] = nil
        }
    }
}

/// Incrementally reads records the extension has appended, tolerating a
/// partially written final block and segments deleted by the storage cap.
public final class CaptureSegmentReader {
    public let directory: CaptureDirectory
    private var segment: Int?
    private var offset = 0
    public private(set) var framesRead = 0

    public init(directory: CaptureDirectory) {
        self.directory = directory
    }

    /// Returns every complete record written since the last call.
    public func readNew(limit: Int = 50_000) -> [CaptureRecord] {
        var out: [CaptureRecord] = []
        let indices = directory.segmentIndices()
        guard !indices.isEmpty else { return out }
        if segment == nil || !indices.contains(segment!) {
            // Start, or the segment we were reading was evicted: jump to the oldest remaining one.
            segment = indices.first { $0 >= (segment ?? 0) } ?? indices.first
            offset = 0
        }
        while let current = segment, out.count < limit {
            guard let chunk = readChunk(segment: current, limit: limit - out.count) else { break }
            out += chunk.records
            framesRead += chunk.records.count
            offset = chunk.offset
            guard chunk.reachedEnd, let next = indices.first(where: { $0 > current }) else { break }
            segment = next
            offset = 0
        }
        return out
    }

    private func readChunk(segment: Int, limit: Int) -> (records: [CaptureRecord], offset: Int, reachedEnd: Bool)? {
        guard let handle = try? FileHandle(forReadingFrom: directory.segmentURL(segment)) else { return nil }
        defer { try? handle.close() }
        guard let headData = try? handle.read(upToCount: 4096) else { return nil }
        let head = [UInt8](headData)
        let headerLength = Self.headerLength(head)
        guard headerLength > 0 else { return ([], offset, false) }
        let start = max(offset, headerLength)
        guard (try? handle.seek(toOffset: UInt64(start))) != nil,
              let tailData = try? handle.readToEnd() else { return ([], start, false) }
        let tail = [UInt8](tailData)
        let end = Self.wholeBlocksLength(tail)
        guard end > 0 else { return ([], start, true) }
        let records = (try? PcapNGReader.read(Array(head[0..<headerLength]) + Array(tail[0..<end]))) ?? []
        return (Array(records.prefix(limit)), start + end, end == tail.count)
    }

    /// Length of the prefix made of whole pcapng blocks.
    static func wholeBlocksLength(_ bytes: [UInt8]) -> Int {
        var end = 0
        while bytes.count - end >= 12 {
            let length = Int(UInt32(bytes[end + 4]) | UInt32(bytes[end + 5]) << 8 | UInt32(bytes[end + 6]) << 16 | UInt32(bytes[end + 7]) << 24)
            guard length >= 12, end + length <= bytes.count else { break }
            end += length
        }
        return end
    }

    /// Length of the Section Header and Interface Description blocks at the start of a segment.
    static func headerLength(_ bytes: [UInt8]) -> Int {
        var end = 0
        for _ in 0..<2 {
            guard bytes.count - end >= 8 else { return 0 }
            let length = Int(UInt32(bytes[end + 4]) | UInt32(bytes[end + 5]) << 8 | UInt32(bytes[end + 6]) << 16 | UInt32(bytes[end + 7]) << 24)
            guard length >= 12, end + length <= bytes.count else { return 0 }
            end += length
        }
        return end
    }
}

/// Merges segments into one file for AirDrop or Files.
public enum CaptureExporter {
    public static func export(from directory: CaptureDirectory, format: CaptureFormat, to destination: URL) throws -> Int {
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        let handle = try FileHandle(forWritingTo: destination)
        defer { try? handle.close() }
        var count = 0
        switch format {
        case .pcap:
            let writer = PcapWriter(linkType: .raw)
            try handle.write(contentsOf: writer.fileHeader())
            for index in directory.segmentIndices() {
                guard let data = FileManager.default.contents(atPath: directory.segmentURL(index).path),
                      let records = try? PcapNGReader.read([UInt8](data)) else { continue }
                var chunk: [UInt8] = []
                for r in records { chunk += writer.record(r) }
                try handle.write(contentsOf: chunk)
                count += records.count
            }
        case .pcapng:
            let writer = PcapNGWriter()
            try handle.write(contentsOf: writer.fileHeader())
            for index in directory.segmentIndices() {
                guard let data = FileManager.default.contents(atPath: directory.segmentURL(index).path),
                      let records = try? PcapNGReader.read([UInt8](data)) else { continue }
                var chunk: [UInt8] = []
                for r in records { chunk += writer.record(r) }
                try handle.write(contentsOf: chunk)
                count += records.count
            }
        }
        return count
    }
}

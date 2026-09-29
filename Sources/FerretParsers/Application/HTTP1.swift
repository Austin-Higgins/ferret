public struct HTTPRequestHead: Hashable, Sendable {
    public var method: String
    public var target: String
    public var version: String
    public var headers: [HTTPHeader]

    public var host: String? { headers.first { $0.name.lowercased() == "host" }?.value }
    public var userAgent: String? { headers.first { $0.name.lowercased() == "user-agent" }?.value }
}

public struct HTTPResponseHead: Hashable, Sendable {
    public var version: String
    public var statusCode: Int
    public var reason: String
    public var headers: [HTTPHeader]
}

public struct HTTPHeader: Hashable, Sendable {
    public var name: String
    public var value: String
}

/// HTTP/1.x message heads. Bodies are not parsed.
public enum HTTP1 {
    public static let methods: Set<String> = [
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ]

    public static func looksLikeRequest(_ bytes: ArraySlice<UInt8>) -> Bool {
        guard let space = bytes.prefix(8).firstIndex(of: 0x20) else { return false }
        return methods.contains(String(decoding: bytes[bytes.startIndex..<space], as: UTF8.self))
    }

    public static func looksLikeResponse(_ bytes: ArraySlice<UInt8>) -> Bool {
        bytes.starts(with: Array("HTTP/1.".utf8))
    }

    /// Parses a request head. Accepts a head cut off before the blank line so that
    /// the host is visible as soon as the first segment arrives.
    public static func parseRequest(_ bytes: ArraySlice<UInt8>) -> HTTPRequestHead? {
        guard looksLikeRequest(bytes) else { return nil }
        let lines = headLines(bytes)
        guard let first = lines.first else { return nil }
        let parts = first.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3, parts[2].hasPrefix("HTTP/") else { return nil }
        return HTTPRequestHead(
            method: String(parts[0]), target: String(parts[1]), version: String(parts[2]),
            headers: parseHeaders(lines.dropFirst()))
    }

    public static func parseResponse(_ bytes: ArraySlice<UInt8>) -> HTTPResponseHead? {
        guard looksLikeResponse(bytes) else { return nil }
        let lines = headLines(bytes)
        guard let first = lines.first else { return nil }
        let parts = first.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, let code = Int(parts[1]) else { return nil }
        return HTTPResponseHead(
            version: String(parts[0]), statusCode: code,
            reason: parts.count == 3 ? String(parts[2]) : "",
            headers: parseHeaders(lines.dropFirst()))
    }

    static func headLines(_ bytes: ArraySlice<UInt8>) -> [String] {
        // Only look at the head; cap at 16 KB so a body is never scanned.
        let limited = bytes.prefix(16_384)
        var lines: [String] = []
        var lineStart = limited.startIndex
        var i = limited.startIndex
        while i < limited.endIndex {
            if limited[i] == 0x0A {
                var end = i
                if end > lineStart, limited[end - 1] == 0x0D { end -= 1 }
                if end == lineStart { return lines }
                lines.append(String(decoding: limited[lineStart..<end], as: UTF8.self))
                lineStart = i + 1
            }
            i += 1
        }
        if lineStart < limited.endIndex {
            lines.append(String(decoding: limited[lineStart..<limited.endIndex], as: UTF8.self))
        }
        return lines
    }

    static func parseHeaders<S: Sequence>(_ lines: S) -> [HTTPHeader] where S.Element == String {
        lines.compactMap { line in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let name = String(line[..<colon])
            let value = line[line.index(after: colon)...].drop { $0 == " " || $0 == "\t" }
            return HTTPHeader(name: name, value: String(value))
        }
    }
}

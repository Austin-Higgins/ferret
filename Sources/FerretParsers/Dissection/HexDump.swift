/// One row of a hex dump, laid out like Wireshark's bytes pane.
public struct HexDumpLine: Hashable, Sendable, Identifiable {
    public var offset: Int
    public var bytes: [UInt8]

    public var id: Int { offset }

    /// `0000` style offset.
    public var offsetText: String {
        let hex = String(offset, radix: 16)
        return String(repeating: "0", count: max(0, 4 - hex.count)) + hex
    }

    /// Hex bytes with an extra space after the eighth byte.
    public var hexText: String {
        var parts: [String] = []
        for (i, b) in bytes.enumerated() {
            if i == 8 { parts.append("") }
            parts.append([b].hexString)
        }
        return parts.joined(separator: " ")
    }

    /// Printable ASCII with dots for everything else.
    public var asciiText: String {
        String(bytes.map { (0x20...0x7E).contains($0) ? Character(UnicodeScalar($0)) : "." })
    }

    public var text: String {
        let padded = hexText.ferretPadded(to: 16 * 3)
        return "\(offsetText)  \(padded)  \(asciiText)"
    }
}

public enum HexDump {
    public static func lines<C: Collection>(_ bytes: C, bytesPerLine: Int = 16) -> [HexDumpLine] where C.Element == UInt8 {
        let all = Array(bytes)
        return stride(from: 0, to: all.count, by: bytesPerLine).map { start in
            HexDumpLine(offset: start, bytes: Array(all[start..<min(start + bytesPerLine, all.count)]))
        }
    }

    public static func text<C: Collection>(_ bytes: C) -> String where C.Element == UInt8 {
        lines(bytes).map(\.text).joined(separator: "\n")
    }
}

extension String {
    func ferretPadded(to length: Int) -> String {
        count >= length ? self : self + String(repeating: " ", count: length - count)
    }
}

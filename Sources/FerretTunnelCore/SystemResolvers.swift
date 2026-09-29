import CFerretResolver
import FerretParsers

public enum SystemResolvers {
    /// The DNS servers the phone is using right now. Read this before applying
    /// tunnel settings, which replace them.
    public static func current() -> [IPAddress] {
        let slots = 8
        var buffer = [CChar](repeating: 0, count: slots * 64)
        let count = Int(buffer.withUnsafeMutableBufferPointer { ferret_system_dns_servers($0.baseAddress, Int32(slots)) })
        return (0..<max(0, count)).compactMap { i in
            let bytes = buffer[(i * 64)..<((i + 1) * 64)].prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
            return IPAddress(String(decoding: bytes, as: UTF8.self))
        }
    }

    /// Fallback when the system resolvers can't be read.
    public static let fallback: [IPAddress] = [IPAddress("1.1.1.1")!, IPAddress("2606:4700:4700::1111")!]
}

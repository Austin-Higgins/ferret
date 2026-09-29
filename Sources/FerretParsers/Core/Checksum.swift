/// The ones' complement Internet checksum (RFC 1071).
public enum InternetChecksum {
    /// Sums 16-bit big-endian words into a 32-bit accumulator without folding.
    public static func partialSum<C: Collection>(_ bytes: C, initial: UInt32 = 0) -> UInt32 where C.Element == UInt8 {
        var sum = initial
        var iterator = bytes.makeIterator()
        while let hi = iterator.next() {
            let lo = iterator.next() ?? 0
            sum &+= UInt32(hi) << 8 | UInt32(lo)
        }
        return sum
    }

    public static func fold(_ sum: UInt32) -> UInt16 {
        var s = sum
        while s >> 16 != 0 {
            s = (s & 0xFFFF) &+ (s >> 16)
        }
        return ~UInt16(s)
    }

    public static func checksum<C: Collection>(_ bytes: C) -> UInt16 where C.Element == UInt8 {
        fold(partialSum(bytes))
    }

    /// Checksum for TCP or UDP including the IPv4/IPv6 pseudo-header.
    public static func transportChecksum<C: Collection>(
        source: IPAddress, destination: IPAddress, protocolNumber: UInt8, segment: C
    ) -> UInt16 where C.Element == UInt8 {
        var pseudo: [UInt8] = []
        pseudo.append(contentsOf: source.bytes)
        pseudo.append(contentsOf: destination.bytes)
        let length = UInt32(segment.count)
        if source.isV4 {
            pseudo.append(0)
            pseudo.append(protocolNumber)
            pseudo.appendU16(UInt16(truncatingIfNeeded: length))
        } else {
            pseudo.appendU32(length)
            pseudo.append(contentsOf: [0, 0, 0, protocolNumber])
        }
        let sum = partialSum(pseudo)
        return fold(partialSum(segment, initial: sum))
    }
}

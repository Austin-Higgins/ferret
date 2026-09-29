/// Reorders one direction of a TCP stream by sequence number and hands back
/// newly contiguous bytes. Retransmitted and overlapping data is trimmed.
public struct TCPStreamReassembler: Sendable {
    public private(set) var nextSequence: UInt32?
    private var pending: [UInt32: [UInt8]] = [:]
    public private(set) var pendingBytes = 0
    /// Out-of-order data beyond this is dropped, keeping memory bounded.
    public var maxPendingBytes: Int

    public init(maxPendingBytes: Int = 256 * 1024) {
        self.maxPendingBytes = maxPendingBytes
    }

    /// Accepts a segment and returns any bytes that are now in order.
    public mutating func accept(sequence: UInt32, flags: TCPFlags, payload: ArraySlice<UInt8>) -> [UInt8] {
        var seq = sequence
        if flags.contains(.syn) {
            seq = sequence &+ 1
            if nextSequence == nil { nextSequence = seq }
        }
        if nextSequence == nil { nextSequence = seq }
        guard !payload.isEmpty, let next = nextSequence else { return [] }

        var out: [UInt8] = []
        let diff = Int32(bitPattern: seq &- next)
        if diff > 0 {
            if pendingBytes + payload.count <= maxPendingBytes {
                if let existing = pending[seq], existing.count >= payload.count { return [] }
                pendingBytes -= pending[seq]?.count ?? 0
                pending[seq] = Array(payload)
                pendingBytes += payload.count
            }
            return []
        }
        let overlap = Int(-diff)
        if overlap < payload.count {
            out.append(contentsOf: payload.dropFirst(overlap))
            nextSequence = next &+ UInt32(payload.count - overlap)
        }
        flushPending(into: &out)
        return out
    }

    private mutating func flushPending(into out: inout [UInt8]) {
        var progressed = true
        while progressed, !pending.isEmpty, let next = nextSequence {
            progressed = false
            for (seq, bytes) in pending {
                let diff = Int32(bitPattern: seq &- next)
                guard diff <= 0 else { continue }
                pending[seq] = nil
                pendingBytes -= bytes.count
                let overlap = Int(-diff)
                if overlap < bytes.count {
                    out.append(contentsOf: bytes[overlap...])
                    nextSequence = next &+ UInt32(bytes.count - overlap)
                }
                progressed = true
                break
            }
        }
    }
}

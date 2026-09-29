import Foundation
import FerretParsers

/// Groups hostnames under their registrable domain ("eTLD+1") using the
/// Public Suffix List, so `a.b.example.co.uk` groups under `example.co.uk`.
public final class PublicSuffixList: @unchecked Sendable {
    private let rules: Set<String>
    private let wildcards: Set<String>
    private let exceptions: Set<String>

    /// The list bundled with FerretKit (MPL 2.0 data, see NOTICE).
    public static let shared: PublicSuffixList = {
        guard let url = Bundle.module.url(forResource: "public_suffix_list", withExtension: "dat"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return PublicSuffixList(text: "")
        }
        return PublicSuffixList(text: text)
    }()

    public init(text: String) {
        var rules = Set<String>(), wildcards = Set<String>(), exceptions = Set<String>()
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("//") { continue }
            let rule = String(line.split(separator: " ").first ?? "").lowercased()
            if rule.hasPrefix("!") {
                exceptions.insert(String(rule.dropFirst()))
            } else if rule.hasPrefix("*.") {
                wildcards.insert(String(rule.dropFirst(2)))
            } else {
                rules.insert(rule)
            }
        }
        self.rules = rules
        self.wildcards = wildcards
        self.exceptions = exceptions
    }

    public var ruleCount: Int { rules.count + wildcards.count + exceptions.count }

    /// The public suffix of a hostname, e.g. `co.uk`. Unknown TLDs use the implicit `*` rule.
    public func publicSuffix(of host: String) -> String? {
        let labels = Domain.normalize(host).split(separator: ".").map(String.init)
        guard !labels.isEmpty else { return nil }
        var suffixLength = 1
        for i in 0..<labels.count {
            let candidate = labels[i...].joined(separator: ".")
            let count = labels.count - i
            if exceptions.contains(candidate) {
                suffixLength = count - 1
                break
            }
            if rules.contains(candidate) {
                suffixLength = max(suffixLength, count)
            }
            if i + 1 < labels.count {
                let parent = labels[(i + 1)...].joined(separator: ".")
                if wildcards.contains(parent) {
                    suffixLength = max(suffixLength, count)
                }
            }
        }
        return labels.suffix(suffixLength).joined(separator: ".")
    }

    /// The registrable domain (public suffix plus one label), or nil when the
    /// host is itself a public suffix or an IP address.
    public func registrableDomain(of host: String) -> String? {
        let normalized = Domain.normalize(host)
        guard !Domain.isIPAddress(normalized), let suffix = publicSuffix(of: normalized) else { return nil }
        let labels = normalized.split(separator: ".")
        let suffixCount = suffix.split(separator: ".").count
        guard labels.count > suffixCount else { return nil }
        return labels.suffix(suffixCount + 1).joined(separator: ".")
    }
}

public enum Domain {
    /// Lowercases and drops a trailing dot.
    public static func normalize(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    public static func isIPAddress(_ s: String) -> Bool {
        FerretParsers.IPAddress(s) != nil
    }

    /// True if `host` equals `domain` or is a subdomain of it.
    public static func host(_ host: String, isWithin domain: String) -> Bool {
        let h = normalize(host), d = normalize(domain)
        return h == d || h.hasSuffix("." + d)
    }

    /// Checks `host` and each parent domain against a set, returning the first match.
    public static func firstMatch(of host: String, in set: Set<String>) -> String? {
        var labels = normalize(host).split(separator: ".")
        while !labels.isEmpty {
            let candidate = labels.joined(separator: ".")
            if set.contains(candidate) { return candidate }
            labels.removeFirst()
        }
        return nil
    }
}

import FerretParsers
import Foundation

/// The 10-second Wi-Fi check. Each check is a pure function of probe results,
/// so the same logic runs against the real network and in practice mode.
public enum SafetySnoot {
    public static let timeBudget: TimeInterval = 10

    // MARK: Reference data

    /// Names whose answers are stable and published by their operators.
    static let knownAnswers: [String: Set<IPAddress>] = [
        "one.one.one.one": addrs("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
        "dns.google": addrs("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
        "dns.quad9.net": addrs("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"),
    ]

    /// Sites checked for certificate interception and the CA organisations
    /// that have issued their certificates. Lists are deliberately generous.
    static let tlsHosts: [String: [String]] = [
        "www.google.com": ["Google Trust Services"],
        "www.apple.com": ["Apple", "DigiCert"],
        "en.wikipedia.org": ["Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo"],
        "www.cloudflare.com": ["Google Trust Services", "Let's Encrypt", "DigiCert", "Sectigo", "SSL.com", "Cloudflare"],
    ]

    public static let captivePortalURLString = "http://captive.apple.com/hotspot-detect.html"
    public static let captivePortalBody = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"

    /// Service types that suggest remote access or file sharing on the local network.
    static let remoteAccessServices: [String: String] = [
        "_ssh._tcp": "SSH remote login",
        "_sftp-ssh._tcp": "SFTP file transfer",
        "_rfb._tcp": "screen sharing (VNC)",
        "_rdp._tcp": "remote desktop",
        "_telnet._tcp": "Telnet remote login",
        "_smb._tcp": "Windows file sharing",
        "_afpovertcp._tcp": "Apple file sharing",
        "_ftp._tcp": "FTP file transfer",
    ]

    public static let bonjourTypes: [String] = Array(remoteAccessServices.keys).sorted() + [
        "_http._tcp", "_ipp._tcp", "_airplay._tcp", "_googlecast._tcp", "_hap._tcp",
    ]

    // MARK: Running

    public static func run(probes: SnootProbes, isPractice: Bool = false, now: Date = Date()) async -> SnootReport {
        let start = Date()
        async let dns = checkDNS(probes)
        async let tls = checkTLS(probes)
        async let portal = checkCaptivePortal(probes)
        async let wifiResult = probes.wifi()
        async let bonjour = checkBonjour(probes)
        let wifi = await wifiResult
        var results = [await dns, await tls, await portal, checkWiFi(wifi), await bonjour]

        // A sign-in page explains failed certificate checks: downgrade them.
        let portalFound = results.contains { $0.kind == .captivePortal && $0.findings.contains { $0.title == "Sign-in page" } }
        if portalFound, let i = results.firstIndex(where: { $0.kind == .tlsInterception }) {
            results[i].findings = results[i].findings.map { f in
                var f = f
                if f.severity == .danger {
                    f.severity = .warning
                    f.detail += " This may be the Wi-Fi sign-in page; sign in and run Safety Snoot again."
                }
                return f
            }
        }
        return SnootReport(
            verdict: SnootReport.verdict(for: results), results: results, startedAt: now,
            duration: Date().timeIntervalSince(start), isPractice: isPractice,
            networkName: wifi.ssid)
    }

    // MARK: Checks

    static func checkDNS(_ probes: SnootProbes) async -> SnootCheckResult {
        var findings: [SnootFinding] = []
        var answered = 0
        for (name, expected) in knownAnswers.sorted(by: { $0.key < $1.key }) {
            switch await probes.resolve(name) {
            case .addresses(let got):
                answered += 1
                let unexpected = got.filter { !expected.contains($0) }
                if !unexpected.isEmpty {
                    findings.append(SnootFinding(
                        kind: .dnsHijack, severity: .danger, title: "Altered answer",
                        detail: "\(name) should point to its operator's servers, but this network answered \(unexpected.map(\.description).joined(separator: ", "))."))
                }
            case .nameNotFound:
                answered += 1
                findings.append(SnootFinding(
                    kind: .dnsHijack, severity: .danger, title: "Blocked lookup",
                    detail: "This network says \(name) doesn't exist. It does."))
            case .failed:
                break
            }
        }
        let bogus = "ferret-\(UInt32.random(in: 0...UInt32.max))-check.example.com"
        if case .addresses(let got) = await probes.resolve(bogus), !got.isEmpty {
            answered += 1
            findings.append(SnootFinding(
                kind: .dnsHijack, severity: .warning, title: "Made-up names resolve",
                detail: "A name that doesn't exist resolved to \(got[0]). The network rewrites failed lookups, often to show ads or a sign-in page."))
        }
        if answered == 0 && findings.isEmpty {
            return SnootCheckResult(kind: .dnsHijack, status: .skipped("DNS lookups didn't complete."), findings: [])
        }
        return SnootCheckResult(kind: .dnsHijack, status: findings.isEmpty ? .passed : .findings, findings: findings)
    }

    static func checkTLS(_ probes: SnootProbes) async -> SnootCheckResult {
        var findings: [SnootFinding] = []
        var completed = 0
        var unexpectedIssuers: [String] = []
        await withTaskGroup(of: TLSProbeResult.self) { group in
            for host in tlsHosts.keys.sorted() {
                group.addTask { await probes.tlsHandshake(host: host) }
            }
            for await result in group {
                if result.error != nil && !result.trusted && result.issuerOrganization == nil {
                    continue  // Couldn't connect at all; not evidence of interception.
                }
                completed += 1
                let issuer = result.issuerOrganization ?? result.issuerCommonName ?? "an unknown issuer"
                if !result.trusted {
                    findings.append(SnootFinding(
                        kind: .tlsInterception, severity: .danger, title: "Untrusted certificate",
                        detail: "\(result.host) presented a certificate from \(issuer) that your iPhone doesn't trust. Something on this network is intercepting encrypted connections."))
                } else if let expected = tlsHosts[result.host],
                          !expected.contains(where: { issuer.localizedCaseInsensitiveContains($0) }) {
                    unexpectedIssuers.append("\(result.host) (\(issuer))")
                }
            }
        }
        if unexpectedIssuers.count >= 2 {
            findings.append(SnootFinding(
                kind: .tlsInterception, severity: .danger, title: "Certificates signed by someone else",
                detail: "Several sites presented trusted certificates from unexpected issuers: \(unexpectedIssuers.sorted().joined(separator: ", ")). A device profile may be letting this network read encrypted traffic."))
        } else if unexpectedIssuers.count == 1 {
            findings.append(SnootFinding(
                kind: .tlsInterception, severity: .info, title: "Unusual issuer",
                detail: "\(unexpectedIssuers[0]) used an issuer Ferret didn't expect. Sites change certificate providers, so on its own this is probably fine."))
        }
        if completed == 0 {
            return SnootCheckResult(kind: .tlsInterception, status: .skipped("Couldn't reach the test sites."), findings: [])
        }
        let status: SnootCheckStatus = findings.contains { $0.severity > .info } ? .findings : .passed
        return SnootCheckResult(kind: .tlsInterception, status: status, findings: findings)
    }

    static func checkCaptivePortal(_ probes: SnootProbes) async -> SnootCheckResult {
        guard let response = await probes.fetchCaptivePortalCheck() else {
            return SnootCheckResult(kind: .captivePortal, status: .skipped("The test page didn't load."), findings: [])
        }
        return evaluateCaptivePortal(response)
    }

    static func evaluateCaptivePortal(_ response: HTTPProbeResult) -> SnootCheckResult {
        let body = response.body.trimmingCharacters(in: .whitespacesAndNewlines)
        if response.statusCode == 200 && body == captivePortalBody {
            return SnootCheckResult(kind: .captivePortal, status: .passed, findings: [])
        }
        if (300..<400).contains(response.statusCode) || (response.statusCode == 200 && !body.contains("Success")) {
            let target = response.redirectLocation.map { " to \($0)" } ?? ""
            return SnootCheckResult(kind: .captivePortal, status: .findings, findings: [SnootFinding(
                kind: .captivePortal, severity: .warning, title: "Sign-in page",
                detail: "This network redirects web traffic\(target). That's normal for hotel and café Wi-Fi before you sign in, but it also means the network controls what you see.")])
        }
        if response.statusCode == 200 && body.contains("Success") {
            return SnootCheckResult(kind: .captivePortal, status: .findings, findings: [SnootFinding(
                kind: .captivePortal, severity: .danger, title: "Page was modified",
                detail: "A known test page arrived with extra content added. This network edits unencrypted web pages, for example to inject ads or scripts.")])
        }
        return SnootCheckResult(kind: .captivePortal, status: .findings, findings: [SnootFinding(
            kind: .captivePortal, severity: .warning, title: "Unexpected response",
            detail: "The test page returned status \(response.statusCode).")])
    }

    static func checkWiFi(_ wifi: WiFiProbeResult) -> SnootCheckResult {
        switch wifi.security {
        case .open:
            return SnootCheckResult(kind: .openNetwork, status: .findings, findings: [SnootFinding(
                kind: .openNetwork, severity: .warning, title: "Open network",
                detail: "This Wi-Fi has no password. Anyone nearby can see unencrypted traffic and set up a look-alike network.")])
        case .wep:
            return SnootCheckResult(kind: .openNetwork, status: .findings, findings: [SnootFinding(
                kind: .openNetwork, severity: .warning, title: "Outdated encryption",
                detail: "This Wi-Fi uses WEP, which can be broken in minutes. Treat it like an open network.")])
        case .personal, .enterprise:
            return SnootCheckResult(kind: .openNetwork, status: .passed, findings: [])
        case .notOnWiFi:
            return SnootCheckResult(kind: .openNetwork, status: .skipped("You're not on Wi-Fi."), findings: [])
        case .unknown:
            return SnootCheckResult(kind: .openNetwork, status: .skipped("iOS didn't share this network's security type."), findings: [])
        }
    }

    static func checkBonjour(_ probes: SnootProbes) async -> SnootCheckResult {
        guard let services = await probes.bonjourServices() else {
            return SnootCheckResult(kind: .bonjour, status: .skipped("Local network access is off for Ferret."), findings: [])
        }
        return evaluateBonjour(services)
    }

    static func evaluateBonjour(_ services: [String: Int]) -> SnootCheckResult {
        let risky = services.filter { remoteAccessServices[$0.key] != nil && $0.value > 0 }
        guard !risky.isEmpty else {
            return SnootCheckResult(kind: .bonjour, status: .passed, findings: [])
        }
        let names = risky.keys.sorted().compactMap { remoteAccessServices[$0] }
        let count = risky.values.reduce(0, +)
        return SnootCheckResult(kind: .bonjour, status: .findings, findings: [SnootFinding(
            kind: .bonjour, severity: .warning, title: "Remote access offered nearby",
            detail: "\(count) \(count == 1 ? "device" : "devices") on this network offer \(names.joined(separator: ", ")). On a public network, that means strangers' devices can see each other.")])
    }

    static func addrs(_ list: String...) -> Set<IPAddress> {
        Set(list.compactMap { IPAddress($0) })
    }
}

import FerretKit
import FerretParsers
import Foundation
import Network
import NetworkExtension
import Security

/// Safety Snoot against the real network. Every probe has its own timeout so
/// the whole check stays within about ten seconds.
struct NetworkSnootProbes: SnootProbes {
    func resolve(_ name: String) async -> DNSProbeResult {
        await withTimeout(seconds: 4, fallback: .failed("timeout")) {
            await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    var hints = addrinfo()
                    hints.ai_socktype = SOCK_STREAM
                    var result: UnsafeMutablePointer<addrinfo>?
                    let status = getaddrinfo(name, nil, &hints, &result)
                    defer { if let result { freeaddrinfo(result) } }
                    guard status == 0 else {
                        continuation.resume(returning: status == EAI_NONAME ? .nameNotFound : .failed(String(cString: gai_strerror(status))))
                        return
                    }
                    var addresses: [IPAddress] = []
                    var cursor = result
                    while let info = cursor {
                        if let sa = info.pointee.ai_addr {
                            if info.pointee.ai_family == AF_INET {
                                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                                    withUnsafeBytes(of: sin.pointee.sin_addr) { addresses.append(IPAddress(bytes: $0)!) }
                                }
                            } else if info.pointee.ai_family == AF_INET6 {
                                sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                                    withUnsafeBytes(of: sin6.pointee.sin6_addr) { addresses.append(IPAddress(bytes: $0)!) }
                                }
                            }
                        }
                        cursor = info.pointee.ai_next
                    }
                    var seen = Set<IPAddress>()
                    continuation.resume(returning: .addresses(addresses.filter { seen.insert($0).inserted }))
                }
            }
        }
    }

    func tlsHandshake(host: String) async -> TLSProbeResult {
        await withTimeout(seconds: 6, fallback: TLSProbeResult(host: host, trusted: false, issuerOrganization: nil, error: "timeout")) {
            await TrustProbe(host: host).run()
        }
    }

    func fetchCaptivePortalCheck() async -> HTTPProbeResult? {
        guard let url = URL(string: SafetySnoot.captivePortalURLString) else { return nil }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 5)
        request.setValue("CaptiveNetworkSupport", forHTTPHeaderField: "User-Agent")
        let delegate = NoRedirects()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        guard let (data, response) = try? await session.data(for: request), let http = response as? HTTPURLResponse else {
            return nil
        }
        var headers: [String: String] = [:]
        for (k, v) in http.allHeaderFields { headers["\(k)"] = "\(v)" }
        return HTTPProbeResult(
            statusCode: http.statusCode, body: String(decoding: data, as: UTF8.self),
            redirectLocation: headers["Location"], headers: headers)
    }

    func wifi() async -> WiFiProbeResult {
        let onWiFi = await withTimeout(seconds: 2, fallback: true) {
            await withCheckedContinuation { continuation in
                let monitor = NWPathMonitor()
                monitor.pathUpdateHandler = { path in
                    monitor.cancel()
                    continuation.resume(returning: path.usesInterfaceType(.wifi))
                }
                monitor.start(queue: .global())
            }
        }
        guard onWiFi else { return WiFiProbeResult(ssid: nil, security: .notOnWiFi) }
        let network = await withTimeout(seconds: 3, fallback: nil) { await NEHotspotNetwork.fetchCurrent() }
        guard let network else { return WiFiProbeResult(ssid: nil, security: .unknown) }
        let security: WiFiSecurity
        switch network.securityType {
        case .open: security = .open
        case .WEP: security = .wep
        case .personal: security = .personal
        case .enterprise: security = .enterprise
        default: security = .unknown
        }
        return WiFiProbeResult(ssid: network.ssid, security: security)
    }

    func bonjourServices() async -> [String: Int]? {
        await withTimeout(seconds: 5, fallback: nil) {
            await BonjourSurvey(types: SafetySnoot.bonjourTypes).run(for: 4)
        }
    }
}

/// Opens a TLS connection far enough to see the certificate chain, then cancels.
private final class TrustProbe: NSObject, URLSessionDelegate, @unchecked Sendable {
    let host: String
    private var result: TLSProbeResult?

    init(host: String) {
        self.host = host
    }

    func run() async -> TLSProbeResult {
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: URL(string: "https://\(host)/")!, timeoutInterval: 5)
        request.httpMethod = "HEAD"
        let error: Error?
        do {
            _ = try await session.data(for: request)
            error = nil
        } catch let e {
            error = e
        }
        if let result { return result }
        return TLSProbeResult(host: host, trusted: false, issuerOrganization: nil, error: error?.localizedDescription ?? "no certificate")
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            return (.performDefaultHandling, nil)
        }
        let trusted = SecTrustEvaluateWithError(trust, nil)
        var names: X509Names?
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
            names = try? X509Names(der: [UInt8](SecCertificateCopyData(leaf) as Data))
        }
        result = TLSProbeResult(
            host: host, trusted: trusted, issuerOrganization: names?.issuerOrganization,
            issuerCommonName: names?.issuerCommonName, error: trusted ? nil : "not trusted")
        // We only needed the certificate: never send a request over it.
        return (.cancelAuthenticationChallenge, nil)
    }
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// Browses a set of Bonjour service types briefly and counts what answers.
private final class BonjourSurvey: @unchecked Sendable {
    let types: [String]
    private var counts: [String: Int] = [:]
    private var denied = false
    private var browsers: [NWBrowser] = []
    private let queue = DispatchQueue(label: "ferret.bonjour")

    init(types: [String]) {
        self.types = types
    }

    func run(for seconds: Double) async -> [String: Int]? {
        await withCheckedContinuation { continuation in
            queue.async {
                for type in self.types {
                    let browser = NWBrowser(for: .bonjour(type: type, domain: "local."), using: .tcp)
                    browser.browseResultsChangedHandler = { [weak self] results, _ in
                        self?.counts[type] = results.count
                    }
                    browser.stateUpdateHandler = { [weak self] state in
                        if case .failed = state { self?.denied = true }
                        if case .waiting = state { self?.denied = true }
                    }
                    browser.start(queue: self.queue)
                    self.browsers.append(browser)
                }
                self.queue.asyncAfter(deadline: .now() + seconds) {
                    self.browsers.forEach { $0.cancel() }
                    continuation.resume(returning: self.denied && self.counts.isEmpty ? nil : self.counts)
                }
            }
        }
    }
}

func withTimeout<T: Sendable>(seconds: Double, fallback: T, _ work: @escaping @Sendable () async -> T) async -> T {
    await withTaskGroup(of: T?.self) { group in
        group.addTask { await work() }
        group.addTask {
            try? await Task.sleep(for: .seconds(seconds))
            return nil
        }
        let first = await group.next() ?? nil
        group.cancelAll()
        return first ?? fallback
    }
}

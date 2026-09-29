import Foundation
import Testing
@testable import FerretKit

@Suite struct SafetySnootTests {
    /// Done-when from the spec: detects each simulated attack in practice mode.
    @Test(arguments: PracticeScenario.allCases)
    func detectsEachPracticeScenario(scenario: PracticeScenario) async {
        let report = await SafetySnoot.run(probes: scenario.probes, isPractice: true)
        #expect(report.isPractice)
        #expect(report.verdict == scenario.expected.verdict, "\(scenario): \(report.findings.map(\.title))")
        if let check = scenario.expected.check {
            let result = report.results.first { $0.kind == check }
            #expect(result?.findings.isEmpty == false, "\(scenario) should be flagged by \(check)")
        } else {
            #expect(report.findings.allSatisfy { $0.severity == .info })
        }
        #expect(report.skippedChecks.isEmpty)
    }

    @Test func greenNeverSaysSafe() {
        #expect(!SnootVerdict.green.title.lowercased().contains("safe"))
        #expect(SnootVerdict.green.advice.contains("expert"))
    }

    @Test func skippedChecksDoNotCountAsPasses() {
        let result = SafetySnoot.checkWiFi(WiFiProbeResult(ssid: nil, security: .unknown))
        guard case .skipped = result.status else {
            Issue.record("unknown security must be skipped, not passed")
            return
        }
    }

    @Test func singleUnexpectedIssuerIsOnlyInformational() async {
        struct OneOdd: SnootProbes {
            func resolve(_ name: String) async -> DNSProbeResult {
                SafetySnoot.knownAnswers[name].map { .addresses(Array($0)) } ?? .nameNotFound
            }
            func tlsHandshake(host: String) async -> TLSProbeResult {
                TLSProbeResult(host: host, trusted: true,
                               issuerOrganization: host == "www.apple.com" ? "New CA Inc" : SafetySnoot.tlsHosts[host]!.first)
            }
            func fetchCaptivePortalCheck() async -> HTTPProbeResult? {
                HTTPProbeResult(statusCode: 200, body: SafetySnoot.captivePortalBody)
            }
            func wifi() async -> WiFiProbeResult { WiFiProbeResult(ssid: "x", security: .personal) }
            func bonjourServices() async -> [String: Int]? { [:] }
        }
        let report = await SafetySnoot.run(probes: OneOdd())
        #expect(report.verdict == .green)
        #expect(report.findings.count == 1)
    }
}

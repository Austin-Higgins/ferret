import FerretKit
import SwiftData
import SwiftUI

/// The 10-second Wi-Fi check, plus practice mode with simulated attacks.
struct SafetySnootView: View {
    @State private var report: SnootReport?
    @State private var running = false
    @State private var practice: PracticeScenario?
    @AppStorage(FerretSettings.Key.discreetMode, store: SharedContainer.defaults) private var discreet = false
    @Environment(CaptureController.self) private var capture
    @Environment(\.modelContext) private var modelContext

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    if running {
                        if !discreet { MascotView(mood: .sniffing) }
                        ProgressView("Sniffing around this network…")
                    } else if let report {
                        ResultCard(report: report, discreet: discreet)
                    } else {
                        if !discreet { MascotView(mood: .sitting) }
                        Text("Check this Wi-Fi before you use it. Takes about ten seconds.")
                            .multilineTextAlignment(.center)
                    }

                    Button {
                        run(practice: nil)
                    } label: {
                        Text(report == nil ? "Run Safety Snoot" : "Run again")
                            .frame(maxWidth: .infinity, minHeight: 50)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(running)

                    Menu {
                        ForEach(PracticeScenario.allCases) { scenario in
                            Button(scenario.title) { run(practice: scenario) }
                        }
                    } label: {
                        Label("Practice mode", systemImage: "graduationcap")
                    }
                    .disabled(running)

                    if let practice, report?.isPractice == true {
                        Text(practice.story)
                            .font(.callout)
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 12))
                    }

                    ExpertHelpSection()
                }
                .padding()
            }
            .navigationTitle("Safety Snoot")
        }
    }

    private func run(practice scenario: PracticeScenario?) {
        running = true
        practice = scenario
        Task {
            let probes: SnootProbes = scenario?.probes ?? NetworkSnootProbes()
            let result = await SafetySnoot.run(probes: probes, isPractice: scenario != nil)
            report = result
            running = false
            if scenario == nil, let id = capture.sessionID {
                let descriptor = FetchDescriptor<CaseFile>(predicate: #Predicate { $0.sessionID == id })
                if let file = try? modelContext.fetch(descriptor).first {
                    file.snootVerdict = result.verdict.rawValue
                }
            }
        }
    }
}

struct ResultCard: View {
    let report: SnootReport
    let discreet: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 14) {
                if !discreet { MascotView(mood: report.verdict.mood, size: 72) }
                VStack(alignment: .leading, spacing: 4) {
                    if report.isPractice {
                        Text("PRACTICE").font(.caption.weight(.bold)).foregroundStyle(.secondary)
                    }
                    Text(report.verdict.title).font(.title3.weight(.semibold))
                    if let name = report.networkName { Text(name).font(.subheadline).foregroundStyle(.secondary) }
                }
            }
            Text(report.verdict.advice)

            ForEach(report.results) { result in
                CheckRow(result: result)
            }
        }
        .padding()
        .background(color.opacity(0.15), in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(color, lineWidth: 2))
        .accessibilityElement(children: .contain)
    }

    private var color: Color {
        switch report.verdict {
        case .green: return .green
        case .yellow: return .yellow
        case .red: return .red
        }
    }
}

struct CheckRow: View {
    let result: SnootCheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label {
                Text(result.kind.title).font(.headline)
            } icon: {
                Image(systemName: icon).foregroundStyle(iconColor)
            }
            switch result.status {
            case .passed:
                Text("Nothing unusual found.").font(.callout).foregroundStyle(.secondary)
            case .skipped(let why):
                Text("Not checked: \(why)").font(.callout).foregroundStyle(.secondary)
            case .findings:
                ForEach(result.findings) { finding in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title).font(.callout.weight(.semibold))
                        Text(finding.detail).font(.callout)
                    }
                }
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var icon: String {
        switch result.worstSeverity {
        case .danger: return "xmark.octagon.fill"
        case .warning: return "exclamationmark.triangle.fill"
        default:
            if case .skipped = result.status { return "minus.circle" }
            return "checkmark.circle.fill"
        }
    }

    private var iconColor: Color {
        switch result.worstSeverity {
        case .danger: return .red
        case .warning: return .orange
        default:
            if case .skipped = result.status { return .secondary }
            return .green
        }
    }
}

/// Ferret stands on expert shoulders rather than acting as the last word.
struct ExpertHelpSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Worried about your phone?").font(.headline)
            Text("Ferret can't prove a phone is free of spyware, and most stalking happens through shared accounts. These groups can help:")
                .font(.callout)
                .foregroundStyle(.secondary)
            ForEach(ExpertResource.all) { resource in
                Link(destination: resource.url) {
                    VStack(alignment: .leading) {
                        Text(resource.name).font(.callout.weight(.semibold))
                        Text(resource.summary).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

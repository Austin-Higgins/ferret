import FerretKit
import StoreKit
import SwiftUI

struct SettingsView: View {
    @AppStorage(FerretSettings.Key.storageCapMB, store: SharedContainer.defaults) private var storageCapMB = FerretSettings.defaultStorageCapMB
    @AppStorage(FerretSettings.Key.discreetMode, store: SharedContainer.defaults) private var discreet = false
    @AppStorage(FerretSettings.Key.learnMode, store: SharedContainer.defaults) private var learnMode = true
    @Environment(CaptureController.self) private var capture
    @Environment(TrafficStore.self) private var store
    @Environment(\.modelContext) private var modelContext
    @State private var confirmDelete = false
    @State private var usedBytes = SharedContainer.totalCaptureBytes()

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    NavigationLink("Case files") { CasesView() }
                }

                Section {
                    Picker("Storage limit", selection: $storageCapMB) {
                        ForEach(FerretSettings.storageCapChoicesMB, id: \.self) { mb in
                            Text(mb >= 1024 ? "\(mb / 1024) GB" : "\(mb) MB").tag(mb)
                        }
                    }
                    LabeledContent("Used", value: usedBytes.bytesText)
                    Button("Delete all captures", role: .destructive) { confirmDelete = true }
                        .disabled(capture.isCapturing)
                } header: {
                    Text("Storage")
                } footer: {
                    Text("When a capture reaches the limit, Ferret deletes its oldest packets first.")
                }

                Section {
                    Toggle("Learn mode", isOn: $learnMode)
                } footer: {
                    Text("Shows a ? beside fields. Tap it for a short, plain explanation.")
                }

                Section {
                    Toggle("Discreet mode", isOn: $discreet)
                        .onChange(of: discreet) { _, on in
                            UIApplication.shared.setAlternateIconName(on ? "DiscreetIcon" : nil)
                        }
                } header: {
                    Text("Safety")
                } footer: {
                    Text("For phones someone else may check: a neutral icon, plain wording, no mascot, and a quick-exit button on every screen.")
                }

                Section("Privacy") {
                    Label(FerretCopy.localOnlyPromise, systemImage: "lock.iphone")
                    NavigationLink("How Ferret handles data") { PrivacyView() }
                }

                Section("Support Ferret") {
                    TipJarView()
                    Link("GitHub Sponsors", destination: URL(string: "https://github.com/sponsors/Austin-Higgins")!)
                }

                Section("About") {
                    LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0")
                    Link("Source code (MIT)", destination: URL(string: "https://github.com/Austin-Higgins/ferret")!)
                    NavigationLink("Acknowledgements") { AcknowledgementsView() }
                }
            }
            .navigationTitle("Settings")
            .onAppear { usedBytes = SharedContainer.totalCaptureBytes() }
            .confirmationDialog("Delete every capture on this iPhone?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("Delete all", role: .destructive) {
                    try? SharedContainer.deleteAllCaptures()
                    try? modelContext.delete(model: CaseFile.self)
                    Task { await store.clear() }
                    usedBytes = SharedContainer.totalCaptureBytes()
                }
            } message: {
                Text("This removes all case files and packets. It can't be undone.")
            }
        }
    }
}

struct PrivacyView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Nothing leaves your iPhone.").font(.title3.weight(.semibold))
                Text("Ferret captures traffic with a local VPN that runs entirely on this device. Traffic still goes straight to where your apps were sending it; Ferret doesn't route it through any server.")
                Text("No accounts, analytics or telemetry. Captures are stored in Ferret's private storage, capped at the limit you choose, and deleted with one tap.")
                Text("Ferret can't read encrypted content. It sees the names your phone looks up, which servers it connects to, and the unencrypted parts of each connection's setup.")
                Text("Safety Snoot contacts a few well-known sites (Apple, Google, Cloudflare, Wikipedia and public DNS names) to test the network. It sends no personal data.")
            }
            .padding()
        }
        .navigationTitle("Privacy")
    }
}

struct AcknowledgementsView: View {
    var body: some View {
        List {
            Section("lwIP (BSD licence)") { Text("Userspace TCP/IP stack by Adam Dunkels and contributors.") }
            Section("Public Suffix List (MPL 2.0)") { Text("Mozilla Foundation. Used to group subdomains.") }
            Section("Wireshark sample captures") { Text("Used only in Ferret's tests. Ferret contains no Wireshark code.") }
        }
        .navigationTitle("Acknowledgements")
    }
}

/// One-time tips through the App Store. Product IDs must exist in App Store Connect.
struct TipJarView: View {
    static let productIDs = ["tip.small", "tip.medium", "tip.large"].map { (Bundle.main.bundleIdentifier ?? "ferret") + "." + $0 }
    @State private var products: [Product] = []
    @State private var thanks = false

    var body: some View {
        Group {
            if products.isEmpty {
                Text("Tips are available in the App Store version.").foregroundStyle(.secondary)
            } else {
                ForEach(products) { product in
                    Button {
                        Task {
                            if case .success(.verified(let transaction))? = try? await product.purchase() {
                                await transaction.finish()
                                thanks = true
                            }
                        }
                    } label: {
                        LabeledContent(product.displayName, value: product.displayPrice)
                    }
                }
                if thanks { Text("Thank you! The ferret is delighted.") }
            }
        }
        .task { products = (try? await Product.products(for: Self.productIDs))?.sorted { $0.price < $1.price } ?? [] }
    }
}

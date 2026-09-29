import FerretKit
import SwiftData
import SwiftUI

@main
struct FerretApp: App {
    @State private var store: TrafficStore
    @State private var capture: CaptureController
    let container: ModelContainer

    init() {
        let store = TrafficStore()
        _store = State(initialValue: store)
        _capture = State(initialValue: CaptureController(store: store))
        container = try! ModelContainer(for: CaseFile.self, SniffTestRecord.self)
        FerretShortcuts.updateAppShortcutParameters()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
                .environment(capture)
                .task {
                    capture.modelContext = container.mainContext
                    await capture.load()
                }
                .onOpenURL { url in
                    Task { try? await store.open(fileAt: url) }
                }
        }
        .modelContainer(container)
    }
}

struct RootView: View {
    @AppStorage(FerretSettings.Key.discreetMode, store: SharedContainer.defaults) private var discreet = false
    @State private var tab = 0
    @State private var coverShown = false

    var body: some View {
        TabView(selection: $tab) {
            CaptureView()
                .tabItem { Label(discreet ? "Session" : "Capture", systemImage: "dot.radiowaves.left.and.right") }
                .tag(0)
            TrafficListView()
                .tabItem { Label("Traffic", systemImage: "list.bullet.rectangle") }
                .tag(1)
            SuspectsView()
                .tabItem { Label(discreet ? "Flagged" : "Suspects", systemImage: "eye.trianglebadge.exclamationmark") }
                .tag(2)
            SafetySnootView()
                .tabItem { Label(discreet ? "Wi-Fi check" : "Safety Snoot", systemImage: "wifi.exclamationmark") }
                .tag(3)
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gear") }
                .tag(4)
        }
        .overlay(alignment: .topTrailing) {
            if discreet {
                Button {
                    tab = 0
                    coverShown = true
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.title2)
                        .padding(10)
                }
                .accessibilityLabel("Quick exit")
            }
        }
        .fullScreenCover(isPresented: $coverShown) {
            QuickExitCover { coverShown = false }
        }
    }
}

/// Quick exit: instantly covers Ferret with a plain checklist. Long-press to return.
struct QuickExitCover: View {
    var dismiss: () -> Void
    @State private var items = ["Milk", "Bread", "Call dentist", "Water plants"]

    var body: some View {
        NavigationStack {
            List(items, id: \.self) { item in
                Label(item, systemImage: "circle")
            }
            .navigationTitle("To do")
        }
        .onLongPressGesture(minimumDuration: 2) { dismiss() }
    }
}

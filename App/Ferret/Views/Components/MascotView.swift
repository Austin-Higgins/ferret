import FerretKit
import SwiftUI

/// The ferret detective, drawn with shapes so it scales and animates cleanly.
/// It sniffs while capturing and sits when stopped; Safety Snoot results
/// show a happy, twitchy or growling snoot.
struct MascotView: View {
    var mood: MascotMood
    var size: CGFloat = 140

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var phase = false

    var body: some View {
        ZStack {
            // Ears
            HStack(spacing: size * 0.42) {
                Circle().fill(fur).frame(width: size * 0.26)
                Circle().fill(fur).frame(width: size * 0.26)
            }
            .offset(y: -size * 0.3)
            // Head
            Ellipse()
                .fill(fur)
                .frame(width: size * 0.8, height: size * 0.66)
            // Mask band
            Capsule()
                .fill(mask)
                .frame(width: size * 0.7, height: size * 0.2)
                .offset(y: -size * 0.04)
            // Eyes
            HStack(spacing: size * 0.2) {
                eye
                eye
            }
            .offset(y: -size * 0.04)
            // Snout
            Ellipse()
                .fill(.white)
                .frame(width: size * 0.36, height: size * 0.24)
                .offset(y: size * 0.16)
            // Nose
            Ellipse()
                .fill(noseColor)
                .frame(width: size * 0.12, height: size * 0.08)
                .offset(y: size * 0.1)
                .scaleEffect(noseScale)
            // Whiskers
            HStack(spacing: size * 0.44) {
                whiskers.scaleEffect(x: -1)
                whiskers
            }
            .offset(y: size * 0.17)
            .rotationEffect(.degrees(whiskerAngle))
            // Deerstalker brim when sitting on the case
            if mood == .sitting || mood == .happy {
                Capsule()
                    .fill(Color.brown.opacity(0.85))
                    .frame(width: size * 0.56, height: size * 0.1)
                    .offset(y: -size * 0.34)
            }
        }
        .frame(width: size, height: size)
        .offset(x: shakeOffset, y: bounceOffset)
        .onAppear { animate() }
        .onChange(of: mood) { animate() }
        .accessibilityElement()
        .accessibilityLabel(accessibilityText)
    }

    private var fur: Color { Color(red: 0.93, green: 0.84, blue: 0.7) }
    private var mask: Color { Color(red: 0.45, green: 0.33, blue: 0.24) }
    private var noseColor: Color { mood == .growling ? .red : Color(red: 0.85, green: 0.45, blue: 0.5) }

    private var eye: some View {
        Group {
            if mood == .happy {
                Capsule().fill(.black).frame(width: size * 0.1, height: size * 0.035)
            } else {
                Circle().fill(.black).frame(width: size * 0.09)
            }
        }
    }

    private var whiskers: some View {
        VStack(spacing: size * 0.03) {
            ForEach(0..<3) { _ in
                Capsule().fill(.gray.opacity(0.7)).frame(width: size * 0.2, height: 1.5)
            }
        }
    }

    private var active: Bool { phase && !reduceMotion }
    private var noseScale: CGFloat { (mood == .sniffing || mood == .twitchy) && active ? 1.25 : 1 }
    private var whiskerAngle: Double { mood == .twitchy && active ? 4 : 0 }
    private var bounceOffset: CGFloat { mood == .happy && active ? -6 : 0 }
    private var shakeOffset: CGFloat { mood == .growling && active ? 3 : 0 }

    private var accessibilityText: String {
        switch mood {
        case .sniffing: return "Ferret sniffing"
        case .sitting: return "Ferret sitting"
        case .happy: return "Happy ferret"
        case .twitchy: return "Twitchy ferret"
        case .growling: return "Growling ferret"
        }
    }

    private func animate() {
        phase = false
        guard !reduceMotion, mood != .sitting else { return }
        let duration: Double = mood == .growling ? 0.08 : mood == .sniffing ? 0.35 : 0.5
        withAnimation(.easeInOut(duration: duration).repeatForever(autoreverses: true)) {
            phase = true
        }
    }
}

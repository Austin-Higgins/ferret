# Device testing checklist

These are the spec's "done when" tests that need a real iPhone and the paid developer program.

| Feature | Test | How |
| --- | --- | --- |
| Capture | Runs 30 minutes without breaking connectivity, extension under 50 MB | Start a capture, stream video, browse, use FaceTime and switch between Wi-Fi and cellular for 30 minutes. Capture > Diagnostics shows the tunnel's memory now and at peak, and marks the 30-minute soak as passed or over budget; the peak is also saved on the case file. Cross-check with Xcode's memory gauge for `FerretTunnel`. |
| Traffic list | 1,000 connections scroll smoothly | Capture a busy browsing session, or open a large pcap, then scroll the Traffic tab with Instruments' Animation Hitches. |
| Connection detail | Every field matches Wireshark on the same pcap | Automated in CI (`WiresharkParityTests`). Spot-check by exporting a capture and opening it in Wireshark. |
| Suspects | Wording says the phone contacted them, never names an app | Covered by tests; review the screen copy. |
| Safety Snoot | Detects each simulated attack in practice mode | Automated in CI. On devices, also run it on home Wi-Fi, a hotspot with a captive portal, and an open network. |
| pcap export | Opens cleanly in Wireshark on a Mac | AirDrop both formats to a Mac and open them in Wireshark. |

Networks to try: home Wi-Fi, cellular, a captive-portal hotspot, IPv6-only (NAT64) Wi-Fi,
and a network with a LAN DNS resolver (for example 192.168.1.1).

## v1.1 checks

| Feature | Done when | How |
| --- | --- | --- |
| Sniff test | The labelled window lists every domain first contacted during it | Capture > Sniff test. Close other apps, run a 30-second window while using one app, and compare the list with the Traffic tab for the same minute. The core rule is tested in CI. |
| Before/after diff | Shows the domains present in only one capture | Settings > Case files > Compare. Capture before and after installing an app. Tested in CI with two fixture captures. |
| Throughput graph | Shows bytes per second live while capturing | Start a capture and stream a video; the graph on the Capture screen should rise within two seconds. |
| Speed on older iPhones | Analysis keeps up on the oldest supported phone | CI prints the analyzer's packets per second (`PerformanceTests`). On an iPhone XS or SE (2nd gen), open a large pcap and check the Traffic tab stays responsive. |

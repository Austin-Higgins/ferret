# Third-party components

| Component | Use | Licence |
| --- | --- | --- |
| [lwIP](https://savannah.nongnu.org/projects/lwip/) 2.2.1 | Userspace TCP/IP stack in the packet tunnel (`Sources/CLwIP`) | BSD 3-Clause, see `Sources/CLwIP/LICENSE` |
| [Public Suffix List](https://publicsuffix.org) | Grouping subdomains under registrable domains (`Sources/FerretKit/Resources/public_suffix_list.dat`) | MPL 2.0 (data file, unmodified) |
| IANA Service Name and Port Number Registry | Naming well-known ports | Public |
| Wireshark sample and test captures | Test fixtures only (`Tests/*/Fixtures`), not shipped in the app | Distributed by the Wireshark project for testing |

Apple frameworks used: NetworkExtension, Network, SwiftUI, Swift Charts, SwiftData,
ActivityKit, WidgetKit, App Intents, CryptoKit, Security, StoreKit.

The tracker seed list (`Sources/FerretKit/Resources/trackers.tsv`) was written for Ferret
and is released under the MIT licence with the rest of the project.

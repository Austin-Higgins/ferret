# Tracker lists

Suspects matches contacted domains, and all their subdomains, against a list of known tracker domains.

Ferret ships a small seed list written for the project (`Sources/FerretKit/Resources/trackers.tsv`, MIT).
It is intentionally conservative and easy to audit.

## Swapping in a larger list

`TrackerList` reads two formats:

- Ferret TSV: `domain<TAB>organisation<TAB>category`
- hosts files: `0.0.0.0 example.com` (`TrackerList(hostsFile:)`)

Before shipping a third-party list, check its licence. The spec asks for permissive licences
and no non-commercial terms, so a future paid tier stays possible. Several popular lists are
GPL or CC BY-NC-SA and don't qualify.

This is still an open question in the spec: which list, or lists, to ship.

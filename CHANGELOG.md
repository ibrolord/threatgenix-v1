# Changelog

## 1.0.0-preview.1 - 2026-07-26

- Published the first complete ThreatGenix product shell as open source
- Added exact-origin ownership proof for live Nuclei targets
- Required the managed isolated runner for live Nuclei execution
- Disabled authenticated live scans until a secret-safe broker is available
- Rejected non-global scan targets, including carrier-grade NAT ranges
- Bounded evidence uploads, GitHub archive downloads, parsed findings, and
  ScoutSuite traversal
- Added persistent token revocation on logout and password reset
- Added auth endpoint rate limits and stronger short-lived verification codes
- Required independent encryption keys in production and staging

# Security policy

## Supported version

Security fixes are currently applied to the latest commit on `main`.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting feature on this repository. Include:

- the affected component and commit
- clear reproduction steps
- expected and observed behavior
- impact and any known preconditions
- a suggested fix, if you have one

Do not include real credentials, customer data, or targets you are not
authorized to test. You should receive an acknowledgment within five business
days.

## Scope note

ThreatGenix v1 is a research preview, not a production security control. The
default runtime does not execute live scanners. Live Nuclei execution requires a
managed isolated runner and exact-origin ownership proof. Authenticated live
scanning remains disabled until a secret-safe credential broker exists.

## Dependency advisory disposition

The release gate requires zero known critical or high-severity npm advisories.
The v1 frontend is a client-rendered application and does not use React Router
SSR, RSC, or user-controlled navigation destinations. Two upstream
moderate-severity React Router advisories remain open because currently released
v6 and v7 versions have overlapping advisory ranges. They are not reachable in
the v1 usage described above and will be upgraded when an audit-clean upstream
release is available.

WeasyPrint also has an upstream moderate-severity advisory with no patched
release. It applies only when rendering untrusted HTML with
`presentational_hints=True`; ThreatGenix renders its own report template and
does not enable presentational hints.

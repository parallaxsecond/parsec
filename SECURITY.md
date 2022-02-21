# Security policy

Security is of paramount importance to the Parsec project. We do all we can to identify and fix
issues, however some problems might slip through the cracks. Any efforts towards responsible
disclosure of security problems are greatly appreciated and your contributions will be acknowledged.

## Supported versions

Currently only the most recent version of the Parsec service is eligible for patching. This could
change in the future.

| Version          | Supported |
|------------------|-----------|
| 0.7.0 and higher | ✅       |
| 0.6.0 and lower  | ❌       |

## Our disclosure policy

All security vulnerabilities affecting the Parsec service - including those reported using the steps
highlighted below, those discovered during routine testing, and those found in our dependency tree
either through `cargo-audit` or otherwise - will receive [security
advisories](https://github.com/parallaxsecond/parsec/security/advisories) in a timely manner. The
advisories should include sufficient information about the cause, effect, and possible mitigations
for the vulnerability. If any information is missing, or you would like to raise a question about
the advisories, please open an issue in [our repo](https://github.com/parallaxsecond/parsec).

Efforts to mitigate for the reported vulnerabilities will be tracked using Github issues linked to
the corresponding advisories.

## Reporting a vulnerability

To report a vulnerability, please send an email to
[cncf-parsec-maintainers@lists.cncf.io](mailto:cncf-parsec-maintainers@lists.cncf.io). We will reply
to acknowledge your report and we'll strive to keep you in the loop as we try to reach a resolution.

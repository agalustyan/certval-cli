# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## Unreleased

- `verify` checks ML-DSA and SLH-DSA signatures: certval is built with its `pqc` feature.

## [0.1.0-rc.1] - 2026-10-31

Initial release of the `certval` command: `x509`, `crl`, `asn1parse`, `verify` (path validation by
certval, against anchor files or a compiled-in FPKI or webpki store, with optional revocation
checking against CRL files or over the network) and `ocsp` (query a responder or describe a saved response). MSRV 1.89.

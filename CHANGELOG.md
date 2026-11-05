# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## Unreleased

- `verify` checks ML-DSA and SLH-DSA signatures: certval is built with its `pqc` feature.
- `cms encrypt`, `cms decrypt`, `cms sign` and `cms verify`, by certval-cms: EnvelopedData and
  AuthEnvelopedData to RSA (key transport), EC (key agreement) and ML-KEM (KEM) recipients, and
  SignedData with RSA PKCS #1 v1.5 and RSASSA-PSS, ECDSA and ML-DSA, detached or not, with each
  signer's certificate validated against trust anchors or a store when named.
- `--crypto` chooses the implementation that performs the cryptographic operations of `verify` and
  the `cms` commands: certval's software, or with the `openssl` feature, OpenSSL through
  certval-openssl. `--only` leaves software out.

## [0.1.0-rc.1] - 2026-10-31

Initial release of the `certval` command: `x509`, `crl`, `asn1parse`, `verify` (path validation by
certval, against anchor files or a compiled-in FPKI or webpki store, with optional revocation
checking against CRL files or over the network) and `ocsp` (query a responder or describe a saved response). MSRV 1.89.

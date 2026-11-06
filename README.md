# certval-cli

`certval`, an openssl-style command-line tool for X.509 certificates, CRLs, OCSP, CMS and DER, with
certification path validation by [certval](https://github.com/carl-wallace/rust-pki): RFC 5280 and
RFC 5937, including certificate policies, name constraints and cross-certified (bridge) topologies.
CMS messages are encrypted, decrypted, signed and verified by
[certval-cms](https://github.com/carl-wallace/certval-cms).

```sh
cargo install certval-cli
```

This installs a command named `certval`. The subcommands take openssl's names; the flags are this
tool's own. Every command reads DER, or PEM where the file holds it.

## Commands

### `certval x509` describes a certificate

```text
$ certval x509 GoodCACert.crt
Subject:     CN=Good CA,O=Test Certificates 2011,C=US
Issuer:      CN=Trust Anchor,O=Test Certificates 2011,C=US
Serial:      02
Version:     V3
Not before:  2010-01-01T08:30:00Z
Not after:   2030-12-31T08:30:00Z
Public key:  RSA Encryption (1.2.840.113549.1.1.1), 2048 bits
Signature:   SHA256 with RSA Encryption (1.2.840.113549.1.1.11)
SHA-256:     86:D2:18:37:...:34:3F
Extensions:
    id-ce-keyUsage (2.5.29.15), critical
        KeyCertSign, CRLSign
    id-ce-basicConstraints (2.5.29.19), critical
        CA: true
    ...
```

`--subject`, `--issuer` and `--fingerprint` print one field alone. `--der-out FILE` also writes the
certificate as DER, which converts a PEM file.

### `certval crl` describes a CRL

Issuer, this and next update, the number of revoked certificates and the CRL's extensions.
`--revoked` lists each entry with its revocation date and reason.

### `certval asn1parse` dumps DER

One line per element, in `openssl asn1parse`'s layout, which is familiar enough to keep. Object
identifiers are named. `--nested` also opens OCTET STRING and BIT STRING contents that are
themselves DER, such as extension values and public keys.

### `certval verify` validates a certification path

```text
$ certval verify --anchor TrustAnchorRootCertificate.crt --chain GoodCACert.crt ValidCertificatePathTest1EE.crt
path 0: Valid
    anchor        CN=Trust Anchor,O=Test Certificates 2011,C=US
    intermediate  CN=Good CA,O=Test Certificates 2011,C=US
    target        CN=Valid EE Certificate Test1,O=Test Certificates 2011,C=US
```

Trust anchors come from `--anchor` files or from a store compiled into the binary, `--store fpki`
or `--store webpki_root_certs` (`--list-stores` lists them). `--chain` adds intermediates. Both
flags repeat, and a PEM file may hold several certificates, so a bundle can be named once. Every
path the sources can assemble is validated and reported, and a failure names the check that failed:

```text
path 0: SignatureVerificationFailure
```

`--settings FILE` takes certval's JSON path validation settings: the time of interest, the initial
policy set, name constraint and key usage handling. Revocation is not checked unless
`--check-revocation` (or a settings file) asks for it, as with `openssl verify`. `--crl FILE`
(repeatable) names CRLs to consult first, as `openssl verify -CRLfile` does; beyond those, CRLs
and OCSP responses are fetched over the network.

`--crypto` chooses the implementation that hashes and verifies signatures; see [Choosing the
cryptography](#choosing-the-cryptography).

### `certval cms` encrypts, decrypts, signs and verifies

```sh
certval cms encrypt --recip alice.crt --recip bob.crt --in message.txt --out message.der
certval cms decrypt --in message.der --cert alice.crt --key alice.key --out message.txt
certval cms sign --in message.txt --cert signer.crt --key signer.key --out signed.der
certval cms verify --in signed.der --anchor ca.crt --out message.txt
```

```text
$ certval cms verify --in signed.der --anchor ca.crt
signer CN=signer: signature verified, certificate validated
```

`encrypt` makes an AuthEnvelopedData for a GCM `--content` algorithm (the default, AES-256-GCM) and
an EnvelopedData for CBC. Each recipient's certificate decides its recipient type: key transport
for an RSA key (`--key-transport`, RSAES-OAEP with SHA-256 by default), key agreement for an EC key
and a KEM for an ML-KEM key (`--kdf`, `--wrap` and `--ukm`). `decrypt` takes the recipient's
certificate and its PKCS #8 private key, or without them, a key the `--crypto` implementation
holds for a recipient the message names (see [Keys an implementation
holds](#keys-an-implementation-holds)).

`sign` signs with the PKCS #8 key for `--cert`, or without `--key`, with a key the `--crypto`
implementation holds, for `--cert`, `--email` or `--skid`. It signs with `--digest`, and `--pss`
for RSASSA-PSS. It
adds the content-type, message-digest and signing-certificate-v2 attributes; `--no-ess-cert-id`
leaves out the last. `--detached` leaves the content out, `--include none` leaves the signer's
certificate out, and `--certfile` adds certificates such as intermediates. `verify` verifies each
signer's signature, and with `--anchor` or `--store` validates its certificate too, through the CA
certificates the message contains and any `--chain`. `--content` names the content of a detached
signature, and `--policy any` accepts a message if any signer verifies.

Messages are read as DER or PEM and written as DER, or as PEM (`--outform pem`) labelled `CMS`,
which `openssl cms` reads with `-inform DER` or `-inform PEM`. S/MIME is neither read nor written.

### `certval ocsp` queries a responder

```sh
certval ocsp --issuer issuer.crt cert.crt          # responder taken from the certificate's AIA
certval ocsp --issuer issuer.crt --url http://ocsp.example cert.crt --nonce --out response.der
certval ocsp --response response.der               # describe a saved response
```

Prints the response status, the responder, and each certificate's status with its this and next
update, and with `--nonce` whether the nonce was echoed. **The response's signature is not
verified**, and the output says so: certval verifies OCSP responses as part of checking a path.
`certval verify --check-revocation` is the command that does that.

### `certval ca` issues certificates, signs CRLs and answers OCSP requests

```sh
certval ca issue --csr alice.csr --cert ca.crt --key ca.key --eku email-protection --out alice.crt
certval ca issue --public-key kem.pub --subject "CN=Bob" --san-email bob@example.com \
    --key-usage key-encipherment --cert ca.crt --key ca.key --out bob.crt
certval ca issue --csr sub.csr --ca --path-len 0 --cert ca.crt --key ca.key --out sub.crt
certval ca crl --crl-number 2 --revoke 65:09:70:E1 --cert ca.crt --key ca.key --out ca.crl
certval ca ocsp --request req.der --issuer ca.crt --revoke 65:09:70:E1 \
    --cert ca.crt --key ca.key --out resp.der
```

For making test material with any implementation's keys: the CA's key is a PKCS #8 file, or
without `--key`, a key the `--crypto` implementation holds for `--cert` or `--skid` (see [Keys an
implementation holds](#keys-an-implementation-holds)), and it signs with `--digest`, or `--pss`
for RSASSA-PSS. `issue` needs a CA certificate whose key usage, if it has one, permits
keyCertSign; `crl`, cRLSign.

`issue` certifies the subject and key of a PKCS #10 request (`--csr`), whose signature it checks
and whose requested subject alternative names it copies, or a public key alone (`--public-key`,
with `--subject`), e.g. an ML-KEM key, which cannot sign a request. It adds subject and authority
key identifiers, and `--key-usage`, `--eku`, `--san-email` and `--san-dns`; `--ca` makes a CA
certificate (basic constraints, and keyCertSign and cRLSign unless `--key-usage` says otherwise).
The serial number is 16 random octets unless `--serial` gives one, and the certificate is valid
for `--days` (365) from now. Nothing else a request asks for is copied.

`crl` lists the `--revoke` serial numbers, with the CRL number and an authority key identifier
naming the CA's key, and a next update `--next-update-days` (7) away. `ocsp` answers each
certificate a request asks about: revoked when `--revoke` names it, good otherwise, and unknown for
a certificate of a CA other than `--issuer`. It echoes the request's nonce and includes the
responder's certificate. The responder is the CA, or a certificate the CA issued containing
id-kp-OCSPSigning.

Certificates and CRLs are written as DER, or with `--outform pem`, PEM; OCSP responses as DER.

### `certval req` makes a certificate request or a self-signed certificate

```sh
certval req --key alice.key --subject "CN=Alice" --san-email alice@example.com --out alice.csr
certval req --key root.key --subject "CN=Test Root" --x509 --ca --days 3650 --out root.crt
```

Signs with a key that has no certificate yet: a PKCS #8 key, taken into the `--crypto`
implementation as one, under software, OpenSSL, AWS-LC, Security.framework, which with the
`cryptokit` feature holds an ML-DSA key in CryptoKit, or CNG, for an RSA or EC key. PKCS #11 does
not offer such keys yet.
A request asks for the extensions `--ca`, `--key-usage`, `--eku`, `--san-email` and `--san-dns`
choose, as `openssl req -addext` does; with `--x509`, a self-signed certificate contains them, with
`--days` and `--serial` as for `ca issue`. A key that cannot sign, such as an ML-KEM key, has no
request: `ca issue --public-key` certifies it.

## Choosing the cryptography

`verify` and the `cms` commands take `--crypto`, which chooses the implementation that performs
their cryptographic operations:

| `--crypto` | Implementation | Offered |
|---|---|---|
| `software` | certval's and certval-cms's RustCrypto software (the default) | everywhere |
| `openssl` | the system's OpenSSL 3, through [certval-openssl](https://github.com/carl-wallace/certval-openssl) | with the `openssl` feature, not on Windows |
| `aws-lc` | AWS-LC, through [certval-awslc](https://github.com/carl-wallace/certval-awslc) | everywhere; its FIPS module with the `awslc-fips` feature |
| `security-framework` | Security.framework, through [certval-security-framework](https://github.com/carl-wallace/certval-security-framework); with the `cryptokit` feature, CryptoKit for ML-KEM-768/1024 and ML-DSA-65/87 signing and verification | macOS; `cryptokit` needs the 26 SDK to build and macOS 26 to run |
| `cng` | CNG, through [certval-cng](https://github.com/carl-wallace/certval-cng) | Windows |
| `pkcs11` | a PKCS #11 module, through [certval-pkcs11](https://github.com/carl-wallace/certval-pkcs11) | everywhere |

The choice is registered ahead of software, so software answers only what it declines; `--only`
leaves software out, so that every operation reaches the chosen implementation or fails. The private
key operations of `cms decrypt` and `cms sign` are performed by the chosen implementation either
way, so what its keys decline, such as ML-DSA signing by AWS-LC, or by Security.framework without
`cryptokit`, fails with or without `--only`. A PKCS #8 `--key` is imported into the chosen implementation; PKCS #11 takes keys
only from its token.

`pkcs11` loads the module `--pkcs11-module` names and uses the token `--pkcs11-token` labels, or the
first slot with a token present. It hashes and verifies through the module, and decrypts and signs
with keys on the token after logging in with `--pkcs11-pin`; content encryption and the public key
side of enveloping are software's. The three flags can be given as `CERTVAL_PKCS11_MODULE`,
`CERTVAL_PKCS11_TOKEN_LABEL` and `CERTVAL_PKCS11_USER_PIN`, which keeps the PIN off the command
line.

`openssl` needs OpenSSL 3 to build, `awslc-fips` CMake and Go, and `cryptokit` Xcode's Swift
toolchain with the 26 SDK:

```sh
cargo install certval-cli --features openssl
```

### Keys an implementation holds

`security-framework`, `cng` and `pkcs11` hold keys, each with its certificate: the keychain's
identities, the current user's personal certificate store, and the token's certificates with the
private keys of the same `CKA_ID`. `certval cred list` lists them, showing each certificate's
subject, issuer, serial number, validity, public key, key usage, extended key usage, subject
alternative names and subject key identifier:

```sh
certval cred list --crypto security-framework
certval cred list --crypto pkcs11 --pkcs11-module /usr/lib/softhsm/libsofthsm2.so
```

Without `--key`, `cms decrypt` decrypts with the key the implementation holds for the first
recipient the message names that it holds one for, and `cms sign` signs with the key for `--cert`,
for a certificate containing `--email`, or for the subject key identifier `--skid`, as `cred list`
shows it. The key must be the only one that matches and permits signing; when several do, `sign`
lists them so that one can be chosen with `--skid`.

```sh
certval cms decrypt --in message.der --crypto security-framework
certval cms sign --in message.txt --email alice@example.com --out signed.der --crypto cng
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success; for `verify`, at least one path is valid |
| 1 | `verify` found no valid path |
| 2 | an error: a file that cannot be read or decoded, a missing argument, a responder that cannot be reached |

## Not yet

`pkcs12` and `ts` are not here yet: `pkcs12` waits on a PKCS #12 builder on crates.io, and `ts` on
certval's move to cms `0.3.0-rc.1`. `req` under `--crypto pkcs11` waits on certval-pkcs11
offering keys that have no certificate.

## Testing

`cargo test` runs the unit tests with no setup. The command tests run the binary against rust-pki's
example files, named by an environment variable; when it is unset they say so and pass.

```sh
CERTVAL_CLI_EXAMPLES=../rust-pki/certval/tests/examples cargo test
```

The CMS tests run the binary against `openssl cms` in both directions, under each `--crypto`
choice with `--only`: what openssl encrypts or signs, `certval cms` decrypts or verifies, and the
reverse, with RSA, EC, ML-KEM and ML-DSA keys from a CA they make with openssl. A case a choice
declines is run to see it fail with `--only`, then without, unless its key performs it.
`CERTVAL_CMS_OPENSSL` names the `openssl` command; when it is unset they say so and pass. ML-KEM
and ML-DSA need OpenSSL 3.5 or later, and ML-KEM in CMS 3.6; with an older openssl those cases
are skipped and say so.

```sh
CERTVAL_CMS_OPENSSL=$(command -v openssl) cargo test --features openssl -- --nocapture
```

The `ca` tests use the same openssl. Under each `--crypto` choice with `--only`, a P-256 CA and,
with OpenSSL 3.5 or later, an ML-DSA-65 CA, both made by openssl, issue a certificate from an
openssl request, sign a CRL revoking it and answer an openssl OCSP request about it; openssl
verifies each, and `certval verify` validates the certificate and, with the CRL, finds it
revoked. They also issue an ML-KEM certificate from a public key, and check what `ca` refuses.

One CMS test puts an EC key and its certificate on a PKCS #11 token, as token objects it removes
afterwards, then lists, signs with and decrypts with it through `--crypto pkcs11`. It reads
`CERTVAL_PKCS11_MODULE`, `CERTVAL_PKCS11_TOKEN_LABEL` and `CERTVAL_PKCS11_USER_PIN`, as
certval-pkcs11's tests do; with the module or PIN unset it says so and passes. CI runs it on
SoftHSM.

`scripts/openssl-interop.sh` runs a wider matrix against openssl than the tests do, and prints it:
every RSA, EC, ML-KEM and ML-DSA parameter set, each key transport, KDF, key wrap and content
algorithm, for `ca`, a CA of each signing key type and a delegated OCSP responder, and for `req`,
a request and a self-signed certificate from each signing key, under every
`--crypto` choice, PKCS #11 included when a module is named. Each cell says whether the choice did
the case alone (`ok`), with software's help (`sw`), declined it (`no`), or failed. It is not part
of `cargo test`; `-h` gives its options.

```sh
cargo build --features openssl,cryptokit
OPENSSL=$(command -v openssl) scripts/openssl-interop.sh -c target/debug/certval
```

certval-cms is not on crates.io yet, and the providers' `cms` features are not released, so
`Cargo.toml`'s `[patch.crates-io]` takes them from neighboring checkouts (`../certval-cms`,
`../certval-awslc`, `../certval-cng`, `../certval-openssl`, `../certval-pkcs11`,
`../certval-security-framework`), and CI checks them out there. They go when they publish, and this
crate cannot publish before they do.

## License

Apache-2.0 OR MIT.

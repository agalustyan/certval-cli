//! `certval ca` against openssl: under each `--crypto` choice the binary offers, with `--only`, a CA
//! whose key openssl made issues a certificate from an openssl request, signs a CRL revoking it and
//! answers an openssl OCSP request about it, and openssl verifies each; certval's own `verify`
//! validates the certificate, and with the CRL, finds it revoked. The CAs are P-256 and, with
//! OpenSSL 3.5 or later, ML-DSA-65, which a choice that cannot sign with ML-DSA declines.
//!
//! Also: an ML-KEM certificate issued from a public key alone, and what `ca` refuses: a signer that
//! is not a CA, a request whose signature does not verify, and a delegated OCSP responder without
//! id-kp-OCSPSigning.
//!
//! `CERTVAL_CMS_OPENSSL` names the `openssl` command, as for the CMS tests; when it is unset each
//! test says so and passes.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{certval, certval_with, cryptos, Case, OpenSsl};

/// A directory of the test's own holding the CAs, the end entity's key and request, and its OCSP
/// request to each CA.
struct Pki {
    dir: PathBuf,
    cas: Vec<(&'static str, Vec<Case>)>,
}

impl Pki {
    fn new(openssl: &OpenSsl, test: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("certval-cli-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("openssl.cnf"),
            "[req]\ndistinguished_name = dn\n[dn]\n",
        )
        .unwrap();
        let o = |args: &[&str]| openssl.run(&dir, args);
        let mut cas = vec![(
            "ec",
            vec!["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
            vec![],
        )];
        if openssl.post_quantum() {
            cas.push((
                "dsa",
                vec!["-newkey", "ML-DSA-65"],
                vec![Case::MlDsaSigning],
            ));
        }
        for (name, key, _) in &cas {
            let mut req = vec!["req", "-x509"];
            req.extend(key);
            let (keyout, out, subject) = (
                format!("ca-{name}.key"),
                format!("ca-{name}.crt"),
                format!("/CN=certval-cli {name} CA"),
            );
            req.extend([
                "-nodes",
                "-keyout",
                &keyout,
                "-out",
                &out,
                "-subj",
                &subject,
                "-days",
                "1",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=keyCertSign,cRLSign",
            ]);
            o(&req);
        }
        o(&[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "ee.key",
        ]);
        o(&[
            "req",
            "-new",
            "-key",
            "ee.key",
            "-subj",
            "/CN=certval-cli end entity",
            "-addext",
            "subjectAltName=email:ee@example.com",
            "-out",
            "ee.csr",
        ]);
        Self {
            dir,
            cas: cas.into_iter().map(|(n, _, c)| (n, c)).collect(),
        }
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Runs the certval binary in `dir` and returns its exit code and standard error.
fn certval_status(dir: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_certval"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The serial number openssl reads from a certificate, as hex.
fn serial(openssl: &OpenSsl, dir: &Path, cert: &str) -> String {
    openssl
        .run(dir, &["x509", "-in", cert, "-noout", "-serial"])
        .trim()
        .trim_start_matches("serial=")
        .to_string()
}

#[test]
fn issues_revokes_and_answers_under_each_choice() {
    let Some(openssl) = OpenSsl::from_env("issues_revokes_and_answers_under_each_choice") else {
        return;
    };
    let pki = Pki::new(&openssl, "ca");
    let dir = pki.dir.as_path();
    for choice in cryptos() {
        for (name, cases) in &pki.cas {
            let case = format!("{} with the {name} CA", choice.name);
            let (ca_cert, ca_key) = (format!("ca-{name}.crt"), format!("ca-{name}.key"));
            let signer = ["--cert", ca_cert.as_str(), "--key", ca_key.as_str()];
            let ee = format!("ee-{}-{name}.crt", choice.name);

            let mut issue = vec![
                "ca",
                "issue",
                "--csr",
                "ee.csr",
                "--key-usage",
                "digital-signature",
                "--eku",
                "email-protection",
                "--days",
                "1",
                "--outform",
                "pem",
                "--out",
                &ee,
            ];
            issue.extend(signer);
            if certval_with(dir, &issue, &choice, cases).is_none() {
                println!("{case}: declined, as expected");
                continue;
            }
            let verified = openssl.run(dir, &["verify", "-CAfile", &ca_cert, &ee]);
            assert!(verified.contains(": OK"), "{case}: {verified}");
            let text = openssl.run(dir, &["x509", "-in", &ee, "-noout", "-text"]);
            assert!(text.contains("email:ee@example.com"), "{case}: {text}");
            certval(dir, &["verify", &ee, "--anchor", &ca_cert]);

            let crl = format!("{}-{name}.crl", choice.name);
            let ee_serial = serial(&openssl, dir, &ee);
            let mut sign_crl = vec![
                "ca",
                "crl",
                "--crl-number",
                "1",
                "--revoke",
                &ee_serial,
                "--out",
                &crl,
            ];
            sign_crl.extend(signer);
            certval_with(dir, &sign_crl, &choice, cases);
            openssl.run(
                dir,
                &[
                    "crl", "-inform", "DER", "-in", &crl, "-noout", "-verify", "-CAfile", &ca_cert,
                ],
            );
            let (code, _) = certval_status(
                dir,
                &[
                    "verify",
                    &ee,
                    "--anchor",
                    &ca_cert,
                    "--crl",
                    &crl,
                    "--check-revocation",
                ],
            );
            assert_eq!(
                code, 1,
                "{case}: certval did not find the certificate revoked"
            );

            let (request, response) = (
                format!("{}-{name}.ocspreq", choice.name),
                format!("{}-{name}.ocsp", choice.name),
            );
            openssl.run(
                dir,
                &[
                    "ocsp", "-issuer", &ca_cert, "-cert", &ee, "-reqout", &request,
                ],
            );
            let mut answer = vec![
                "ca",
                "ocsp",
                "--request",
                &request,
                "--issuer",
                &ca_cert,
                "--revoke",
                &ee_serial,
                "--out",
                &response,
            ];
            answer.extend(signer);
            certval_with(dir, &answer, &choice, cases);
            // With -reqin and no -cert, openssl checks the response against the saved request,
            // nonce included.
            let checked = openssl.run(
                dir,
                &[
                    "ocsp",
                    "-reqin",
                    &request,
                    "-respin",
                    &response,
                    "-CAfile",
                    &ca_cert,
                    "-resp_text",
                ],
            );
            assert!(
                checked.contains("Cert Status: revoked"),
                "{case}: {checked}"
            );
        }
    }
}

#[test]
fn an_ml_kem_certificate_from_a_public_key() {
    let Some(openssl) = OpenSsl::from_env("an_ml_kem_certificate_from_a_public_key") else {
        return;
    };
    if !openssl.post_quantum() {
        println!("an_ml_kem_certificate_from_a_public_key: skipped, ML-KEM needs openssl 3.5");
        return;
    }
    let pki = Pki::new(&openssl, "ca-kem");
    let dir = pki.dir.as_path();
    openssl.run(
        dir,
        &["genpkey", "-algorithm", "ML-KEM-768", "-out", "kem.key"],
    );
    openssl.run(
        dir,
        &["pkey", "-in", "kem.key", "-pubout", "-out", "kem.pub"],
    );
    certval(
        dir,
        &[
            "ca",
            "issue",
            "--public-key",
            "kem.pub",
            "--subject",
            "CN=certval-cli KEM",
            "--key-usage",
            "key-encipherment",
            "--san-email",
            "kem@example.com",
            "--outform",
            "pem",
            "--out",
            "kem.crt",
            "--cert",
            "ca-ec.crt",
            "--key",
            "ca-ec.key",
        ],
    );
    let verified = openssl.run(dir, &["verify", "-CAfile", "ca-ec.crt", "kem.crt"]);
    assert!(verified.contains(": OK"), "{verified}");
    let text = openssl.run(dir, &["x509", "-in", "kem.crt", "-noout", "-text"]);
    assert!(text.contains("ML-KEM-768"), "{text}");
    assert!(text.contains("Key Encipherment"), "{text}");
}

#[test]
fn what_ca_refuses() {
    let Some(openssl) = OpenSsl::from_env("what_ca_refuses") else {
        return;
    };
    let pki = Pki::new(&openssl, "ca-refuses");
    let dir = pki.dir.as_path();
    certval(
        dir,
        &[
            "ca",
            "issue",
            "--csr",
            "ee.csr",
            "--out",
            "ee.crt",
            "--cert",
            "ca-ec.crt",
            "--key",
            "ca-ec.key",
        ],
    );

    // An end entity is not a CA.
    let (code, err) = certval_status(
        dir,
        &[
            "ca", "issue", "--csr", "ee.csr", "--out", "x.crt", "--cert", "ee.crt", "--key",
            "ee.key",
        ],
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("not a CA certificate"), "{err}");

    // A request whose signature does not verify: its last octet changed.
    let text = std::fs::read_to_string(pki.dir.join("ee.csr")).unwrap();
    let (_, mut der) = pem_rfc7468::decode_vec(text.as_bytes()).unwrap();
    let last = der.len() - 1;
    der[last] ^= 1;
    std::fs::write(pki.dir.join("bad.csr"), der).unwrap();
    let (code, err) = certval_status(
        dir,
        &[
            "ca",
            "issue",
            "--csr",
            "bad.csr",
            "--out",
            "x.crt",
            "--cert",
            "ca-ec.crt",
            "--key",
            "ca-ec.key",
        ],
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("does not verify"), "{err}");

    // A delegated responder without id-kp-OCSPSigning.
    openssl.run(
        dir,
        &[
            "ocsp",
            "-issuer",
            "ca-ec.crt",
            "-cert",
            "ee.crt",
            "-reqout",
            "ee.ocspreq",
        ],
    );
    let (code, err) = certval_status(
        dir,
        &[
            "ca",
            "ocsp",
            "--request",
            "ee.ocspreq",
            "--issuer",
            "ca-ec.crt",
            "--out",
            "x.ocsp",
            "--cert",
            "ee.crt",
            "--key",
            "ee.key",
        ],
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("id-kp-OCSPSigning"), "{err}");
}

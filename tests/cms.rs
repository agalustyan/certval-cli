//! `certval cms` against `openssl cms`, in both directions: what openssl encrypts or signs, certval
//! decrypts or verifies, and the reverse. Each runs once per `--crypto` choice the binary offers,
//! with `--only`, so every operation reaches that implementation.
//!
//! `CERTVAL_CMS_OPENSSL` names the `openssl` command; when it is unset each test says so and passes.
//! It makes a CA and RSA, EC, ML-KEM and ML-DSA keys with certificates from it, in a directory of
//! the test's own. ML-KEM and ML-DSA need OpenSSL 3.5 or later, and ML-KEM in CMS 3.6; against an
//! older openssl those cases are skipped, and the test says so.

use std::path::{Path, PathBuf};
use std::process::Command;

const OPENSSL: &str = "CERTVAL_CMS_OPENSSL";

const MESSAGE: &str = "certval-cli, longer than one AES block so that padding is exercised\n";

/// The --crypto choices the binary offers.
fn cryptos() -> Vec<&'static str> {
    let mut cryptos = vec!["software"];
    if cfg!(all(feature = "openssl", not(windows))) {
        cryptos.push("openssl");
    }
    cryptos
}

/// The openssl command, and its version as major and minor.
struct OpenSsl {
    command: String,
    version: (u32, u32),
}

impl OpenSsl {
    fn from_env(test: &str) -> Option<Self> {
        let Some(command) = std::env::var(OPENSSL).ok().filter(|v| !v.trim().is_empty()) else {
            println!("{test}: skipped, {OPENSSL} is not set");
            return None;
        };
        let output = Command::new(&command).arg("version").output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        // "OpenSSL 3.6.5 30 Sep 2026 (Library: ...)"
        let mut numbers = text
            .split_whitespace()
            .nth(1)
            .unwrap_or("0.0")
            .split('.')
            .map(|n| n.parse().unwrap_or(0));
        let version = (numbers.next().unwrap_or(0), numbers.next().unwrap_or(0));
        Some(Self { command, version })
    }

    fn post_quantum(&self) -> bool {
        self.version >= (3, 5)
    }

    fn kem_in_cms(&self) -> bool {
        self.version >= (3, 6)
    }

    /// Runs openssl in `dir`, panicking with its error output if it fails.
    fn run(&self, dir: &Path, args: &[&str]) -> String {
        let output = Command::new(&self.command)
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "openssl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

/// Runs the certval binary in `dir`, panicking with its error output if it fails, and returns its
/// standard output.
fn certval(dir: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_certval"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "certval {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A directory of the test's own holding a CA, keys with certificates from it, and the message.
struct Pki {
    dir: PathBuf,
}

impl Pki {
    fn new(openssl: &OpenSsl, test: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("certval-cli-{}-{test}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let o = |args: &[&str]| openssl.run(&dir, args);
        o(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-subj",
            "/CN=certval-cli test CA",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=keyCertSign,cRLSign",
        ]);
        std::fs::write(
            dir.join("ee.ext"),
            "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
        )
        .unwrap();
        let mut keys = vec![
            (
                "rsa",
                vec!["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            ),
            (
                "ec",
                vec!["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            ),
        ];
        if openssl.post_quantum() {
            keys.push(("kem", vec!["-algorithm", "ML-KEM-768"]));
            keys.push(("dsa", vec!["-algorithm", "ML-DSA-65"]));
        }
        for (name, algorithm) in keys {
            let key = format!("{name}.key");
            let public = format!("{name}.pub");
            let mut genpkey = vec!["genpkey"];
            genpkey.extend(algorithm);
            genpkey.extend(["-out", &key]);
            o(&genpkey);
            o(&["pkey", "-in", &key, "-pubout", "-out", &public]);
            o(&[
                "x509",
                "-new",
                "-subj",
                &format!("/CN={name}"),
                "-force_pubkey",
                &public,
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-days",
                "1",
                "-extfile",
                "ee.ext",
                "-out",
                &format!("{name}.crt"),
            ]);
        }
        std::fs::write(dir.join("message.txt"), MESSAGE).unwrap();
        Self { dir }
    }

    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.dir.join(file)).unwrap()
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn openssl_encrypts_and_certval_decrypts() {
    const TEST: &str = "openssl_encrypts_and_certval_decrypts";
    let Some(openssl) = OpenSsl::from_env(TEST) else {
        return;
    };
    let pki = Pki::new(&openssl, TEST);
    let mut cases = vec![
        ("rsa", "-aes-256-gcm", vec![]),
        (
            "rsa",
            "-aes-128-cbc",
            vec!["-keyopt", "rsa_padding_mode:oaep"],
        ),
        // openssl's default X9.63 KDF hash is SHA-1, which certval-cms does not offer.
        ("ec", "-aes-256-cbc", vec!["-keyopt", "ecdh_kdf_md:sha256"]),
    ];
    if openssl.kem_in_cms() {
        cases.push(("kem", "-aes-256-gcm", vec![]));
    } else {
        println!("{TEST}: skipped ML-KEM, which openssl cms writes from 3.6");
    }
    for (key, content, keyopt) in cases {
        let mut args = vec![
            "cms",
            "-encrypt",
            "-binary",
            content,
            "-in",
            "message.txt",
            "-outform",
            "DER",
            "-out",
            "message.der",
            "-recip",
        ];
        let cert = format!("{key}.crt");
        args.push(&cert);
        args.extend(keyopt);
        openssl.run(&pki.dir, &args);
        for crypto in cryptos() {
            let content = certval(
                &pki.dir,
                &[
                    "cms",
                    "decrypt",
                    "--in",
                    "message.der",
                    "--cert",
                    &cert,
                    "--key",
                    &format!("{key}.key"),
                    "--crypto",
                    crypto,
                    "--only",
                ],
            );
            assert_eq!(content, MESSAGE, "{key} {crypto}");
        }
    }
}

#[test]
fn certval_encrypts_and_openssl_decrypts() {
    const TEST: &str = "certval_encrypts_and_openssl_decrypts";
    let Some(openssl) = OpenSsl::from_env(TEST) else {
        return;
    };
    let pki = Pki::new(&openssl, TEST);
    let mut keys = vec!["rsa", "ec"];
    if openssl.kem_in_cms() {
        keys.push("kem");
    } else {
        println!("{TEST}: skipped ML-KEM, which openssl cms reads from 3.6");
    }
    for crypto in cryptos() {
        for content in ["aes256-gcm", "aes128-cbc"] {
            let mut args = vec![
                "cms",
                "encrypt",
                "--in",
                "message.txt",
                "--out",
                "message.der",
                "--content",
                content,
                "--crypto",
                crypto,
                "--only",
            ];
            let certs: Vec<String> = keys.iter().map(|k| format!("{k}.crt")).collect();
            for cert in &certs {
                args.extend(["--recip", cert]);
            }
            certval(&pki.dir, &args);
            for key in &keys {
                let decrypted = openssl.run(
                    &pki.dir,
                    &[
                        "cms",
                        "-decrypt",
                        "-inform",
                        "DER",
                        "-in",
                        "message.der",
                        "-recip",
                        &format!("{key}.crt"),
                        "-inkey",
                        &format!("{key}.key"),
                    ],
                );
                assert_eq!(decrypted, MESSAGE, "{key} {content} {crypto}");
            }
        }
    }
}

#[test]
fn certval_signs_and_openssl_verifies() {
    const TEST: &str = "certval_signs_and_openssl_verifies";
    let Some(openssl) = OpenSsl::from_env(TEST) else {
        return;
    };
    let pki = Pki::new(&openssl, TEST);
    let mut cases = vec![
        ("rsa", vec![]),
        ("rsa", vec!["--pss", "--digest", "sha384"]),
        ("ec", vec!["--digest", "sha512"]),
    ];
    if openssl.post_quantum() {
        cases.push(("dsa", vec!["--digest", "sha512"]));
    } else {
        println!("{TEST}: skipped ML-DSA, which openssl offers from 3.5");
    }
    for crypto in cryptos() {
        for (key, options) in &cases {
            let cert = format!("{key}.crt");
            let private = format!("{key}.key");
            let mut args = vec![
                "cms",
                "sign",
                "--in",
                "message.txt",
                "--cert",
                &cert,
                "--key",
                &private,
                "--out",
                "signed.der",
                "--crypto",
                crypto,
                "--only",
            ];
            args.extend(options.iter().copied());
            certval(&pki.dir, &args);
            let content = openssl.run(
                &pki.dir,
                &[
                    "cms",
                    "-verify",
                    "-inform",
                    "DER",
                    "-in",
                    "signed.der",
                    "-CAfile",
                    "ca.crt",
                    "-purpose",
                    "any",
                ],
            );
            assert_eq!(content, MESSAGE, "{key} {options:?} {crypto}");
        }

        // Detached, and written as PEM.
        certval(
            &pki.dir,
            &[
                "cms",
                "sign",
                "--in",
                "message.txt",
                "--cert",
                "ec.crt",
                "--key",
                "ec.key",
                "--out",
                "detached.pem",
                "--detached",
                "--outform",
                "pem",
                "--crypto",
                crypto,
                "--only",
            ],
        );
        openssl.run(
            &pki.dir,
            &[
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "PEM",
                "-in",
                "detached.pem",
                "-content",
                "message.txt",
                "-CAfile",
                "ca.crt",
                "-purpose",
                "any",
            ],
        );
    }
}

#[test]
fn openssl_signs_and_certval_verifies_and_validates() {
    const TEST: &str = "openssl_signs_and_certval_verifies_and_validates";
    let Some(openssl) = OpenSsl::from_env(TEST) else {
        return;
    };
    let pki = Pki::new(&openssl, TEST);
    let mut keys = vec!["rsa", "ec"];
    if openssl.post_quantum() {
        keys.push("dsa");
    } else {
        println!("{TEST}: skipped ML-DSA, which openssl offers from 3.5");
    }
    for key in keys {
        let cert = format!("{key}.crt");
        let private = format!("{key}.key");
        // openssl has no default digest for ML-DSA, so one is named for every key.
        openssl.run(
            &pki.dir,
            &[
                "cms",
                "-sign",
                "-binary",
                "-nodetach",
                "-md",
                "sha512",
                "-in",
                "message.txt",
                "-signer",
                &cert,
                "-inkey",
                &private,
                "-outform",
                "DER",
                "-out",
                "signed.der",
            ],
        );
        for crypto in cryptos() {
            let report = certval(
                &pki.dir,
                &[
                    "cms",
                    "verify",
                    "--in",
                    "signed.der",
                    "--anchor",
                    "ca.crt",
                    "--out",
                    "verified.txt",
                    "--crypto",
                    crypto,
                    "--only",
                ],
            );
            assert!(
                report.contains(&format!(
                    "signer CN={key}: signature verified, certificate validated"
                )),
                "{key} {crypto}: {report}"
            );
            assert_eq!(pki.read("verified.txt"), MESSAGE, "{key} {crypto}");

            // Without trust anchors, only the signature is verified.
            let report = certval(
                &pki.dir,
                &[
                    "cms",
                    "verify",
                    "--in",
                    "signed.der",
                    "--crypto",
                    crypto,
                    "--only",
                ],
            );
            assert!(
                report.contains("certificate not validated"),
                "{key} {crypto}: {report}"
            );
        }
    }
}

#[test]
fn a_wrong_key_does_not_decrypt() {
    const TEST: &str = "a_wrong_key_does_not_decrypt";
    let Some(openssl) = OpenSsl::from_env(TEST) else {
        return;
    };
    let pki = Pki::new(&openssl, TEST);
    certval(
        &pki.dir,
        &[
            "cms",
            "encrypt",
            "--in",
            "message.txt",
            "--out",
            "message.der",
            "--recip",
            "rsa.crt",
        ],
    );
    // The ec key with the rsa certificate: the recipient matches, the key does not.
    let output = Command::new(env!("CARGO_BIN_EXE_certval"))
        .current_dir(&pki.dir)
        .args([
            "cms",
            "decrypt",
            "--in",
            "message.der",
            "--cert",
            "rsa.crt",
            "--key",
            "ec.key",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

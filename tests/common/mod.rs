//! What the openssl-driven tests share: the openssl command `CERTVAL_CMS_OPENSSL` names, running
//! the certval binary, and the --crypto choices it offers with the cases each declines.

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

pub const OPENSSL: &str = "CERTVAL_CMS_OPENSSL";

/// A case some --crypto choice declines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    /// AES-GCM content encryption
    Gcm,
    /// Encrypting to a key agreement recipient
    KeyAgreementEncryption,
    /// Encrypting to a KEM recipient
    KemEncryption,
    /// Decrypting as a KEM recipient, which the key performs
    KemDecryption,
    /// Signing with ML-DSA, which the key performs
    MlDsaSigning,
    /// Verifying ML-DSA
    MlDsaVerification,
    /// Signing with ECDSA on P-256 with SHA-512, which the key performs
    P256Sha512,
}

impl Case {
    /// Whether the key performs this, rather than an implementation software can stand in for.
    pub fn by_the_key(self) -> bool {
        matches!(
            self,
            Case::KemDecryption | Case::MlDsaSigning | Case::P256Sha512
        )
    }
}

/// A --crypto choice the binary offers, and the cases it declines.
pub struct Choice {
    pub name: &'static str,
    pub declines: &'static [Case],
}

/// The --crypto choices the binary offers.
pub fn cryptos() -> Vec<Choice> {
    let mut cryptos = vec![Choice {
        name: "software",
        declines: &[],
    }];
    if cfg!(all(feature = "openssl", not(windows))) {
        cryptos.push(Choice {
            name: "openssl",
            declines: &[],
        });
    }
    cryptos.push(Choice {
        name: "aws-lc",
        // aws-lc-rs signs ECDSA only with the hash that matches the curve.
        declines: &[Case::MlDsaSigning, Case::P256Sha512],
    });
    if cfg!(all(target_os = "macos", feature = "cryptokit")) {
        cryptos.push(Choice {
            name: "security-framework",
            // CommonCrypto has no GCM. The ML-KEM and ML-DSA cases use ML-KEM-768 and ML-DSA-65,
            // which CryptoKit offers.
            declines: &[Case::Gcm],
        });
    } else if cfg!(target_os = "macos") {
        cryptos.push(Choice {
            name: "security-framework",
            // CommonCrypto has no GCM; ML-KEM and ML-DSA are CryptoKit's, which the cryptokit
            // feature brings in.
            declines: &[
                Case::Gcm,
                Case::KemEncryption,
                Case::KemDecryption,
                Case::MlDsaSigning,
                Case::MlDsaVerification,
            ],
        });
    }
    if cfg!(windows) {
        cryptos.push(Choice {
            name: "cng",
            // CNG has no X9.63 KDF.
            declines: &[
                Case::KeyAgreementEncryption,
                Case::KemEncryption,
                Case::KemDecryption,
                Case::MlDsaSigning,
                Case::MlDsaVerification,
            ],
        });
    }
    cryptos
}

/// The openssl command, and its version as major and minor.
pub struct OpenSsl {
    pub command: String,
    pub version: (u32, u32),
}

impl OpenSsl {
    pub fn from_env(test: &str) -> Option<Self> {
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

    pub fn post_quantum(&self) -> bool {
        self.version >= (3, 5)
    }

    pub fn kem_in_cms(&self) -> bool {
        self.version >= (3, 6)
    }

    /// Runs openssl in `dir`, panicking with its error output if it fails.
    /// The configuration is the test directory's own, so that no installation's is needed: a
    /// source build installed with `make install_sw` has none, and `req` will not run without one.
    pub fn run(&self, dir: &Path, args: &[&str]) -> String {
        let output = Command::new(&self.command)
            .current_dir(dir)
            .env("OPENSSL_CONF", dir.join("openssl.cnf"))
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
pub fn certval(dir: &Path, args: &[&str]) -> String {
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

/// Runs `certval` with `args` and `choice` as --crypto, and returns its standard output. With
/// --only it must succeed, unless `choice` declines one of `cases`: then it must fail with --only,
/// and succeed without, or with a case the key performs, there is no output to return.
pub fn certval_with(dir: &Path, args: &[&str], choice: &Choice, cases: &[Case]) -> Option<String> {
    let mut args = args.to_vec();
    args.extend(["--crypto", choice.name]);
    let declined: Vec<Case> = cases
        .iter()
        .copied()
        .filter(|c| choice.declines.contains(c))
        .collect();
    if declined.is_empty() {
        args.push("--only");
        return Some(certval(dir, &args));
    }
    let mut only = args.clone();
    only.push("--only");
    let output = Command::new(env!("CARGO_BIN_EXE_certval"))
        .current_dir(dir)
        .args(&only)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "certval {}: {} declines {declined:?}, but this did not fail",
        only.join(" "),
        choice.name
    );
    if declined.iter().any(|c| c.by_the_key()) {
        return None;
    }
    Some(certval(dir, &args))
}

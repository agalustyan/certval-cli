//! `certval cms` against `openssl cms`, in both directions: what openssl encrypts or signs, certval
//! decrypts or verifies, and the reverse. Each runs once per `--crypto` choice the binary offers,
//! with `--only`, so every operation reaches that implementation. A case a choice declines is run
//! with `--only` to see it fail, then without, so that software answers it, unless the key
//! performs it: a key is the chosen implementation's either way, so that case is not run further.
//!
//! `CERTVAL_CMS_OPENSSL` names the `openssl` command; when it is unset each test says so and passes.
//! It makes a CA and RSA, EC, ML-KEM and ML-DSA keys with certificates from it, in a directory of
//! the test's own. ML-KEM and ML-DSA need OpenSSL 3.5 or later, and ML-KEM in CMS 3.6; against an
//! older openssl those cases are skipped, and the test says so.
//!
//! Keys held by an implementation rather than given as files are tested on a PKCS #11 token, named
//! by `CERTVAL_PKCS11_MODULE`, `CERTVAL_PKCS11_TOKEN_LABEL` and `CERTVAL_PKCS11_USER_PIN`, as for
//! certval-pkcs11's tests; with the module or PIN unset, that test says so and passes.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::{certval, certval_with, cryptos, Case, OpenSsl};

const MESSAGE: &str = "certval-cli, longer than one AES block so that padding is exercised\n";

/// A directory of the test's own holding a CA, keys with certificates from it, and the message.
struct Pki {
    dir: PathBuf,
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
            let cert = format!("{name}.crt");
            let subject = format!("/CN={name}");
            let mut genpkey = vec!["genpkey"];
            genpkey.extend(algorithm);
            genpkey.extend(["-out", &key]);
            o(&genpkey);
            let issue = [
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                "ee.ext",
                "-out",
                &cert,
            ];
            if name == "kem" {
                // An ML-KEM key cannot sign a request, so its certificate is made from the public
                // key alone, with `x509 -new -force_pubkey`, which every openssl with ML-KEM has.
                let public = format!("{name}.pub");
                o(&["pkey", "-in", &key, "-pubout", "-out", &public]);
                let mut x509 = vec!["x509", "-new", "-subj", &subject, "-force_pubkey", &public];
                x509.extend(issue);
                o(&x509);
            } else {
                let request = format!("{name}.csr");
                o(&[
                    "req", "-new", "-key", &key, "-subj", &subject, "-out", &request,
                ]);
                let mut x509 = vec!["x509", "-req", "-in", &request];
                x509.extend(issue);
                o(&x509);
            }
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
        let mut declinable = vec![];
        if content.ends_with("gcm") {
            declinable.push(Case::Gcm);
        }
        if key == "kem" {
            declinable.push(Case::KemDecryption);
        }
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
            let Some(content) = certval_with(
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
                ],
                &crypto,
                &declinable,
            ) else {
                continue;
            };
            assert_eq!(content, MESSAGE, "{key} {}", crypto.name);
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
            ];
            let certs: Vec<String> = keys.iter().map(|k| format!("{k}.crt")).collect();
            for cert in &certs {
                args.extend(["--recip", cert]);
            }
            let mut declinable = vec![Case::KeyAgreementEncryption];
            if content.ends_with("gcm") {
                declinable.push(Case::Gcm);
            }
            if keys.contains(&"kem") {
                declinable.push(Case::KemEncryption);
            }
            certval_with(&pki.dir, &args, &crypto, &declinable);
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
                assert_eq!(decrypted, MESSAGE, "{key} {content} {}", crypto.name);
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
            ];
            args.extend(options.iter().copied());
            let declinable = match (*key, options.contains(&"sha512")) {
                ("dsa", _) => vec![Case::MlDsaSigning],
                ("ec", true) => vec![Case::P256Sha512],
                _ => vec![],
            };
            if certval_with(&pki.dir, &args, &crypto, &declinable).is_none() {
                continue;
            }
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
            assert_eq!(content, MESSAGE, "{key} {options:?} {}", crypto.name);
        }

        // Detached, and written as PEM.
        certval_with(
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
            ],
            &crypto,
            &[],
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
        let declinable = if key == "dsa" {
            vec![Case::MlDsaVerification]
        } else {
            vec![]
        };
        for crypto in cryptos() {
            let Some(report) = certval_with(
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
                ],
                &crypto,
                &declinable,
            ) else {
                continue;
            };
            assert!(
                report.contains(&format!(
                    "signer CN={key}: signature verified, certificate validated"
                )),
                "{key} {}: {report}",
                crypto.name
            );
            assert_eq!(pki.read("verified.txt"), MESSAGE, "{key} {}", crypto.name);

            // Without trust anchors, only the signature is verified.
            let Some(report) = certval_with(
                &pki.dir,
                &["cms", "verify", "--in", "signed.der"],
                &crypto,
                &declinable,
            ) else {
                continue;
            };
            assert!(
                report.contains("certificate not validated"),
                "{key} {}: {report}",
                crypto.name
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

// ---- keys on a token

const PKCS11_MODULE: &str = "CERTVAL_PKCS11_MODULE";
const PKCS11_TOKEN_LABEL: &str = "CERTVAL_PKCS11_TOKEN_LABEL";
const PKCS11_USER_PIN: &str = "CERTVAL_PKCS11_USER_PIN";

/// An EC key and its certificate put on a token as token objects, so that another process sees
/// them, and destroyed when dropped.
struct TokenKey {
    session: cryptoki::session::Session,
    objects: Vec<cryptoki::object::ObjectHandle>,
}

impl TokenKey {
    fn put(module: &str, label: Option<&str>, pin: &str, cert_pem: &str, key_pem: &str) -> Self {
        use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
        use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
        use cryptoki::session::UserType;
        use cryptoki::types::AuthPin;
        use der::{Decode, Encode};

        let (_, cert) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).unwrap();
        let subject = x509_cert::Certificate::from_der(&cert)
            .unwrap()
            .tbs_certificate()
            .subject()
            .to_der()
            .unwrap();
        let (_, pkcs8) = pem_rfc7468::decode_vec(key_pem.as_bytes()).unwrap();
        let info = pkcs8::PrivateKeyInfoRef::from_der(&pkcs8).unwrap();
        let curve = info.algorithm.parameters.unwrap().to_der().unwrap();
        let scalar = sec1::EcPrivateKey::from_der(info.private_key.as_bytes())
            .unwrap()
            .private_key
            .to_vec();

        let context = Pkcs11::new(module).unwrap();
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .unwrap();
        let slot = context
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|slot| {
                label.is_none_or(|label| {
                    context.get_token_info(*slot).unwrap().label().trim_end() == label
                })
            })
            .expect("the token");
        let session = context.open_rw_session(slot).unwrap();
        session
            .login(UserType::User, Some(&AuthPin::new(pin.into())))
            .unwrap();
        let mut id = vec![0u8; 16];
        getrandom::fill(&mut id).unwrap();
        let certificate = session
            .create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(true),
                Attribute::Id(id.clone()),
                Attribute::Subject(subject),
                Attribute::Value(cert),
            ])
            .unwrap();
        let key = session
            .create_object(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Id(id),
                Attribute::EcParams(curve),
                Attribute::Value(scalar),
                Attribute::Sign(true),
                Attribute::Derive(true),
            ])
            .unwrap();
        Self {
            session,
            objects: vec![certificate, key],
        }
    }
}

impl Drop for TokenKey {
    fn drop(&mut self) {
        for object in &self.objects {
            let _ = self.session.destroy_object(*object);
        }
    }
}

/// The certificate's subject key identifier, as hex.
fn subject_key_identifier(cert_pem: &str) -> String {
    use der::Decode;
    let (_, der) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).unwrap();
    let cert = x509_cert::Certificate::from_der(&der).unwrap();
    let skid = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER)
        .expect("a subject key identifier");
    let skid =
        x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(skid.extn_value.as_bytes()).unwrap();
    skid.0
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn a_key_on_a_token_is_listed_signs_and_decrypts() {
    const TEST: &str = "a_key_on_a_token_is_listed_signs_and_decrypts";
    let Some(openssl) = OpenSsl::from_env(TEST) else {
        return;
    };
    let (Ok(module), Ok(pin)) = (std::env::var(PKCS11_MODULE), std::env::var(PKCS11_USER_PIN))
    else {
        println!("{TEST}: skipped, {PKCS11_MODULE} or {PKCS11_USER_PIN} is not set");
        return;
    };
    let label = std::env::var(PKCS11_TOKEN_LABEL).ok();
    let pki = Pki::new(&openssl, TEST);
    let _key = TokenKey::put(
        &module,
        label.as_deref(),
        &pin,
        &pki.read("ec.crt"),
        &pki.read("ec.key"),
    );
    let mut token = vec![
        "--crypto",
        "pkcs11",
        "--pkcs11-module",
        &module,
        "--pkcs11-pin",
        &pin,
    ];
    if let Some(label) = &label {
        token.extend(["--pkcs11-token", label]);
    }
    let with_token = |args: &[&str]| {
        let mut args = args.to_vec();
        args.extend(token.iter().copied());
        certval(&pki.dir, &args)
    };

    let listing = with_token(&["cred", "list"]);
    assert!(listing.contains("Subject:     CN=ec"), "{listing}");

    let skid = subject_key_identifier(&pki.read("ec.crt"));
    for signer in [["--cert", "ec.crt"], ["--skid", skid.as_str()]] {
        let mut args = vec!["cms", "sign", "--in", "message.txt", "--out", "signed.der"];
        args.extend(signer);
        with_token(&args);
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
        assert_eq!(content, MESSAGE, "{signer:?}");
    }

    // The recipient's key is found by the identifier the message contains.
    openssl.run(
        &pki.dir,
        &[
            "cms",
            "-encrypt",
            "-binary",
            "-aes-256-cbc",
            "-in",
            "message.txt",
            "-outform",
            "DER",
            "-out",
            "message.der",
            "-recip",
            "ec.crt",
            "-keyopt",
            "ecdh_kdf_md:sha256",
        ],
    );
    let content = with_token(&["cms", "decrypt", "--in", "message.der"]);
    assert_eq!(content, MESSAGE);
}

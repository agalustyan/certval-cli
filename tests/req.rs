//! `certval req` against openssl: under each `--crypto` choice the binary offers, with `--only`,
//! RSA, P-256 and, with OpenSSL 3.5 or later, ML-DSA-65 keys openssl made sign a certificate request
//! that `openssl req -verify` accepts and a self-signed CA certificate that `openssl verify`
//! accepts. That CA then issues, with `certval ca issue`, a certificate from the P-256 request, and
//! `certval verify` validates it. A choice that cannot sign with ML-DSA declines it.
//!
//! `CERTVAL_CMS_OPENSSL` names the `openssl` command, as for the CMS tests; when it is unset the
//! test says so and passes.

mod common;

use std::path::PathBuf;

use common::{certval, certval_with, cryptos, Case, OpenSsl};

struct Keys {
    dir: PathBuf,
}

impl Drop for Keys {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn requests_and_self_signed_certificates_under_each_choice() {
    let test = "requests_and_self_signed_certificates_under_each_choice";
    let Some(openssl) = OpenSsl::from_env(test) else {
        return;
    };
    let keys = Keys {
        dir: std::env::temp_dir().join(format!("certval-cli-{}-req", std::process::id())),
    };
    let dir = keys.dir.as_path();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("openssl.cnf"),
        "[req]\ndistinguished_name = dn\n[dn]\n",
    )
    .unwrap();
    let o = |args: &[&str]| openssl.run(dir, args);
    let mut kinds: Vec<(&str, Vec<&str>, &str, Vec<Case>)> = vec![
        // P-256 first: each CA issues from the P-256 request made under the same choice.
        (
            "ec",
            vec!["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
            "sha256",
            vec![],
        ),
        (
            "rsa",
            vec!["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            "sha256",
            vec![],
        ),
    ];
    if openssl.post_quantum() {
        kinds.push((
            "dsa",
            vec!["-algorithm", "ML-DSA-65"],
            "sha512",
            vec![Case::MlDsaSigning],
        ));
    }
    for (name, algorithm, _, _) in &kinds {
        let mut genpkey = vec!["genpkey"];
        genpkey.extend(algorithm);
        let out = format!("{name}.key");
        genpkey.extend(["-out", out.as_str()]);
        o(&genpkey);
    }

    for choice in cryptos() {
        for (name, _, digest, cases) in &kinds {
            let case = format!("{} with the {name} key", choice.name);
            let key = format!("{name}.key");
            let (request, root) = (
                format!("{}-{name}.csr", choice.name),
                format!("{}-{name}.crt", choice.name),
            );
            let subject = format!("CN=certval-cli req {case}");
            let req = [
                "req",
                "--key",
                &key,
                "--subject",
                &subject,
                "--san-email",
                "req@example.com",
                "--digest",
                digest,
                "--outform",
                "pem",
                "--out",
                &request,
            ];
            if certval_with(dir, &req, &choice, cases).is_none() {
                println!("{case}: declined, as expected");
                continue;
            }
            let verified = o(&["req", "-in", &request, "-noout", "-verify", "-text"]);
            assert!(
                verified.contains("email:req@example.com"),
                "{case}: {verified}"
            );

            let self_signed = [
                "req",
                "--key",
                &key,
                "--subject",
                &subject,
                "--x509",
                "--ca",
                "--days",
                "1",
                "--digest",
                digest,
                "--outform",
                "pem",
                "--out",
                &root,
            ];
            certval_with(dir, &self_signed, &choice, cases);
            let verified = o(&["verify", "-CAfile", &root, &root]);
            assert!(verified.contains(": OK"), "{case}: {verified}");

            // The self-signed CA issues from a P-256 request made under the same choice.
            let ee_request = format!("{}-ec.csr", choice.name);
            let issued = format!("{}-{name}-issued.crt", choice.name);
            let issue = [
                "ca",
                "issue",
                "--csr",
                &ee_request,
                "--cert",
                &root,
                "--key",
                &key,
                "--digest",
                digest,
                "--days",
                "1",
                "--out",
                &issued,
            ];
            certval_with(dir, &issue, &choice, cases);
            certval(dir, &["verify", &issued, "--anchor", &root]);
        }
    }
}

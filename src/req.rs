//! `certval req`: a certificate request (PKCS #10), or with `--x509` a self-signed certificate,
//! signed by a key that has no certificate yet, held by the implementation `--crypto` chooses.
//!
//! The key is a PKCS #8 file, taken into the chosen implementation as a key with no certificate
//! (certval-cms's `SigningKey`): software, OpenSSL, AWS-LC, Security.framework, which with the
//! `cryptokit` feature holds an ML-DSA key in CryptoKit, or CNG, for an RSA or EC key, and an
//! ML-DSA key where Windows' CNG has ML-DSA. A request asks for the extensions the
//! arguments choose, as `openssl req -addext` does; a self-signed certificate contains them. A key
//! that cannot sign, such as an ML-KEM key, has neither: `certval ca issue --public-key` certifies
//! it.

use certval_cms::{rsa_pss, CredentialSignature, CredentialSigner, SigningKey};
use der::referenced::OwnedToRef;
use der::{Decode, Encode};
use x509_cert::builder::Builder;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::name::Name;
use x509_cert::request::RequestBuilder;

use crate::ca::{write, ContentArgs};
use crate::cms::{Form, Hash};
use crate::crypto::CryptoArgs;
use crate::input::read_der;
use crate::Result;

#[derive(clap::Args)]
pub struct Args {
    /// The private key, PKCS #8, DER or PEM, taken into the --crypto implementation
    #[arg(long, value_name = "FILE")]
    pub key: String,

    /// Subject name, as RFC 4514 writes it, e.g. "CN=Alice,O=Example"
    #[arg(long, value_name = "NAME")]
    pub subject: String,

    /// Write a self-signed certificate rather than a request; --days and --serial apply only here
    #[arg(long)]
    pub x509: bool,

    /// File to write the request or certificate to
    #[arg(long, value_name = "FILE")]
    pub out: String,

    /// Encoding of what is written
    #[arg(long, value_enum, default_value_t = Form::Der)]
    pub outform: Form,

    #[command(flatten)]
    pub content: ContentArgs,

    /// Digest algorithm
    #[arg(long, value_enum, default_value_t = Hash::Sha256)]
    pub digest: Hash,

    /// Sign with RSASSA-PSS rather than PKCS #1 v1.5, for an RSA key
    #[arg(long)]
    pub pss: bool,

    #[command(flatten)]
    pub crypto: CryptoArgs,
}

pub fn run(args: &Args) -> Result<bool> {
    let env = args.crypto.cms_environment(args.crypto.pki_environment()?);
    let key: Box<dyn SigningKey> = args.crypto.signing_key(&read_der(&args.key)?)?;
    let digest = args.digest.digest();
    let signer = if args.pss {
        CredentialSigner::with_algorithm(&env, key.as_ref(), digest, rsa_pss(digest)?)?
    } else {
        CredentialSigner::new(&env, key.as_ref(), digest)?
    };
    let subject: Name = args
        .subject
        .parse()
        .map_err(|e| format!("{}: not a name: {e}", args.subject))?;

    if args.x509 {
        let spki = key.public_key().clone();
        // Self-signed: the authority key identifier is the key's own.
        let key_id = SubjectKeyIdentifier::try_from(spki.owned_to_ref())?.0;
        let certificate =
            args.content
                .certificate(&signer, subject.clone(), key_id, subject, spki, vec![])?;
        write(
            &args.out,
            &certificate.to_der()?,
            args.outform,
            "CERTIFICATE",
        )?;
    } else {
        let extensions = args.content.extensions(&subject, vec![])?;
        let mut builder = RequestBuilder::new(subject)?;
        for ext in &extensions {
            let value = der::Any::from_der(ext.extn_value.as_bytes())?;
            builder.add_extension((ext.extn_id, ext.critical, &value))?;
        }
        let request = builder.build::<_, CredentialSignature>(&signer)?;
        write(
            &args.out,
            &request.to_der()?,
            args.outform,
            "CERTIFICATE REQUEST",
        )?;
    }
    Ok(true)
}

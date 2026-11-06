//! `certval ca`: issue certificates, sign CRLs and answer OCSP requests with a CA's key, held as a
//! file or by the implementation `--crypto` chooses, so that test material can be made with any
//! provider's keys.
//!
//! The key is chosen as `cms sign` chooses one: `--cert` and `--key` files, or without `--key`, the
//! key the keychain, the certificate store or a token holds for `--cert` or `--skid`. A key found
//! that way is not narrowed to keys permitting signing, since a CA's certificate permits
//! keyCertSign and cRLSign instead; each command checks the use it needs.
//!
//! Each command signs through certval-cms's `CredentialSigner`. Certificates are built by
//! x509-cert's `CertificateBuilder` and OCSP responses by x509-ocsp's `OcspResponseBuilder`. CRLs
//! are assembled here, because x509-cert 0.3.0's `CrlBuilder` takes its authority key identifier
//! from the issuer certificate's own authority key identifier, which identifies the issuer's
//! issuer; a CRL's must identify the CA's key (RFC 5280, section 5.2.1).

use std::time::{Duration, SystemTime};

use certval_cms::{
    rsa_pss, CmsEnvironment, CredentialSignature, CredentialSigner, SharedSigningCredential,
    SigningCredential, SigningCredentialLookup,
};
use clap::ValueEnum;
use cms::cert::IssuerAndSerialNumber;
use cms::signed_data::SignerIdentifier;
use const_oid::db::rfc5280::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CRL_NUMBER, ID_CE_EXT_KEY_USAGE,
    ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER, ID_KP_CLIENT_AUTH,
    ID_KP_CODE_SIGNING, ID_KP_EMAIL_PROTECTION, ID_KP_OCSP_SIGNING, ID_KP_SERVER_AUTH,
    ID_KP_TIME_STAMPING,
};
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use const_oid::ObjectIdentifier;
use der::asn1::{Ia5String, OctetString};
use der::referenced::OwnedToRef;
use der::{Decode, Encode};
use sha1::{Digest, Sha1};
use signature::Signer as _;
use spki::{
    DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
    SubjectPublicKeyInfoRef,
};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::request::CertReq;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};
use x509_ocsp::builder::OcspResponseBuilder;
use x509_ocsp::{
    CertId, CertStatus, OcspGeneralizedTime, OcspRequest, ResponderId, RevokedInfo, SingleResponse,
};

use crate::cms::{from_hex, read_certificate, Form, Hash};
use crate::crypto::CryptoArgs;
use crate::display;
use crate::input::read_der;
use crate::Result;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Issue a certificate, from a certificate request or a public key
    Issue(IssueArgs),
    /// Sign a certificate revocation list
    Crl(CrlArgs),
    /// Answer an OCSP request, as the CA or a responder it has delegated to
    Ocsp(OcspArgs),
}

pub fn run(command: &Command) -> Result<bool> {
    match command {
        Command::Issue(args) => issue(args),
        Command::Crl(args) => crl(args),
        Command::Ocsp(args) => ocsp(args),
    }
}

/// The key that signs, and how it signs.
#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("signer").required(true).multiple(false)))]
pub struct SigningArgs {
    /// The signer's certificate, DER or PEM: the CA's, or for `ocsp`, the responder's. Without
    /// --key, it chooses the key the --crypto implementation holds for it
    #[arg(long, value_name = "FILE", group = "signer")]
    pub cert: Option<String>,

    /// The signer's private key, PKCS #8, DER or PEM. When absent, the key is one the --crypto
    /// implementation holds, chosen by --cert or --skid
    #[arg(long, value_name = "FILE", requires = "cert")]
    pub key: Option<String>,

    /// Sign with the key the --crypto implementation holds for the certificate with this subject
    /// key identifier, as hex, which `certval cred list` shows
    #[arg(long, value_name = "HEX", group = "signer")]
    pub skid: Option<String>,

    /// Digest algorithm
    #[arg(long, value_enum, default_value_t = Hash::Sha256)]
    pub digest: Hash,

    /// Sign with RSASSA-PSS rather than PKCS #1 v1.5, for an RSA key
    #[arg(long)]
    pub pss: bool,

    #[command(flatten)]
    pub crypto: CryptoArgs,
}

/// The signer's credential: from a key file, or held by the implementation's store.
enum Held {
    File(Box<dyn SigningCredential>),
    Store(SharedSigningCredential),
}

impl Held {
    fn credential(&self) -> &dyn SigningCredential {
        match self {
            Held::File(c) => c.as_ref(),
            Held::Store(c) => c.as_ref(),
        }
    }
}

impl SigningArgs {
    /// The credential the arguments choose.
    fn held(&self, env: &CmsEnvironment) -> Result<Held> {
        if let (Some(cert), Some(key)) = (&self.cert, &self.key) {
            return Ok(Held::File(
                self.crypto
                    .signing_credential(read_certificate(cert)?, &read_der(key)?)?,
            ));
        }
        let store = self.crypto.store()?;
        let (sid, what) = if let Some(cert) = &self.cert {
            let cert = read_certificate(cert)?;
            let tbs = cert.tbs_certificate();
            (
                SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                    issuer: tbs.issuer().clone(),
                    serial_number: tbs.serial_number().clone(),
                }),
                format!("the certificate {}", display::name(tbs.subject())),
            )
        } else if let Some(skid) = &self.skid {
            (
                SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(OctetString::new(
                    from_hex(skid)?,
                )?)),
                format!("subject key identifier {skid}"),
            )
        } else {
            return Err("no signer: one of --cert and --skid is required".into());
        };
        let mut found =
            store.find_signing_credentials(env, SigningCredentialLookup::Identifier(&sid))?;
        match found.len() {
            1 => {
                let credential = found.remove(0);
                eprintln!(
                    "signing with the key from {} for {}",
                    store.description(),
                    display::name(credential.certificate().tbs_certificate().subject())
                );
                Ok(Held::Store(credential))
            }
            0 => Err(format!("{} holds no key for {what}", store.description()).into()),
            n => Err(format!(
                "{} holds {n} keys for {what}; choose one with --skid",
                store.description()
            )
            .into()),
        }
    }

    /// The environment the signer signs in: the chosen implementation's hashing, for a credential
    /// that signs only digests.
    fn environment(&self) -> Result<CmsEnvironment> {
        Ok(self.crypto.cms_environment(self.crypto.pki_environment()?))
    }

    /// A signer for `credential` with the digest and signature algorithm the arguments choose.
    fn signer<'a>(
        &self,
        env: &'a CmsEnvironment,
        credential: &'a dyn SigningCredential,
    ) -> Result<CredentialSigner<'a>> {
        let digest = self.digest.digest();
        Ok(if self.pss {
            CredentialSigner::with_algorithm(env, credential, digest, rsa_pss(digest)?)
        } else {
            CredentialSigner::new(env, credential, digest)?
        })
    }
}

// ---- issue

/// A key usage, as `--key-usage` names it.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Usage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
}

impl From<Usage> for KeyUsages {
    fn from(usage: Usage) -> Self {
        match usage {
            Usage::DigitalSignature => KeyUsages::DigitalSignature,
            Usage::NonRepudiation => KeyUsages::NonRepudiation,
            Usage::KeyEncipherment => KeyUsages::KeyEncipherment,
            Usage::DataEncipherment => KeyUsages::DataEncipherment,
            Usage::KeyAgreement => KeyUsages::KeyAgreement,
            Usage::KeyCertSign => KeyUsages::KeyCertSign,
            Usage::CrlSign => KeyUsages::CRLSign,
        }
    }
}

/// An extended key usage, as `--eku` names it.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Purpose {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

impl From<Purpose> for ObjectIdentifier {
    fn from(purpose: Purpose) -> Self {
        match purpose {
            Purpose::ServerAuth => ID_KP_SERVER_AUTH,
            Purpose::ClientAuth => ID_KP_CLIENT_AUTH,
            Purpose::CodeSigning => ID_KP_CODE_SIGNING,
            Purpose::EmailProtection => ID_KP_EMAIL_PROTECTION,
            Purpose::TimeStamping => ID_KP_TIME_STAMPING,
            Purpose::OcspSigning => ID_KP_OCSP_SIGNING,
        }
    }
}

#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("subject_key").required(true).multiple(false)))]
pub struct IssueArgs {
    /// Certificate request, PKCS #10, DER or PEM, whose signature is checked; its subject and
    /// public key are certified, and its requested subject alternative names copied
    #[arg(long, value_name = "FILE", group = "subject_key")]
    pub csr: Option<String>,

    /// Public key to certify, SubjectPublicKeyInfo, DER or PEM, e.g. an ML-KEM key, which cannot
    /// sign a request; needs --subject
    #[arg(long, value_name = "FILE", group = "subject_key", requires = "subject")]
    pub public_key: Option<String>,

    /// Subject name, as RFC 4514 writes it, e.g. "CN=Alice,O=Example"; with --public-key, or to
    /// replace a request's
    #[arg(long, value_name = "NAME")]
    pub subject: Option<String>,

    /// File to write the certificate to
    #[arg(long, value_name = "FILE")]
    pub out: String,

    /// Days the certificate is valid for, from now
    #[arg(long, default_value_t = 365)]
    pub days: u64,

    /// Serial number, as hex; 16 random octets when absent
    #[arg(long, value_name = "HEX")]
    pub serial: Option<String>,

    /// Issue a CA certificate: basic constraints with cA set, and unless --key-usage says
    /// otherwise, keyCertSign and cRLSign
    #[arg(long)]
    pub ca: bool,

    /// The path length constraint of a CA certificate
    #[arg(long, value_name = "N", requires = "ca")]
    pub path_len: Option<u8>,

    /// Key usages, comma separated; without it, an end-entity certificate has no key usage
    /// extension
    #[arg(long, value_enum, value_delimiter = ',')]
    pub key_usage: Vec<Usage>,

    /// Extended key usages, comma separated
    #[arg(long, value_enum, value_delimiter = ',')]
    pub eku: Vec<Purpose>,

    /// An email address for the subject alternative name; repeatable
    #[arg(long, value_name = "ADDRESS")]
    pub san_email: Vec<String>,

    /// A DNS name for the subject alternative name; repeatable
    #[arg(long, value_name = "NAME")]
    pub san_dns: Vec<String>,

    /// Encoding of the certificate written
    #[arg(long, value_enum, default_value_t = Form::Der)]
    pub outform: Form,

    #[command(flatten)]
    pub signing: SigningArgs,
}

/// The subject's name and public key, and the subject alternative names requested.
struct Subject {
    name: Name,
    spki: SubjectPublicKeyInfoOwned,
    requested_names: Vec<GeneralName>,
}

/// The subject a request names, after checking the request's signature with its own key.
fn subject_from_request(file: &str, env: &CmsEnvironment) -> Result<Subject> {
    let request =
        CertReq::from_der(&read_der(file)?).map_err(|e| format!("{file}: not a request: {e}"))?;
    let pe = env.pki_environment().ok_or("no PkiEnvironment")?;
    pe.verify_signature_message(
        pe,
        &request.info.to_der()?,
        &request.signature,
        &request.algorithm,
        &request.info.public_key,
    )
    .map_err(|e| format!("{file}: the request's signature does not verify: {e:?}"))?;
    let mut requested_names = vec![];
    for attribute in request.info.attributes.iter() {
        if attribute.oid != ID_EXTENSION_REQ {
            continue;
        }
        for value in attribute.values.iter() {
            let extensions: Vec<Extension> = value
                .decode_as()
                .map_err(|e| format!("{file}: an extension request: {e}"))?;
            for ext in extensions
                .iter()
                .filter(|e| e.extn_id == ID_CE_SUBJECT_ALT_NAME)
            {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| format!("{file}: a requested subject alternative name: {e}"))?;
                requested_names.extend(san.0);
            }
        }
    }
    Ok(Subject {
        name: request.info.subject,
        spki: request.info.public_key,
        requested_names,
    })
}

/// Issues with exactly the extensions `ca issue` chose, adding the key identifiers.
struct Profile {
    issuer: Name,
    subject: Name,
    authority_key_identifier: OctetString,
    extensions: Vec<Extension>,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = self.extensions.clone();
        extensions.push(extension(
            ID_CE_SUBJECT_KEY_IDENTIFIER,
            false,
            &SubjectKeyIdentifier::try_from(spk)?,
        )?);
        extensions.push(extension(
            ID_CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(self.authority_key_identifier.clone()),
                ..Default::default()
            },
        )?);
        Ok(extensions)
    }
}

fn issue(args: &IssueArgs) -> Result<bool> {
    let signing = &args.signing;
    let env = signing.environment()?;
    let held = signing.held(&env)?;
    let credential = held.credential();
    let ca = credential.certificate();
    require_ca(ca)?;
    require_key_usage(ca, KeyUsages::KeyCertSign, "issue certificates")?;

    let mut subject = match (&args.csr, &args.public_key) {
        (Some(csr), _) => subject_from_request(csr, &env)?,
        (None, Some(file)) => Subject {
            name: Name::default(),
            spki: SubjectPublicKeyInfoOwned::from_der(&read_der(file)?)
                .map_err(|e| format!("{file}: not a public key: {e}"))?,
            requested_names: vec![],
        },
        (None, None) => return Err("one of --csr and --public-key is required".into()),
    };
    if let Some(name) = &args.subject {
        subject.name = name
            .parse()
            .map_err(|e| format!("{name}: not a name: {e}"))?;
    }

    let mut extensions = vec![];
    if args.ca {
        extensions.push(extension(
            ID_CE_BASIC_CONSTRAINTS,
            true,
            &BasicConstraints {
                ca: true,
                path_len_constraint: args.path_len,
            },
        )?);
    }
    let usages: Vec<Usage> = if args.key_usage.is_empty() && args.ca {
        vec![Usage::KeyCertSign, Usage::CrlSign]
    } else {
        args.key_usage.clone()
    };
    if !usages.is_empty() {
        let flags = usages
            .iter()
            .fold(der::flagset::FlagSet::<KeyUsages>::default(), |f, u| {
                f | KeyUsages::from(*u)
            });
        extensions.push(extension(ID_CE_KEY_USAGE, true, &KeyUsage(flags))?);
    }
    if !args.eku.is_empty() {
        let purposes = ExtendedKeyUsage(args.eku.iter().map(|p| (*p).into()).collect());
        extensions.push(extension(ID_CE_EXT_KEY_USAGE, false, &purposes)?);
    }
    let mut names = subject.requested_names;
    for email in &args.san_email {
        names.push(GeneralName::Rfc822Name(Ia5String::new(email)?));
    }
    for dns in &args.san_dns {
        names.push(GeneralName::DnsName(Ia5String::new(dns)?));
    }
    if !names.is_empty() {
        // RFC 5280, section 4.2.1.6: critical when the subject name is empty.
        let critical = subject.name.is_empty();
        extensions.push(extension(
            ID_CE_SUBJECT_ALT_NAME,
            critical,
            &SubjectAltName(names),
        )?);
    } else if subject.name.is_empty() {
        return Err("a certificate needs a subject name or a subject alternative name".into());
    }

    let profile = Profile {
        issuer: ca.tbs_certificate().subject().clone(),
        subject: subject.name,
        authority_key_identifier: key_identifier(ca)?,
        extensions,
    };
    let serial = match &args.serial {
        Some(hex) => SerialNumber::new(&from_hex(hex)?)?,
        None => random_serial()?,
    };
    let validity = Validity::from_now(Duration::from_secs(args.days * 86400))?;
    let signer = signing.signer(&env, credential)?;
    let certificate = CertificateBuilder::new(profile, serial, validity, subject.spki)?
        .build::<_, CredentialSignature>(&signer)?;
    write(
        &args.out,
        &certificate.to_der()?,
        args.outform,
        "CERTIFICATE",
    )?;
    Ok(true)
}

// ---- crl

#[derive(clap::Args)]
pub struct CrlArgs {
    /// File to write the CRL to
    #[arg(long, value_name = "FILE")]
    pub out: String,

    /// The CRL number, which increases with each CRL the CA issues
    #[arg(long, value_name = "N")]
    pub crl_number: u64,

    /// Serial number of a revoked certificate, as hex; repeatable
    #[arg(long, value_name = "HEX")]
    pub revoke: Vec<String>,

    /// Days until the next update
    #[arg(long, value_name = "DAYS", default_value_t = 7)]
    pub next_update_days: u64,

    /// Encoding of the CRL written
    #[arg(long, value_enum, default_value_t = Form::Der)]
    pub outform: Form,

    #[command(flatten)]
    pub signing: SigningArgs,
}

fn crl(args: &CrlArgs) -> Result<bool> {
    let signing = &args.signing;
    let env = signing.environment()?;
    let held = signing.held(&env)?;
    let credential = held.credential();
    let ca = credential.certificate();
    require_key_usage(ca, KeyUsages::CRLSign, "sign CRLs")?;
    let signer = signing.signer(&env, credential)?;

    let now = SystemTime::now();
    let this_update = Time::try_from(now)?;
    let next_update = Time::try_from(now + Duration::from_secs(args.next_update_days * 86400))?;
    let revoked: Vec<RevokedCert> = args
        .revoke
        .iter()
        .map(|hex| {
            Ok(RevokedCert {
                serial_number: SerialNumber::new(&from_hex(hex)?)?,
                revocation_date: this_update,
                crl_entry_extensions: None,
            })
        })
        .collect::<Result<_>>()?;
    let crl_extensions = vec![
        extension(
            ID_CE_CRL_NUMBER,
            false,
            &CrlNumber::try_from(args.crl_number)?,
        )?,
        extension(
            ID_CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(key_identifier(ca)?),
                ..Default::default()
            },
        )?,
    ];
    let tbs_cert_list = TbsCertList {
        version: Version::V2,
        signature: signer.signature_algorithm_identifier()?,
        issuer: ca.tbs_certificate().subject().clone(),
        this_update,
        next_update: Some(next_update),
        revoked_certificates: (!revoked.is_empty()).then_some(revoked),
        crl_extensions: Some(crl_extensions),
    };
    let signature = signer.try_sign(&tbs_cert_list.to_der()?)?.to_bitstring()?;
    let crl = CertificateList {
        signature_algorithm: tbs_cert_list.signature.clone(),
        tbs_cert_list,
        signature,
    };
    write(&args.out, &crl.to_der()?, args.outform, "X509 CRL")?;
    Ok(true)
}

// ---- ocsp

#[derive(clap::Args)]
pub struct OcspArgs {
    /// The OCSP request to answer, DER or PEM
    #[arg(long, value_name = "FILE")]
    pub request: String,

    /// Certificate of the CA whose certificates the request asks about, DER or PEM; a certificate
    /// identifier for another CA is answered unknown
    #[arg(long, value_name = "FILE")]
    pub issuer: String,

    /// File to write the response to, DER
    #[arg(long, value_name = "FILE")]
    pub out: String,

    /// Serial number of a revoked certificate, as hex; repeatable. Others are answered good
    #[arg(long, value_name = "HEX")]
    pub revoke: Vec<String>,

    /// Hours until the next update
    #[arg(long, value_name = "HOURS", default_value_t = 24)]
    pub next_update_hours: u64,

    #[command(flatten)]
    pub signing: SigningArgs,
}

/// Whether `cert_id` identifies a certificate `issuer` issued: its issuer name and key hashed with
/// the request's hash algorithm. A hash algorithm offered here other than SHA-1, -256, -384 or
/// -512 never matches.
fn issued_by(cert_id: &CertId, issuer: &Certificate) -> Result<bool> {
    use const_oid::db::rfc5912::{ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512};
    let serial = cert_id.serial_number.clone();
    let ours = match cert_id.hash_algorithm.oid {
        ID_SHA_1 => CertId::from_issuer::<Sha1>(issuer, serial)?,
        ID_SHA_256 => CertId::from_issuer::<sha2::Sha256>(issuer, serial)?,
        ID_SHA_384 => CertId::from_issuer::<sha2::Sha384>(issuer, serial)?,
        ID_SHA_512 => CertId::from_issuer::<sha2::Sha512>(issuer, serial)?,
        _ => return Ok(false),
    };
    Ok(ours.issuer_name_hash == cert_id.issuer_name_hash
        && ours.issuer_key_hash == cert_id.issuer_key_hash)
}

fn ocsp(args: &OcspArgs) -> Result<bool> {
    let request = OcspRequest::from_der(&read_der(&args.request)?)
        .map_err(|e| format!("{}: not an OCSP request: {e}", args.request))?;
    let issuer = read_certificate(&args.issuer)?;

    let signing = &args.signing;
    let env = signing.environment()?;
    let held = signing.held(&env)?;
    let credential = held.credential();
    let responder = credential.certificate();
    let delegated = responder != &issuer;
    if delegated {
        // RFC 6960, section 4.2.2.2: a delegated responder's certificate is issued by the CA and
        // contains id-kp-OCSPSigning.
        if responder.tbs_certificate().issuer() != issuer.tbs_certificate().subject() {
            return Err(
                "the responder's certificate is not the --issuer's, nor issued by it".into(),
            );
        }
        let eku = responder
            .tbs_certificate()
            .get_extension::<ExtendedKeyUsage>()?
            .map(|(_, eku)| eku.0)
            .unwrap_or_default();
        if !eku.contains(&ID_KP_OCSP_SIGNING) {
            return Err(
                "a delegated responder's certificate must contain id-kp-OCSPSigning".into(),
            );
        }
    }

    let now = SystemTime::now();
    let this_update = OcspGeneralizedTime::try_from(now)?;
    let next_update =
        OcspGeneralizedTime::try_from(now + Duration::from_secs(args.next_update_hours * 3600))?;
    let revoked: Vec<SerialNumber> = args
        .revoke
        .iter()
        .map(|hex| Ok(SerialNumber::new(&from_hex(hex)?)?))
        .collect::<Result<_>>()?;

    // RFC 6960, section 4.2.1: byKey is the SHA-1 hash of the responder's public key.
    let key_hash = OctetString::new(
        Sha1::digest(
            responder
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes(),
        )
        .to_vec(),
    )?;
    let mut builder = OcspResponseBuilder::new(ResponderId::ByKey(key_hash));
    for single in &request.tbs_request.request_list {
        let cert_id = single.req_cert.clone();
        let status = if !issued_by(&cert_id, &issuer)? {
            CertStatus::unknown()
        } else if revoked.contains(&cert_id.serial_number) {
            CertStatus::revoked(RevokedInfo {
                revocation_time: this_update,
                revocation_reason: None,
            })
        } else {
            CertStatus::good()
        };
        builder = builder.with_single_response(
            SingleResponse::new(cert_id, status, this_update).with_next_update(next_update),
        );
    }
    if let Some(nonce) = request.nonce() {
        builder = builder.with_extension(&nonce)?;
    }

    let mut signer = signing.signer(&env, credential)?;
    // The responder's certificate goes in the response even when the CA signs, as openssl's
    // responder does, since clients such as openssl look for the signer only among the response's
    // certificates and those they are given.
    let response = builder.sign::<_, CredentialSignature>(
        &mut signer,
        Some(vec![responder.clone()]),
        OcspGeneralizedTime::try_from(now)?,
    )?;
    std::fs::write(&args.out, response.to_der()?).map_err(|e| format!("{}: {e}", args.out))?;
    Ok(true)
}

// ---- shared

fn extension(oid: ObjectIdentifier, critical: bool, value: &impl Encode) -> der::Result<Extension> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der()?)?,
    })
}

/// The key identifier of `ca`'s key, for an authority key identifier: its certificate's subject
/// key identifier, or without one, the SHA-1 hash of its public key (RFC 5280, section 4.2.1.2).
fn key_identifier(ca: &Certificate) -> Result<OctetString> {
    let tbs = ca.tbs_certificate();
    Ok(match tbs.get_extension::<SubjectKeyIdentifier>()? {
        Some((_, skid)) => skid.0,
        None => SubjectKeyIdentifier::try_from(tbs.subject_public_key_info().owned_to_ref())?.0,
    })
}

/// Fails unless `ca`'s basic constraints set cA.
fn require_ca(ca: &Certificate) -> Result<()> {
    match ca.tbs_certificate().get_extension::<BasicConstraints>()? {
        Some((_, bc)) if bc.ca => Ok(()),
        _ => Err(format!(
            "{} is not a CA certificate: its basic constraints do not set cA",
            display::name(ca.tbs_certificate().subject())
        )
        .into()),
    }
}

/// Fails when `cert` has a key usage extension without `usage`.
fn require_key_usage(cert: &Certificate, usage: KeyUsages, to: &str) -> Result<()> {
    match cert.tbs_certificate().get_extension::<KeyUsage>()? {
        Some((_, ku)) if !ku.0.contains(usage) => Err(format!(
            "the key usage of {} does not permit it to {to}",
            display::name(cert.tbs_certificate().subject())
        )
        .into()),
        _ => Ok(()),
    }
}

/// A positive serial number of 16 random octets, its first octet nonzero so that none is dropped.
fn random_serial() -> Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| format!("could not generate a serial number: {e}"))?;
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::new(&bytes)?)
}

fn write(file: &str, der: &[u8], form: Form, label: &str) -> Result<()> {
    let bytes = match form {
        Form::Der => der.to_vec(),
        Form::Pem => pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::LF, der)
            .map_err(|e| format!("{file}: {e}"))?
            .into_bytes(),
    };
    std::fs::write(file, bytes).map_err(|e| format!("{file}: {e}"))?;
    Ok(())
}

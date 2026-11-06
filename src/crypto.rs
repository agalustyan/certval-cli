//! `--crypto`: which implementation performs the cryptographic operations.
//!
//! The chosen implementation is registered ahead of certval's and certval-cms's software, so it is
//! consulted first and software answers only what it declines. With `--only`, software is not
//! registered behind it, so every operation reaches the chosen implementation or fails. Private key
//! operations are performed by a credential of the chosen implementation either way.
//!
//! Security.framework, CNG and PKCS #11 also hold keys: the keychain's identities, the current
//! user's certificate store and a token's certificates. Those are a [`Store`], from which `cms
//! decrypt` and `cms sign` take a key when no `--key` file is given, and which `cred list` lists.

use std::sync::Arc;

use certval::PkiEnvironment;
use certval_cms::{
    CmsEnvironment, RecipientCredential, SharedSigningCredential, SigningCredential,
    SigningCredentialLookup, SigningCredentialSource, SigningKey, SoftwareKey,
    SoftwareRecipientKey, SoftwareSigningKey,
};
use x509_cert::Certificate;

use crate::Result;

/// An implementation to perform cryptographic operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Crypto {
    /// certval's and certval-cms's RustCrypto software
    Software,
    /// The system's OpenSSL 3, through certval-openssl
    #[cfg(all(feature = "openssl", not(windows)))]
    Openssl,
    /// AWS-LC, through certval-awslc
    AwsLc,
    /// Apple's Security.framework, through certval-security-framework
    #[cfg(target_os = "macos")]
    SecurityFramework,
    /// Windows CNG, through certval-cng
    #[cfg(windows)]
    Cng,
    /// A PKCS #11 module, through certval-pkcs11; needs --pkcs11-module
    Pkcs11,
}

#[derive(clap::Args)]
pub struct CryptoArgs {
    /// The implementation that performs cryptographic operations, ahead of software
    #[arg(long, value_enum, default_value_t = Crypto::Software)]
    pub crypto: Crypto,

    /// Register only the --crypto implementation, without software behind it, so that every
    /// operation reaches it or fails
    #[arg(long)]
    pub only: bool,

    #[command(flatten)]
    pub pkcs11: Pkcs11Args,
}

/// Which PKCS #11 module and token --crypto pkcs11 uses.
#[derive(clap::Args)]
pub struct Pkcs11Args {
    /// The PKCS #11 module, a shared library, for --crypto pkcs11
    #[arg(long, value_name = "FILE", env = "CERTVAL_PKCS11_MODULE")]
    pub pkcs11_module: Option<String>,

    /// The label of the token, for --crypto pkcs11; the first slot with a token present when absent
    #[arg(long, value_name = "LABEL", env = "CERTVAL_PKCS11_TOKEN_LABEL")]
    pub pkcs11_token: Option<String>,

    /// The user PIN, for --crypto pkcs11, to decrypt or sign with a key on the token or list its
    /// keys
    #[arg(
        long,
        value_name = "PIN",
        env = "CERTVAL_PKCS11_USER_PIN",
        hide_env_values = true
    )]
    pub pkcs11_pin: Option<String>,
}

impl Pkcs11Args {
    /// The module --crypto pkcs11 loads.
    fn module(&self) -> Result<&str> {
        Ok(self
            .pkcs11_module
            .as_deref()
            .ok_or("--crypto pkcs11 needs --pkcs11-module")?)
    }
}

impl CryptoArgs {
    /// Whether software is registered: as the choice, or behind it.
    fn software(&self) -> bool {
        self.crypto == Crypto::Software || !self.only
    }

    /// A PkiEnvironment that hashes and verifies signatures with the chosen implementation.
    /// Path validation and certval's other callbacks are software in every case; what --only
    /// leaves out is software hashing and signature verification.
    pub fn pki_environment(&self) -> Result<PkiEnvironment> {
        let mut pe = PkiEnvironment::default();
        self.register_pki(&mut pe)?;
        pe.populate_5280_pki_environment();
        if !self.software() {
            pe.clear_calculate_hash_callbacks();
            pe.clear_verify_signature_message_callbacks();
            pe.clear_verify_signature_digest_callbacks();
            self.register_pki(&mut pe)?;
        }
        Ok(pe)
    }

    /// Registers the chosen implementation's hashing and signature verification on `pe`. Software
    /// registers nothing here, since populate_5280_pki_environment registers it.
    fn register_pki(&self, pe: &mut PkiEnvironment) -> Result<()> {
        match self.crypto {
            Crypto::Software => {}
            #[cfg(all(feature = "openssl", not(windows)))]
            Crypto::Openssl => {
                use certval_openssl::OpenSslCrypto;
                pe.add_calculate_hash_callback(OpenSslCrypto::new());
                pe.add_verify_signature_message_callback(OpenSslCrypto::new());
                pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
            }
            Crypto::AwsLc => {
                use certval_awslc::AwsLcCrypto;
                pe.add_calculate_hash_callback(AwsLcCrypto::new());
                pe.add_verify_signature_message_callback(AwsLcCrypto::new());
                pe.add_verify_signature_digest_callback(AwsLcCrypto::new());
            }
            #[cfg(target_os = "macos")]
            Crypto::SecurityFramework => {
                use certval_security_framework::SecurityFrameworkCrypto;
                pe.add_calculate_hash_callback(SecurityFrameworkCrypto::new());
                pe.add_verify_signature_message_callback(SecurityFrameworkCrypto::new());
                pe.add_verify_signature_digest_callback(SecurityFrameworkCrypto::new());
            }
            #[cfg(windows)]
            Crypto::Cng => {
                use certval_cng::CngCrypto;
                pe.add_calculate_hash_callback(CngCrypto::new());
                pe.add_verify_signature_message_callback(CngCrypto::new());
                pe.add_verify_signature_digest_callback(CngCrypto::new());
            }
            Crypto::Pkcs11 => {
                // One value in every role, so that they share a session and its key cache.
                let crypto = Arc::new(certval_pkcs11::Pkcs11Crypto::open(
                    self.pkcs11.module()?,
                    self.pkcs11.pkcs11_token.as_deref(),
                )?);
                pe.add_calculate_hash_callback(crypto.clone());
                pe.add_verify_signature_message_callback(crypto.clone());
                pe.add_verify_signature_digest_callback(crypto);
            }
        }
        Ok(())
    }

    /// A CmsEnvironment that encrypts and decrypts content and recipient keys with the chosen
    /// implementation, over `pe`. PKCS #11 offers none of these, only credentials, so with it
    /// they are software's, or with --only, nobody's.
    pub fn cms_environment(&self, pe: PkiEnvironment) -> CmsEnvironment {
        let mut env = CmsEnvironment::new();
        match self.crypto {
            Crypto::Software | Crypto::Pkcs11 => {}
            #[cfg(all(feature = "openssl", not(windows)))]
            Crypto::Openssl => {
                use certval_openssl::OpenSslCrypto;
                env.add_encrypt_content_callback(OpenSslCrypto::new());
                env.add_decrypt_content_callback(OpenSslCrypto::new());
                env.add_encrypt_key_transport_callback(OpenSslCrypto::new());
                env.add_encrypt_key_agreement_callback(OpenSslCrypto::new());
                env.add_encrypt_kem_callback(OpenSslCrypto::new());
            }
            Crypto::AwsLc => {
                use certval_awslc::AwsLcCrypto;
                env.add_encrypt_content_callback(AwsLcCrypto::new());
                env.add_decrypt_content_callback(AwsLcCrypto::new());
                env.add_encrypt_key_transport_callback(AwsLcCrypto::new());
                env.add_encrypt_key_agreement_callback(AwsLcCrypto::new());
                env.add_encrypt_kem_callback(AwsLcCrypto::new());
            }
            #[cfg(target_os = "macos")]
            Crypto::SecurityFramework => {
                use certval_security_framework::SecurityFrameworkCrypto;
                env.add_encrypt_content_callback(SecurityFrameworkCrypto::new());
                env.add_decrypt_content_callback(SecurityFrameworkCrypto::new());
                env.add_encrypt_key_transport_callback(SecurityFrameworkCrypto::new());
                env.add_encrypt_key_agreement_callback(SecurityFrameworkCrypto::new());
                #[cfg(feature = "cryptokit")]
                env.add_encrypt_kem_callback(SecurityFrameworkCrypto::new());
            }
            #[cfg(windows)]
            Crypto::Cng => {
                use certval_cng::CngCrypto;
                env.add_encrypt_content_callback(CngCrypto::new());
                env.add_decrypt_content_callback(CngCrypto::new());
                env.add_encrypt_key_transport_callback(CngCrypto::new());
                env.add_encrypt_key_agreement_callback(CngCrypto::new());
            }
        }
        if self.software() {
            env.populate_software();
        }
        env.set_pki_environment(Arc::new(pe));
        env
    }

    /// A recipient credential of the chosen implementation for the PKCS #8 key `pkcs8`.
    pub fn recipient_credential(
        &self,
        certificate: Certificate,
        pkcs8: &[u8],
    ) -> Result<Box<dyn RecipientCredential>> {
        Ok(match self.crypto {
            Crypto::Software => Box::new(SoftwareRecipientKey::from_pkcs8_der(certificate, pkcs8)?),
            #[cfg(all(feature = "openssl", not(windows)))]
            Crypto::Openssl => Box::new(certval_openssl::OpenSslRecipientKey::from_pkcs8_der(
                certificate,
                pkcs8,
            )?),
            Crypto::AwsLc => Box::new(certval_awslc::AwsLcRecipientKey::from_pkcs8_der(
                certificate,
                pkcs8,
            )?),
            #[cfg(target_os = "macos")]
            Crypto::SecurityFramework => security_framework_recipient(certificate, pkcs8)?,
            #[cfg(windows)]
            Crypto::Cng => Box::new(certval_cng::import_pkcs8(certificate, pkcs8)?.0),
            Crypto::Pkcs11 => return Err(pkcs11_key_file()),
        })
    }

    /// A signing credential of the chosen implementation for the PKCS #8 key `pkcs8`.
    pub fn signing_credential(
        &self,
        certificate: Certificate,
        pkcs8: &[u8],
    ) -> Result<Box<dyn SigningCredential>> {
        Ok(match self.crypto {
            Crypto::Software => Box::new(SoftwareSigningKey::from_pkcs8_der(certificate, pkcs8)?),
            #[cfg(all(feature = "openssl", not(windows)))]
            Crypto::Openssl => Box::new(certval_openssl::OpenSslSigningKey::from_pkcs8_der(
                certificate,
                pkcs8,
            )?),
            Crypto::AwsLc => Box::new(certval_awslc::AwsLcSigningKey::from_pkcs8_der(
                certificate,
                pkcs8,
            )?),
            #[cfg(target_os = "macos")]
            Crypto::SecurityFramework => security_framework_signer(certificate, pkcs8)?,
            #[cfg(windows)]
            Crypto::Cng => Box::new(certval_cng::import_pkcs8(certificate, pkcs8)?.1),
            Crypto::Pkcs11 => return Err(pkcs11_key_file()),
        })
    }

    /// A key of the chosen implementation, with no certificate, for the PKCS #8 key `pkcs8`: to
    /// sign its own certificate request or a self-signed certificate.
    pub fn signing_key(&self, pkcs8: &[u8]) -> Result<Box<dyn SigningKey>> {
        Ok(match self.crypto {
            Crypto::Software => Box::new(SoftwareKey::from_pkcs8_der(pkcs8)?),
            #[cfg(all(feature = "openssl", not(windows)))]
            Crypto::Openssl => Box::new(certval_openssl::OpenSslKey::from_pkcs8_der(pkcs8)?),
            Crypto::AwsLc => Box::new(certval_awslc::AwsLcKey::from_pkcs8_der(pkcs8)?),
            #[cfg(target_os = "macos")]
            Crypto::SecurityFramework => security_framework_key(pkcs8)?,
            #[cfg(windows)]
            Crypto::Cng => {
                return Err(
                    "--crypto cng does not yet sign with a key that has no certificate".into(),
                )
            }
            Crypto::Pkcs11 => {
                return Err(
                    "--crypto pkcs11 does not yet sign with a key that has no certificate".into(),
                )
            }
        })
    }

    /// The store of keys the chosen implementation holds.
    pub fn store(&self) -> Result<Store> {
        Store::open(self.crypto, &self.pkcs11)
    }
}

impl Crypto {
    /// The name --crypto takes.
    pub fn name(self) -> String {
        clap::ValueEnum::to_possible_value(&self)
            .map(|v| v.get_name().to_string())
            .unwrap_or_default()
    }
}

/// A Security.framework recipient credential for the PKCS #8 key `pkcs8`: an ML-KEM key in CryptoKit
/// with the `cryptokit` feature, and an RSA or EC key in Security.framework.
#[cfg(target_os = "macos")]
fn security_framework_recipient(
    certificate: Certificate,
    pkcs8: &[u8],
) -> Result<Box<dyn RecipientCredential>> {
    #[cfg(feature = "cryptokit")]
    {
        use const_oid::db::fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768};
        let oid = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid;
        if [ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024].contains(&oid) {
            return Ok(Box::new(
                certval_security_framework::CryptoKitRecipientKey::from_pkcs8_der(
                    certificate,
                    pkcs8,
                )?,
            ));
        }
    }
    Ok(Box::new(
        certval_security_framework::import_pkcs8(certificate, pkcs8)?.0,
    ))
}

/// A Security.framework signing credential for the PKCS #8 key `pkcs8`: an ML-DSA key in CryptoKit
/// with the `cryptokit` feature, and an RSA or EC key in Security.framework.
#[cfg(target_os = "macos")]
fn security_framework_signer(
    certificate: Certificate,
    pkcs8: &[u8],
) -> Result<Box<dyn SigningCredential>> {
    #[cfg(feature = "cryptokit")]
    {
        use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
        let oid = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid;
        if [ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87].contains(&oid) {
            return Ok(Box::new(
                certval_security_framework::CryptoKitSigningKey::from_pkcs8_der(
                    certificate,
                    pkcs8,
                )?,
            ));
        }
    }
    Ok(Box::new(
        certval_security_framework::import_pkcs8(certificate, pkcs8)?.1,
    ))
}

/// A Security.framework key with no certificate for the PKCS #8 key `pkcs8`: an ML-DSA key in
/// CryptoKit with the `cryptokit` feature, and an RSA or EC key in Security.framework.
#[cfg(target_os = "macos")]
fn security_framework_key(pkcs8: &[u8]) -> Result<Box<dyn SigningKey>> {
    #[cfg(feature = "cryptokit")]
    {
        use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
        let oid = pkcs8::PrivateKeyInfoRef::try_from(pkcs8)
            .map_err(|e| format!("not a PKCS #8 key: {e}"))?
            .algorithm
            .oid;
        if [ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87].contains(&oid) {
            return Ok(Box::new(
                certval_security_framework::CryptoKitKey::from_pkcs8_der(pkcs8)?,
            ));
        }
    }
    Ok(Box::new(certval_security_framework::import_pkcs8_key(
        pkcs8,
    )?))
}

fn pkcs11_key_file() -> Box<dyn std::error::Error> {
    "--crypto pkcs11 uses the keys on the token, not a --key file".into()
}

/// The keys an implementation holds, each with its certificate.
pub enum Store {
    #[cfg(target_os = "macos")]
    Keychain(certval_security_framework::KeychainIdentities),
    #[cfg(windows)]
    CertStore(certval_cng::CertStoreIdentities),
    Token(certval_pkcs11::TokenIdentities),
}

impl Store {
    /// The store of keys `crypto` holds, logging in to the token for PKCS #11.
    pub fn open(crypto: Crypto, pkcs11: &Pkcs11Args) -> Result<Self> {
        match crypto {
            #[cfg(target_os = "macos")]
            Crypto::SecurityFramework => Ok(Store::Keychain(
                certval_security_framework::KeychainIdentities::new(),
            )),
            #[cfg(windows)]
            Crypto::Cng => Ok(Store::CertStore(certval_cng::CertStoreIdentities::new())),
            Crypto::Pkcs11 => {
                let pin = pkcs11
                    .pkcs11_pin
                    .as_deref()
                    .ok_or("--crypto pkcs11 needs --pkcs11-pin to use the token's keys")?;
                let token = certval_pkcs11::Pkcs11Token::open(
                    pkcs11.module()?,
                    pkcs11.pkcs11_token.as_deref(),
                    &cryptoki::types::AuthPin::new(pin.into()),
                )?;
                Ok(Store::Token(certval_pkcs11::TokenIdentities::new(
                    Arc::new(token),
                )))
            }
            _ => Err(format!(
                "--crypto {} holds no keys; a key is given with --cert and --key",
                crypto.name()
            )
            .into()),
        }
    }

    /// What the store is, for a message.
    pub fn description(&self) -> &'static str {
        match self {
            #[cfg(target_os = "macos")]
            Store::Keychain(_) => "the keychain",
            #[cfg(windows)]
            Store::CertStore(_) => "the certificate store",
            Store::Token(_) => "the token",
        }
    }

    /// The certificate of every key the store holds.
    pub fn certificates(&self) -> Result<Vec<Certificate>> {
        Ok(match self {
            #[cfg(target_os = "macos")]
            Store::Keychain(s) => s.certificates()?,
            #[cfg(windows)]
            Store::CertStore(s) => s.certificates()?,
            Store::Token(s) => s.certificates()?,
        })
    }

    /// Every key the store holds for `lookup`, whatever its certificate's key usage permits.
    /// `CmsEnvironment::find_signing_credentials` keeps only keys permitted digitalSignature or
    /// nonRepudiation, which leaves out a CA's key; `ca` checks keyCertSign or cRLSign itself.
    pub fn find_signing_credentials(
        &self,
        env: &CmsEnvironment,
        lookup: SigningCredentialLookup<'_>,
    ) -> Result<Vec<SharedSigningCredential>> {
        Ok(match self {
            #[cfg(target_os = "macos")]
            Store::Keychain(s) => s.find_signing_credentials(env, lookup)?,
            #[cfg(windows)]
            Store::CertStore(s) => s.find_signing_credentials(env, lookup)?,
            Store::Token(s) => s.find_signing_credentials(env, lookup)?,
        })
    }

    /// Registers the store on `env` as a source of both recipient and signing credentials.
    pub fn register(&self, env: &mut CmsEnvironment) {
        match self {
            #[cfg(target_os = "macos")]
            Store::Keychain(s) => {
                env.add_recipient_credential_source(*s);
                env.add_signing_credential_source(*s);
            }
            #[cfg(windows)]
            Store::CertStore(s) => {
                env.add_recipient_credential_source(*s);
                env.add_signing_credential_source(*s);
            }
            Store::Token(s) => {
                env.add_recipient_credential_source(s.clone());
                env.add_signing_credential_source(s.clone());
            }
        }
    }
}

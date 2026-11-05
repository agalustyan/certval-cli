//! `--crypto`: which implementation performs the cryptographic operations.
//!
//! The chosen implementation is registered ahead of certval's and certval-cms's software, so it is
//! consulted first and software answers only what it declines. With `--only`, software is not
//! registered behind it, so every operation reaches the chosen implementation or fails. Private key
//! operations are performed by a credential of the chosen implementation either way.

use std::sync::Arc;

use certval::PkiEnvironment;
use certval_cms::{
    CmsEnvironment, RecipientCredential, SigningCredential, SoftwareRecipientKey,
    SoftwareSigningKey,
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
}

impl CryptoArgs {
    /// Whether software is registered: as the choice, or behind it.
    fn software(&self) -> bool {
        self.crypto == Crypto::Software || !self.only
    }

    /// A PkiEnvironment that hashes and verifies signatures with the chosen implementation.
    /// Path validation and certval's other callbacks are software in every case; what --only
    /// leaves out is software hashing and signature verification.
    pub fn pki_environment(&self) -> PkiEnvironment {
        let mut pe = PkiEnvironment::default();
        register_pki(&mut pe, self.crypto);
        pe.populate_5280_pki_environment();
        if !self.software() {
            pe.clear_calculate_hash_callbacks();
            pe.clear_verify_signature_message_callbacks();
            pe.clear_verify_signature_digest_callbacks();
            register_pki(&mut pe, self.crypto);
        }
        pe
    }

    /// A CmsEnvironment that encrypts and decrypts content and recipient keys with the chosen
    /// implementation, over `pe`.
    pub fn cms_environment(&self, pe: PkiEnvironment) -> CmsEnvironment {
        let mut env = CmsEnvironment::new();
        match self.crypto {
            Crypto::Software => {}
            #[cfg(all(feature = "openssl", not(windows)))]
            Crypto::Openssl => {
                use certval_openssl::OpenSslCrypto;
                env.add_encrypt_content_callback(OpenSslCrypto::new());
                env.add_decrypt_content_callback(OpenSslCrypto::new());
                env.add_encrypt_key_transport_callback(OpenSslCrypto::new());
                env.add_encrypt_key_agreement_callback(OpenSslCrypto::new());
                env.add_encrypt_kem_callback(OpenSslCrypto::new());
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
        })
    }
}

/// Registers `crypto`'s hashing and signature verification on `pe`. Software registers nothing
/// here, since populate_5280_pki_environment registers it, so without another implementation
/// compiled in, `pe` goes unused.
#[cfg_attr(not(all(feature = "openssl", not(windows))), allow(unused_variables))]
fn register_pki(pe: &mut PkiEnvironment, crypto: Crypto) {
    match crypto {
        Crypto::Software => {}
        #[cfg(all(feature = "openssl", not(windows)))]
        Crypto::Openssl => {
            use certval_openssl::OpenSslCrypto;
            pe.add_calculate_hash_callback(OpenSslCrypto::new());
            pe.add_verify_signature_message_callback(OpenSslCrypto::new());
            pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
        }
    }
}

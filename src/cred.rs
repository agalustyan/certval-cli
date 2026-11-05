//! `certval cred`: the keys an implementation holds, each with its certificate: the keychain's
//! identities for Security.framework, the current user's certificate store for CNG, and a token's
//! certificates for PKCS #11. `cms decrypt` and `cms sign` use these keys when no `--key` is given.

use const_oid::db::rfc5280::{
    ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME, ID_CE_SUBJECT_KEY_IDENTIFIER,
};

use crate::crypto::{Crypto, Pkcs11Args, Store};
use crate::display;
use crate::Result;

#[derive(clap::Subcommand)]
pub enum Command {
    /// List the keys an implementation holds, by their certificates
    List(ListArgs),
}

#[derive(clap::Args)]
pub struct ListArgs {
    /// The implementation whose keys to list: security-framework (the keychain), cng (the
    /// certificate store) or pkcs11 (a token)
    #[arg(long, value_enum)]
    pub crypto: Crypto,

    #[command(flatten)]
    pub pkcs11: Pkcs11Args,
}

pub fn run(command: &Command) -> Result<bool> {
    match command {
        Command::List(args) => list(args),
    }
}

/// The extensions that tell which key is which and what it may do, shown for each.
const EXTENSIONS: [const_oid::ObjectIdentifier; 4] = [
    ID_CE_KEY_USAGE,
    ID_CE_EXT_KEY_USAGE,
    ID_CE_SUBJECT_ALT_NAME,
    ID_CE_SUBJECT_KEY_IDENTIFIER,
];

fn list(args: &ListArgs) -> Result<bool> {
    let store = Store::open(args.crypto, &args.pkcs11)?;
    let certificates = store.certificates()?;
    let keys = if certificates.len() == 1 {
        "key"
    } else {
        "keys"
    };
    println!("{} {keys} in {}", certificates.len(), store.description());
    for cert in &certificates {
        let tbs = cert.tbs_certificate();
        println!();
        println!("Subject:     {}", display::name(tbs.subject()));
        println!("Issuer:      {}", display::name(tbs.issuer()));
        println!(
            "Serial:      {}",
            display::hex(tbs.serial_number().as_bytes())
        );
        println!("Not before:  {}", display::time(&tbs.validity().not_before));
        println!("Not after:   {}", display::time(&tbs.validity().not_after));
        println!(
            "Public key:  {}",
            display::public_key(tbs.subject_public_key_info())
        );
        for ext in tbs
            .extensions()
            .into_iter()
            .flatten()
            .filter(|e| EXTENSIONS.contains(&e.extn_id))
        {
            display::print_extension(ext, "    ");
        }
    }
    Ok(true)
}

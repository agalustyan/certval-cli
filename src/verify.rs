//! `certval verify`: validate a certification path to a target certificate.
//!
//! Trust anchors come either from files named with `--anchor` or from a store compiled into the
//! binary (`--store`). Intermediates come from `--chain` and, for a store that includes one, from the
//! store's own CA certificates. CRLs named with `--crl` are consulted when revocation is checked.
//! Every path the sources can assemble is validated and reported, and the command succeeds when at
//! least one is valid.

use crate::crypto::CryptoArgs;
use crate::display;
use crate::input::read_der;
use crate::trust;
use crate::Result;
use certval::*;

#[derive(clap::Args)]
pub struct Args {
    /// Certificate to validate, DER or PEM
    pub target: Option<String>,

    /// Trust anchor certificate, DER, or PEM holding one or more; repeatable. Used instead of --store
    #[arg(long, value_name = "FILE", conflicts_with = "store")]
    pub anchor: Vec<String>,

    /// Store compiled into this binary to take anchors and CA certificates from; see --list-stores
    #[arg(long)]
    pub store: Option<String>,

    /// Intermediate CA certificate to consider, DER, or PEM holding one or more; repeatable
    #[arg(long, value_name = "FILE")]
    pub chain: Vec<String>,

    /// JSON certification path validation settings (policy, time of interest, revocation)
    #[arg(long, value_name = "FILE")]
    pub settings: Option<String>,

    /// Check revocation status over the network (CRLs and OCSP). Off unless asked for, as with
    /// openssl verify; a settings file can also turn it on
    #[arg(long)]
    pub check_revocation: bool,

    /// CRL to consult when checking revocation, DER or PEM; repeatable. Consulted before any CRL or
    /// OCSP responder a certificate names
    #[arg(long, value_name = "FILE")]
    pub crl: Vec<String>,

    /// List the stores this binary contains, then exit
    #[arg(long)]
    pub list_stores: bool,

    #[command(flatten)]
    pub crypto: CryptoArgs,
}

pub async fn run(args: &Args) -> Result<bool> {
    if args.list_stores {
        trust::list_stores();
        return Ok(true);
    }

    let Some(target) = &args.target else {
        return Err("a target certificate is required unless --list-stores is given".into());
    };
    if args.anchor.is_empty() && args.store.is_none() {
        return Err("name trust anchors with --anchor, or a store with --store".into());
    }

    let mut cps = trust::settings(args.settings.as_deref())?;
    if args.check_revocation {
        cps.set_check_revocation_status(true);
    }
    let toi = cps.get_time_of_interest();

    let mut pe = args.crypto.pki_environment();
    let anchors_only = trust::add_trust(
        &mut pe,
        &cps,
        &args.anchor,
        args.store.as_deref(),
        &args.chain,
        &args.crl,
    )?;

    let mut target_cert = PDVCertificate::try_from(read_der(target)?.as_slice())
        .map_err(|e| format!("{target}: not a certificate: {e:?}"))?;
    target_cert.parse_extensions(EXTS_OF_INTEREST);

    // A threshold of 0 collects every path the sources can assemble. In a cross-certified
    // community there is often more than one, and they need not reach the same verdict.
    let mut paths = vec![];
    match pe.get_paths_for_target(&target_cert, &mut paths, 0, toi) {
        Ok(()) => {}
        Err(certval::Error::PathValidation(
            PathValidationStatus::InvalidNotAfterDate | PathValidationStatus::InvalidNotBeforeDate,
        )) => {
            println!("target is not valid at the time of interest ({toi})");
            return Ok(false);
        }
        Err(e) => return Err(format!("{e:?}").into()),
    }
    if paths.is_empty() {
        println!("no candidate paths to a trust anchor");
        if anchors_only && args.chain.is_empty() {
            println!("the store includes anchors only; name intermediates with --chain");
        }
        return Ok(false);
    }

    let mut any_valid = false;
    for (i, path) in paths.iter_mut().enumerate() {
        let mut cpr = CertificationPathResults::new();
        let result = validate_path_rfc5280(&pe, &cps, path, &mut cpr);
        if result.is_ok() && cps.get_check_revocation_status() {
            let _ = check_revocation(&pe, &cps, path, &mut cpr).await;
        }
        let status = cpr
            .get_validation_status()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|| format!("{result:?}"));
        println!("path {i}: {status}");
        print_path(path);
        any_valid |= cpr.get_validation_status() == Some(PathValidationStatus::Valid);
    }
    Ok(any_valid)
}

/// Prints a path from its anchor down to the target, one subject per line.
fn print_path(path: &CertificationPath) {
    if let Ok(name) = get_trust_anchor_name(path.trust_anchor.decoded()) {
        println!("    anchor        {}", display::name(name));
    }
    for ca in &path.intermediates {
        println!(
            "    intermediate  {}",
            display::name(ca.decoded().tbs_certificate().subject())
        );
    }
    println!(
        "    target        {}",
        display::name(path.target.decoded().tbs_certificate().subject())
    );
}

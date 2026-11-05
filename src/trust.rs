//! What validates certificates: trust anchors from files or a store compiled into the binary,
//! intermediates, CRLs and path validation settings, shared by `verify` and `cms verify`.

use certval::*;
use certval_stores_core::{prepare_certval_environment, TrustStoreProvider};

use crate::input::{read_certs, read_der};
use crate::Result;

/// The stores this binary contains.
pub fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    vec![
        certval_stores_fpki::provider(),
        certval_stores_webpki_root_certs::provider(),
    ]
}

/// Prints the stores this binary contains.
pub fn list_stores() {
    for provider in providers() {
        for entry in provider.entries() {
            let cas = if entry.cert_store_cbor.is_some() {
                "with CA store"
            } else {
                "anchors only"
            };
            println!(
                "{:<20} {:>4} anchors, {cas:<13} {}",
                entry.id,
                entry.roots.len(),
                entry.label
            );
        }
    }
}

/// The path validation settings in `file`, or with none, the defaults with revocation checking
/// off.
pub fn settings(file: Option<&str>) -> Result<CertificationPathSettings> {
    match file {
        Some(file) => {
            if !std::path::Path::new(file).exists() {
                return Err(format!("settings file not found: {file}").into());
            }
            Ok(read_settings(&Some(file.to_string()))?)
        }
        None => {
            let mut cps = CertificationPathSettings::default();
            cps.set_check_revocation_status(false);
            Ok(cps)
        }
    }
}

/// Adds trust anchors, from `anchors` or `store`, intermediates from `chain` and the store, and
/// CRLs from `crls` to `pe`. Returns whether the store holds anchors only.
pub fn add_trust(
    pe: &mut PkiEnvironment,
    cps: &CertificationPathSettings,
    anchors: &[String],
    store: Option<&str>,
    chain: &[String],
    crls: &[String],
) -> Result<bool> {
    let mut anchors_only = false;
    if let Some(store) = store {
        let Some(entry) = providers()
            .iter()
            .flat_map(|p| p.entries())
            .find(|e| e.id == store)
        else {
            return Err(format!("unknown store {store}; --list-stores prints the ids").into());
        };
        anchors_only = entry.cert_store_cbor.is_none();
        prepare_certval_environment(&providers(), pe, store)?;
    } else {
        let mut ta_source = TaSource::new();
        for file in anchors {
            for (i, bytes) in read_certs(file)?.into_iter().enumerate() {
                ta_source.push(CertFile {
                    filename: format!("{file}#{i}"),
                    bytes,
                });
            }
        }
        ta_source.initialize()?;
        pe.add_trust_anchor_source(Box::new(ta_source));
    }

    // Registered even when --chain names nothing: path building runs only through certificate
    // sources, so without one a target issued directly by an anchor would find no path.
    let mut cert_source = CertSource::new();
    for file in chain {
        for (i, bytes) in read_certs(file)?.into_iter().enumerate() {
            cert_source.push(CertFile {
                filename: format!("{file}#{i}"),
                bytes,
            });
        }
    }
    cert_source.initialize(cps)?;
    cert_source.find_all_partial_paths(pe, cps);
    pe.add_certificate_source(Box::new(cert_source));

    if !crls.is_empty() {
        let crl_source = MemoryCrlSource::new();
        for file in crls {
            if !crl_source.add(&read_der(file)?) {
                return Err(format!("{file}: not a CRL").into());
            }
        }
        pe.add_crl_source(Box::new(crl_source));
    }
    Ok(anchors_only)
}

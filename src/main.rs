//! `certval`: an openssl-style command-line tool for X.509 certificates, CRLs, OCSP and DER, with
//! RFC 5280 certification path validation by certval.
//!
//! Each subcommand reads DER, or PEM where the file holds it, and prints a readable description.
//! The command names follow openssl's; the flags do not.

mod asn1parse;
mod cms;
mod cred;
mod crl;
mod crypto;
mod display;
mod input;
mod ocsp;
mod trust;
mod verify;
mod x509;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "certval",
    version,
    about = "Inspect X.509 certificates, CRLs, OCSP responses and DER, and validate certification paths"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Describe a certificate
    X509(x509::Args),
    /// Describe a certificate revocation list
    Crl(crl::Args),
    /// Dump the DER structure of a file
    Asn1parse(asn1parse::Args),
    /// Validate a certification path to a target certificate
    Verify(verify::Args),
    /// Query an OCSP responder, or describe a saved response
    Ocsp(ocsp::Args),
    /// Encrypt, decrypt, sign and verify CMS messages
    #[command(subcommand)]
    Cms(cms::Command),
    /// List the keys the keychain, the certificate store or a PKCS #11 token holds
    #[command(subcommand)]
    Cred(cred::Command),
}

/// Restores the default action for SIGPIPE, which Rust programs otherwise ignore, so that output
/// piped into `head` or `grep -q` ends the process quietly instead of panicking in `println!`.
#[cfg(unix)]
fn exit_quietly_on_broken_pipe() {
    // SAFETY: called once at startup, before any other thread exists, and setting a signal's
    // disposition to its default touches no Rust state.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn exit_quietly_on_broken_pipe() {}

fn main() -> ExitCode {
    // Before the runtime starts, so no other thread exists yet.
    exit_quietly_on_broken_pipe();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("certval: could not start the async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> ExitCode {
    let outcome = match cli.command {
        Command::X509(args) => x509::run(&args).map(|()| true),
        Command::Crl(args) => crl::run(&args).map(|()| true),
        Command::Asn1parse(args) => asn1parse::run(&args).map(|()| true),
        Command::Verify(args) => verify::run(&args).await,
        Command::Ocsp(args) => ocsp::run(&args).await.map(|()| true),
        Command::Cms(command) => cms::run(&command),
        Command::Cred(command) => cred::run(&command),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("certval: {e}");
            ExitCode::from(2)
        }
    }
}

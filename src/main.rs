use std::fs;
use std::path::PathBuf;

use clap::{Parser};
use rsa::{
    // pkcs8::{DecodePrivateKey, DecodePublicKey},
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Read a rsa privkey
    #[clap(long, value_parser, value_name = "FILE")]
    privkey: Option<PathBuf>,

    /// Read a rsa pubkey
    #[clap(long, value_parser, value_name = "FILE")]
    pubkey: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    println!("cli: {:?}", cli);
    if let Some(path) = cli.privkey.as_ref() {
        let content = fs::read_to_string(path).unwrap();
        let priv_key = RsaPrivateKey::from_pkcs1_pem(content.as_str()).unwrap();
        println!("[private key]: {:?}\n", priv_key);
    }
    if let Some(path) = cli.pubkey.as_ref() {
        let content = fs::read_to_string(path).unwrap();
        let pub_key = RsaPublicKey::from_pkcs1_pem(content.as_str()).unwrap();
        println!("[public key]: {:?}\n", pub_key);
    }
}

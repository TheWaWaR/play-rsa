use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use pem_rfc7468::LineEnding;
use rsa::{
    hash::Hash,
    padding::PaddingScheme,
    // pkcs8::{DecodePrivateKey, DecodePublicKey},
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    PublicKey,
    PublicKeyParts,
    RsaPrivateKey,
    RsaPublicKey,
};
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
/// Sign/Verify: Padding Scheme use PKCS1v15 and hash function use sha2_256.
/// Encrypt/Decrypt: Padding Scheme use PKCS1v15.
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sign a message use private key, output the signature (hex format)
    Sign {
        /// The rsa private key
        #[clap(long, value_parser, value_name = "FILE")]
        private_key: PathBuf,

        /// The message to sign
        #[clap(long, value_parser, value_name = "STRING")]
        message: String,
    },
    /// Verify a message use public key
    Verify {
        /// The rsa public key
        #[clap(long, value_parser, value_name = "FILE")]
        public_key: PathBuf,

        /// The message to sign
        #[clap(long, value_parser, value_name = "STRING")]
        message: String,

        /// The signature (hex format)
        #[clap(long, value_parser, value_name = "STRING")]
        signature_hex: String,
    },
    /// Encrypt a message use public key, output the ciphertext (hex format)
    Encrypt {
        /// The rsa public key
        #[clap(long, value_parser, value_name = "FILE")]
        public_key: PathBuf,

        /// The message to encrypt
        #[clap(long, value_parser, value_name = "STRING")]
        message: String,
    },
    /// Decrypt a ciphertext use private key, output the message
    Decrypt {
        /// The rsa private key
        #[clap(long, value_parser, value_name = "FILE")]
        private_key: PathBuf,

        /// The ciphertext to decrypt (hex format)
        #[clap(long, value_parser, value_name = "STRING")]
        ciphertext_hex: String,
    },
    /// Generate public key from a private key (pkcs1 pem format)
    GenPublicKey {
        /// The rsa private key
        #[clap(long, value_parser, value_name = "FILE")]
        private_key: PathBuf,
    },
    /// Generate a random private key (pkcs1 pem format)
    GenPrivateKey {
        /// bit size, allowed value: [1024, 2048, 4096]
        #[clap(long, value_parser, value_name = "NUMBER")]
        bit_size: usize,
    },
}

fn pubkey_from_path(path: &Path) -> RsaPublicKey {
    let content = fs::read_to_string(path).unwrap();
    RsaPublicKey::from_pkcs1_pem(content.as_str()).unwrap()
}
fn privkey_from_path(path: &Path) -> RsaPrivateKey {
    let content = fs::read_to_string(path).unwrap();
    RsaPrivateKey::from_pkcs1_pem(content.as_str()).unwrap()
}

fn main() {
    let cli = Cli::parse();
    println!("command: {:?}", cli.command);
    let sign_padding = PaddingScheme::PKCS1v15Sign {
        hash: Some(Hash::SHA2_256),
    };
    let encrypt_padding = PaddingScheme::PKCS1v15Encrypt;
    match cli.command {
        Commands::Sign {
            private_key,
            message,
        } => {
            let priv_key = privkey_from_path(&private_key);
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let digest = hasher.finalize();
            let signature = priv_key.sign(sign_padding, digest.as_slice()).unwrap();
            println!(">> signature: {}", hex::encode(signature));
        }
        Commands::Verify {
            public_key,
            message,
            signature_hex,
        } => {
            let pub_key = pubkey_from_path(&public_key);
            let signature = hex::decode(&signature_hex).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            let digest = hasher.finalize();
            if let Err(err) = pub_key.verify(sign_padding, digest.as_slice(), &signature) {
                println!(">> verify failed: {:?}", err);
            } else {
                println!(">> verify ok");
            }
        }
        Commands::Encrypt {
            public_key,
            message,
        } => {
            let pub_key = pubkey_from_path(&public_key);
            let mut rng = rand::thread_rng();
            let ciphertext = pub_key
                .encrypt(&mut rng, encrypt_padding, message.as_bytes())
                .unwrap();
            println!(">> ciphertext: {}", hex::encode(&ciphertext));
        }
        Commands::Decrypt {
            private_key,
            ciphertext_hex,
        } => {
            let priv_key = privkey_from_path(&private_key);
            let ciphertext = hex::decode(&ciphertext_hex).unwrap();
            match priv_key.decrypt(encrypt_padding, &ciphertext) {
                Ok(bytes) => {
                    println!(">> message: {}", String::from_utf8_lossy(&bytes));
                }
                Err(err) => {
                    println!(">> decrypt failed: {:?}", err);
                }
            }
        }
        Commands::GenPublicKey { private_key } => {
            let priv_key = privkey_from_path(&private_key);
            let pub_key = priv_key.to_public_key();
            let pub_pem = pub_key.to_pkcs1_pem(LineEnding::LF).unwrap();
            println!(">> bit_size: {}", pub_key.size() * 8);
            println!(">> [public key pem]:\n{}", pub_pem);
        }
        Commands::GenPrivateKey { bit_size } => {
            if ![1024, 2048, 4096].iter().any(|v| *v == bit_size) {
                println!("ERROR: invalid <bit-size>: {}", bit_size);
                exit(-1);
            }
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, bit_size).expect("generate a key");
            let priv_pem = priv_key.to_pkcs1_pem(LineEnding::LF).unwrap();
            let pub_key = priv_key.to_public_key();
            let pub_pem = pub_key.to_pkcs1_pem(LineEnding::LF).unwrap();
            println!(">> [private key pem]:\n{}", priv_pem.deref());
            println!(">> [public  key pem]:\n{}", pub_pem);
        }
    }
}

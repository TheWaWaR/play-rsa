use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pem_rfc7468::LineEnding;
use rsa::{
    // pkcs8::{DecodePrivateKey, DecodePublicKey},
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey},
    RsaPrivateKey,
    RsaPublicKey,
};

#[derive(Parser, Debug)]
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
        signature: String,
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

        /// The ciphertext to decrypt
        #[clap(long, value_parser, value_name = "STRING")]
        ciphertext: String,
    },
    /// Generate public key from a private key (pkcs1 pem format)
    ToPublicKey {
        /// The rsa private key
        #[clap(long, value_parser, value_name = "FILE")]
        private_key: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    println!("command: {:?}", cli.command);
    match cli.command {
        Commands::Sign {
            private_key,
            message,
        } => {}
        Commands::Verify {
            public_key,
            message,
            signature,
        } => {
            let content = fs::read_to_string(public_key).unwrap();
            let pub_key = RsaPublicKey::from_pkcs1_pem(content.as_str()).unwrap();
            println!("[public key]: {:?}", pub_key);
        }
        Commands::Encrypt {
            public_key,
            message,
        } => {}
        Commands::Decrypt {
            private_key,
            ciphertext,
        } => {}
        Commands::ToPublicKey { private_key } => {
            let content = fs::read_to_string(private_key).unwrap();
            let priv_key = RsaPrivateKey::from_pkcs1_pem(content.as_str()).unwrap();
            let pub_key = priv_key.to_public_key();
            let pub_pem = pub_key.to_pkcs1_pem(LineEnding::LF).unwrap();
            println!("[public key pem]:\n{}", pub_pem);
        }
    }
}

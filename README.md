
## Usage
```
$ cargo run -- --help
play-rsa 0.1.0
Sign/Verify: Padding Scheme use PKCS1v15 and hash function use ripemd160. Encrypt/Decrypt: Padding
Scheme use PKCS1v15

USAGE:
    play-rsa <SUBCOMMAND>

SUBCOMMANDS:
    decrypt          Decrypt a ciphertext use private key, output the message
    encrypt          Encrypt a message use public key, output the ciphertext (hex format)
    help             Print this message or the help of the given subcommand(s)
    sign             Sign (use RIPEMD160 hash) a message use private key, output the signature
                         (hex format)
    to-public-key    Generate public key from a private key (pkcs1 pem format)
    verify           Verify a message use public key
```

## Export private/public key from gpg key

Install openpgp2pem
```
sudo apt install monkeysphere
```

Remove password and export the keys
```shell
gpg --edit-key D937A057 # removing password
gpg --export D937A057 | openpgp2pem D937A057 >  D937A057.rsa.pubkey # generating public key
gpg --export-secret-key D937A057 | openpgp2pem D937A057 > D937A057.rsa.privkey # generating private key
gpg --delete-secret-key D937A057 # cleanup
```


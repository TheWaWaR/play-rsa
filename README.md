
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


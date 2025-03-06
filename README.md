# Sodix

A Rust CLI tool providing libsodium-compatible cryptographic operations. Uses Ed25519 for signing and Curve25519 for encryption, with hex-encoded keys for easy scripting.

## Quick Start

```bash
# Install
cargo install sodix

# Generate keys
sodix generate     # Creates key files in current directory
sodix generate -k /path/to/keys   # Custom key location

# Key operations
sodix print        # Show all keys
sodix print -p     # Show only public keys

# Sign/Verify
sodix sign "message"
sodix sign -f document.txt
sodix check "message" <signature>
sodix check -f document.txt <signature>

# Encrypt/Decrypt
sodix encrypt "secret"
sodix encrypt -f secret.txt   # Creates secret.txt.x
sodix decrypt <ciphertext>
sodix decrypt -f secret.txt.x
```

## Features

- Ed25519 signing/verification
- Curve25519 encryption (XSalsa20-Poly1305)
- Embedded nonces in encrypted output
- Shell-friendly outputs
- PyNaCl/libsodium compatibility

## Key Files

- `sign_public.key`: Ed25519 public key
- `sign_secret.key`: Ed25519 secret key
- `enc_public.key`: Curve25519 public key
- `enc_secret.key`: Curve25519 secret key

## Python Integration

```python
from nacl.signing import VerifyKey
from nacl.public import PublicKey, PrivateKey
import binascii

# Load Sodix-generated keys
with open("sign_public.key") as f:
    verify_key = VerifyKey(binascii.unhexlify(f.read().strip()))

with open("enc_public.key") as f:
    public_key = PublicKey(binascii.unhexlify(f.read().strip()))
```

## Scripting Example

```bash
#!/bin/sh
sig=$(sodix sign "Hello") || exit 1
sodix check "Hello" "$sig" || exit 1
enc=$(sodix encrypt "Secret") || exit 1
sodix decrypt "$enc"
```

## Build

```bash
git clone https://github.com/ioustamora/sodix.git
cd sodix && cargo build --release
```

## License

MIT License

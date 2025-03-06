# Sodix

A Rust CLI tool providing libsodium-compatible cryptographic operations. Uses Ed25519 for signing and Curve25519 for encryption, with hex-encoded keys for easy scripting.

## Quick Start

```bash
# Install
cargo install sodix

# Generate and Print Keys
sodix generate     # Creates key files in current directory
sodix generate -k /path/to/keys   # Custom key location
sodix print        # Show all keys (generates if missing)

# Sign/Verify
sodix s "message"          # Short alias for sign
sodix sign -f file.txt     # Sign a file
sodix c "message" <sig>    # Short alias for check
sodix check -f file.txt <sig>

# Encrypt/Decrypt with file-based keys
sodix e "secret"           # Uses local key files
sodix encrypt -f file.txt  # Creates file.txt.x
sodix d <ciphertext>       # Uses local key files
sodix decrypt -f file.txt.x

# Encrypt/Decrypt with hex keys
sodix e -k <receiver_pubkey> -s <sender_seckey> "message"
sodix d -k <sender_pubkey> -s <receiver_seckey> <ciphertext>
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

## Python Integration Example
```python
from nacl.public import PrivateKey, PublicKey
import binascii

# Generate keys
sender_private = PrivateKey.generate()
sender_public = sender_private.public_key
receiver_private = PrivateKey.generate()
receiver_public = receiver_private.public_key

# Convert to hex for sodix
sender_sec = binascii.hexlify(bytes(sender_private)).decode()
sender_pub = binascii.hexlify(bytes(sender_public)).decode()
receiver_pub = binascii.hexlify(bytes(receiver_public)).decode()
receiver_sec = binascii.hexlify(bytes(receiver_private)).decode()

# Encrypt: sender -> receiver
# $ sodix e -k <receiver_pub> -s <sender_sec> "secret"

# Decrypt: receiver gets message from sender
# $ sodix d -k <sender_pub> -s <receiver_sec> <ciphertext>
```

## Shell Script Example

```bash
#!/bin/sh
# Generate keys if needed
keys=$(sodix print) || exit 1

# Get public key (first line)
pubkey=$(echo "$keys" | head -n1)

# Encrypt and decrypt
msg="Hello World"
enc=$(sodix e -k "$pubkey" "$msg") || exit 1
dec=$(sodix d "$enc") || exit 1
echo "Decrypted: $dec"
```

## Build

```bash
git clone https://github.com/ioustamora/sodix.git
cd sodix && cargo build --release
```

## License

MIT License

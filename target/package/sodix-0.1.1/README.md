# Sodix

A Rust CLI tool providing libsodium-compatible cryptographic operations. Uses Ed25519 for signing and Curve25519 for encryption, with hex-encoded keys for easy scripting.

## Quick Start

```bash
# Install
cargo install sodix

# Generate and Print Keys
sodix g                    # Generate keys in current directory
sodix generate -k /path    # Generate keys in specific path
sodix p                    # Print all keys (generates if missing)
sodix print -k /path      # Print keys from specific path

# Sign/Verify
sodix s "message"                     # Sign with default key file
sodix sign -k <hex_secret_key> "msg"  # Sign with hex key
sodix sign -f document.txt            # Sign file
sodix c "message" <signature>         # Check with default key
sodix check -k <hex_public_key> "message" <signature>

# Encrypt/Decrypt with file-based keys
sodix e "message"          # Use default keys
sodix encrypt -f file.txt  # Creates file.txt.x
sodix d <ciphertext>       # Use default keys
sodix decrypt -f file.txt  # Decrypts file.txt.x

# Encrypt/Decrypt with hex keys
sodix e -k <receiver_pub> -s <sender_sec> "message"
sodix d -k <sender_pub> -s <receiver_sec> <ciphertext>
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
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey
import binascii

# Signing Example
signing_key = SigningKey.generate()
signing_hex = binascii.hexlify(bytes(signing_key)).decode()

# Sign with sodix using hex key
# $ sodix sign -k <signing_hex> "message"

# Encryption Example
private = PrivateKey.generate()
public = private.public_key

# Get hex format keys
priv_hex = binascii.hexlify(bytes(private)).decode()
pub_hex = binascii.hexlify(bytes(public)).decode()

# Encrypt: sender -> receiver
# $ sodix e -k <pub_hex> -s <priv_hex> "secret"
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
# Get default keys
keys=$(sodix p) || exit 1

# Extract keys (one per line)
sign_pub=$(echo "$keys" | sed -n '1p')
sign_sec=$(echo "$keys" | sed -n '2p')
enc_pub=$(echo "$keys" | sed -n '3p')
enc_sec=$(echo "$keys" | sed -n '4p')

# Use keys
sig=$(sodix s -k "$sign_sec" "Hello") || exit 1
sodix c -k "$sign_pub" "Hello" "$sig" || exit 1

enc=$(sodix e -k "$enc_pub" -s "$enc_sec" "Secret") || exit 1
dec=$(sodix d -k "$enc_pub" -s "$enc_sec" "$enc")
echo "$dec"
```

## Build

```bash
git clone https://github.com/ioustamora/sodix.git
cd sodix && cargo build --release
```

## License

MIT License

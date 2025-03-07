#!/bin/bash

# Exit on any error and enable debug output
set -e
set -x

# Check if sodix is installed
if ! command -v sodix &> /dev/null; then
    echo "Error: sodix is not installed. Please install it first:"
    echo "cargo install sodix"
    exit 1
fi

# Clean up previous test
rm -rf alice_keys bob_keys
mkdir -p alice_keys bob_keys

# Generate keys for both parties
echo "Generating Alice's keys..."
sodix g -k alice_keys/

echo "Generating Bob's keys..."
sodix g -k bob_keys/

# Add a small delay to ensure files are written
sleep 1

# Get public keys and secret keys
ALICE_PUBLIC=$(cat alice_keys/enc_public.key)
ALICE_SECRET=$(cat alice_keys/enc_secret.key)
BOB_PUBLIC=$(cat bob_keys/enc_public.key)
BOB_SECRET=$(cat bob_keys/enc_secret.key)

echo -e "\nAlice's public key: $ALICE_PUBLIC"
echo "Bob's public key: $BOB_PUBLIC"

# Test message
MESSAGE="Hello, Bob!"
echo -e "\nOriginal message: $MESSAGE"

# Alice encrypts for Bob (using Bob's public key and Alice's secret key)
echo "Alice encrypting message for Bob..."
ENCRYPTED=$(sodix e "$MESSAGE" \
    --pubkey "$BOB_PUBLIC" \
    --seckey "$ALICE_SECRET")
echo "Encrypted: $ENCRYPTED"

# Bob decrypts message from Alice (using Alice's public key and Bob's secret key)
echo -e "\nBob decrypting message from Alice..."
DECRYPTED=$(sodix d "$ENCRYPTED" \
    --pubkey "$ALICE_PUBLIC" \
    --seckey "$BOB_SECRET")
echo "Decrypted: $DECRYPTED"

# Verify
if [ "$MESSAGE" = "$DECRYPTED" ]; then
    echo -e "\nSuccess: Message encrypted and decrypted correctly"
else
    echo -e "\nError: Decrypted message doesn't match original"
    exit 1
fi
# Two-Party TSS Implementation

**Status: Work in Progress**

*Note: Stability and correctness are not guaranteed. This project has no affiliation with the Handcash crypto system.*

## Overview

This library implements a 2-of-2 threshold signature scheme (TSS) for arbitrary data using ECDSA and Paillier keys. The signing process is divided into three main steps:

1. **Signer 1**: Creates a signing group that includes:
   - Random Point
   - ECDSA Public Key
   - Encrypted ECDSA Private Key
   - Paillier Public Key
   - Message to be signed

2. **Signer 2**: Uses their ECDSA Private Key to create a partial signature using the request group and returns the shared public key.

3. **Signer 1**: Completes the signature using their private key.

## Implementation Details

The implementation follows the approach described in the article: [ECDSA is not that bad: Two-party signing without Schnorr or BLS](https://medium.com/cryptoadvance/ecdsa-is-not-that-bad-two-party-signing-without-schnorr-or-bls-1941806ec36f)

## Usage

*[Add usage instructions and code examples here]*

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


## Disclaimer

This is an experimental implementation and should not be used in production environments without thorough testing and security audits.
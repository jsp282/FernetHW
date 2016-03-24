# Fernet2 Spec

This document describes version 0x81 of the fernet format.

Conceptually, fernet takes a user-provided *message* (an arbitrary
sequence of bytes), a *key* (256 bits), derives two subkeys and 
produces a *token*, which contains the message in a form that can't be read or 
altered without orignal password.

To facilitate convenient interoperability, this spec defines the
external format of both tokens and keys.

In the previous version of the fernet format, there existed a vulnerability
in which the signing and encryption keys were derived from the same block. 
This new version of fernet removes that vulnerability by generating the keys separately. 

All encryption in this version is done with AES 128 in CBC mode.

All base 64 encoding is done with the "URL and Filename Safe"
variant, defined in [RFC 4648](http://tools.ietf.org/html/rfc4648#section-5) as "base64url".

## Key Format

A fernet *key* is the base64url encoding of the following
fields:

    h = HMAC(key, hashes.SHA256(), backend=backend)
    h.update(b"\x00")
    self._signing_key = h.finalize()[:16]

    h = HMAC(key, hashes.SHA256(), backend=backend)
    h.update(b"\x01")
    self._encryption_key = h.finalize()[:16]

- *Signing-key*, 128 bits
- *Encryption-key*, 128 bits

## Token Format

A fernet *token* is the base64url encoding of the
concatenation of the following fields:

    Version ‖ IV ‖ Ciphertext ‖ Tag

- *Version*, 8 bits
- *IV*, 128 bits
- *Ciphertext*, variable length, multiple of 128 bits
- *HMAC*, 256 bits

Fernet tokens are not self-delimiting. It is assumed that the
transport will provide a means of finding the length of each
complete fernet token.

## Token Fields

### Version

This field denotes which version of the format is being used by
the token. The most recent version is denoted 0x81 and is backward compatible.
The previous (and first) version is denoted 0x80. The Fernet checks which version 
is being used to choose the appropriate decryption method.


### IV

The 128-bit Initialization Vector used in AES encryption and
decryption of the Ciphertext.

When generating new fernet tokens, the IV must be chosen uniquely
for every token. With a high-quality source of entropy, random
selection will do this with high probability.

### Ciphertext

This field has variable size, but is always a multiple of 128
bits, the AES block size. It contains the original input message,
padded and encrypted.

### HMAC

This field is the 256-bit SHA256 HMAC, under signing-key, of the
concatenation of the following fields:

    Version ‖ IV ‖ Ciphertext ‖ Associated Data

Note that the HMAC input is the entire rest of the token verbatim,
and that this input is *not* base64url encoded.

The associated data is an arbitrary length byte string that is 
is part of the authentication scope, yet not encrypted.

## Generating

Given a key and message, generate a fernet token with the
following steps, in order:

1. Derive two random subkeys (signing and encryption) from original key
2. Choose a unique IV.
3. Construct the ciphertext:
   1. Pad the message to a multiple of 16 bytes (128 bits) per [RFC
   5652, section 6.3](http://tools.ietf.org/html/rfc5652#section-6.3).
   This is the same padding technique used in [PKCS #7
   v1.5](http://tools.ietf.org/html/rfc2315#section-10.3) and all
   versions of SSL/TLS (cf. [RFC 5246, section
   6.2.3.2](http://tools.ietf.org/html/rfc5246#section-6.2.3.2) for
   TLS 1.2).
   2. Encrypt the padded message using AES 128 in CBC mode with
   the chosen IV and user-supplied encryption-key.
4. Compute the HMAC field as described above using the
derived signing-key.
5. Concatenate all fields together in the format above.
6. base64url encode the entire token.

## Verifying

Given a key and token, to verify that the token is valid and
recover the original message, perform the following steps, in
order:

1. base64url decode the token.
2. Check first byte of the token. If the token is 0x80 (old version), continue to step 3, else if it is 0x81 (new version) go to step 4.
3. If the user has specified a maximum age (or "time-to-live") for
the token, ensure the recorded timestamp is not too far in the
past.
4. Recompute the HMAC from the other fields and the derived
signing-key.
5. Ensure the recomputed HMAC matches the HMAC field stored in the
token, using a constant-time comparison function.
6. Decrypt the ciphertext field using AES 128 in CBC mode with the
recorded IV and user-supplied encryption-key.
8. Unpad the decrypted plaintext, yielding the original message.



# PwFernet Spec

This document describes version 0x82 of the fernet format.

Conceptually, fernet takes a user-provided *message* (an arbitrary
sequence of bytes), a *password* (arbitrary length), derives two subkeys and produces a *token*, which contains the message in a form that can't be read or altered without orignal password.

To facilitate convenient interoperability, this spec defines the
external format of both tokens and keys.

All encryption in this version is done with AES 128 in CBC mode.

All base 64 encoding is done with the "URL and Filename Safe"
variant, defined in [RFC 4648](http://tools.ietf.org/html/rfc4648#section-5) as "base64url".

## Key Format

A fernet *password* is used to generate 2 subkeys by utilizing [PBKDF2HMAC](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/?highlight=pbkdf2hmac#cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC) key derivation function:
  
  kdf = PBKDF2HMAC(
    algorithm = hashes.SHA256(),
    length = 32,
    salt = salt,
    iterations = 100000,
    backend = self._backend
  )

- *Signing-key*, 128 bits
- *Encryption-key*, 128 bits
- *Salt*, 128 bits

## Token Format

A fernet *token* is the base64url encoding of the
concatenation of the following fields:

    Version ‖ IV ‖ Ciphertext ‖ HMAC

- *Version*, 8 bits
- *Salt*, 128 bits
- *Ciphertext*, variable length, multiple of 128 bits
- *HMAC*, 256 bits

Fernet tokens are not self-delimiting. It is assumed that the
transport will provide a means of finding the length of each
complete fernet token.

## Token Fields

### Version

This field denotes which version of the format is being used by
the token. The version has a value of 128 bits (0x82).

### Salt

The 128-bit salt used in AES encryption and
decryption of the Ciphertext.

When generating new fernet tokens, the salt must be chosen uniquely
for every token. With a high-quality source of entropy, random
selection will do this with high probability.

### Ciphertext

This field has variable size, but is always a multiple of 128
bits, the AES block size. It contains the original input message,
padded and encrypted.

### HMAC

This field is the 256-bit SHA256 HMAC, under signing-key, of the
concatenation of the following fields:

    Version ‖ Salt ‖ Ciphertext ‖ Associated Data

Note that the HMAC input is the entire rest of the token verbatim,
and that this input is *not* base64url encoded.

The associated data is an arbitrary length byte string that is 
is part of the authentication scope, yet not encrypted.

## Generating

Given a password and message, generate a fernet token with the
following steps, in order:

1. Choose a unique salt.
2. Generate two subkeys for signing and encryption
3. Construct the ciphertext:
   1. Pad the message to a multiple of 16 bytes (128 bits) per [RFC
   5652, section 6.3](http://tools.ietf.org/html/rfc5652#section-6.3).
   This is the same padding technique used in [PKCS #7
   v1.5](http://tools.ietf.org/html/rfc2315#section-10.3) and all
   versions of SSL/TLS (cf. [RFC 5246, section
   6.2.3.2](http://tools.ietf.org/html/rfc5246#section-6.2.3.2) for
   TLS 1.2).
   2. Encrypt the padded message using AES 128 in CBC mode with
   the chosen IV and user-supplied encryption-key.
4. Compute the HMAC field as described above using the
derived signing-key.
5. Concatenate all fields together in the format above.
6. base64url encode the entire token.

## Verifying

Given a key and token, to verify that the token is valid and
recover the original message, perform the following steps, in
order:

1. base64url decode the token.
2. Ensure the first byte of the token is 0x82.
3. Extract the salt from token and derive two subkeys from password
4. Recompute the HMAC from the other fields and the derived
signing-key.
5. Ensure the recomputed HMAC matches the HMAC field stored in the
token, using a constant-time comparison function.
6. Decrypt the ciphertext field using AES 128 in CBC mode with the
recorded IV and derived encryption-key.
7. Unpad the decrypted plaintext, yielding the original message. 





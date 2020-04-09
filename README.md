AES-GCM-SIV Authenticated Encryption with Associated Data
---------------------------------------------------------

AES-GCM-SIV AEAD implementation.

Nonce Misuse-Resistant Authenticated Encryption.

From RFC8452:

    Some AEADs, including AES-GCM, suffer catastrophic failures 
    of confidentiality and/or integrity when two distinct messages are
    encrypted with the same key and nonce.
       
    Nonce misuse-resistant AEADs do not suffer from this problem.  For
    this class of AEADs, encrypting two messages with the same nonce only
    discloses whether the messages were equal or not.

See [RFC8452](https://tools.ietf.org/html/rfc8452) for more details.

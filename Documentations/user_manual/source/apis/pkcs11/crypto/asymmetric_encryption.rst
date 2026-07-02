Asymmetric Encryption/Decryption
""""""""""""""""""""""""""""""""

PKCS#11 provides the same set of functions for asymmetric encryption and
decryption as for symmetric operations. Refer to the
:ref:`Symmetric Encryption<p11_symmetric_encryption>` section for the detailed
description of the operation sequences.

However, asymmetric encryption and decryption operations differ in the key types
used. Asymmetric encryption requires a public key for encryption and a private
key for decryption.

The operation initialization must be setup to use the asymmetric encryption
mechanisms as listed in the
:ref:`Symmetric Encryption Mechanisms<p11_asym_enc_mechanims>`.

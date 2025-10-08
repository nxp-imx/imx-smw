Cryptography APIs
^^^^^^^^^^^^^^^^^

The Cryptography APIs allow user of the library to perform cryptographic
operations such as hashing, signing, encryption, decryption, MAC and RNG.
For some cryptographic operations, both oneshot and multipart modes are
supported.

Random number generation (RNG)
""""""""""""""""""""""""""""""

.. kernel-doc:: /public/smw/crypto/rng.h
   :functions: smw_rng

.. kdoc-extension:: /public/smw/crypto/rng.h
   :structs:

Operation context
"""""""""""""""""

.. kernel-doc:: /public/smw/crypto/op_context.h
   :functions: smw_allocate_context smw_cancel_operation smw_copy_context

.. kdoc-extension:: /public/smw/crypto/op_context.h
   :structs:

Message digests (Hashes)
""""""""""""""""""""""""

.. kernel-doc:: /public/smw/crypto/hash.h
   :functions: smw_hash

.. kernel-doc:: /public/smw/crypto/hash.h
   :functions: smw_hash_init smw_hash_update smw_hash_final

.. kdoc-extension:: /public/smw/crypto/hash.h
   :structs:


Message authentication code (MAC)
"""""""""""""""""""""""""""""""""

.. kernel-doc:: /public/smw/crypto/mac.h
   :functions: smw_mac smw_mac_verify

.. kdoc-extension:: /public/smw/crypto/mac.h
   :structs:

Asymmetric signature
""""""""""""""""""""

.. kernel-doc:: /public/smw/crypto/sign.h
   :functions: smw_sign smw_verify

.. kernel-doc:: /public/smw/crypto/sign.h
   :functions: smw_sign_init smw_sign_update smw_sign_final smw_verify_init
               smw_verify_update smw_verify_final

.. kdoc-extension:: /public/smw/crypto/sign.h
   :structs:

.. kdoc-extension:: /public/smw/crypto/sign.h
   :macros:


Authentication Encryption/Decryption with associated data (AEAD)
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. kernel-doc:: /public/smw/crypto/aead.h
   :functions: smw_aead

.. kernel-doc:: /public/smw/crypto/aead.h
   :functions: smw_aead_init smw_aead_update smw_aead_update_aad smw_aead_final

.. kdoc-extension:: /public/smw/crypto/aead.h
   :structs:


Asymmetric Encryption/Decryption
""""""""""""""""""""""""""""""""

.. kernel-doc:: /public/smw/crypto/asymmetric_encryption.h
   :functions: smw_asymmetric_encrypt smw_asymmetric_decrypt

.. kdoc-extension:: /public/smw/crypto/asymmetric_encryption.h
   :structs:


Symmetric Encryption (Cipher)
"""""""""""""""""""""""""""""

.. kernel-doc:: /public/smw/crypto/cipher.h
   :functions: smw_cipher

.. kernel-doc:: /public/smw/crypto/cipher.h
   :functions: smw_cipher_init smw_cipher_update smw_cipher_final

.. kdoc-extension:: /public/smw/crypto/cipher.h
   :structs:

Mechanisms
^^^^^^^^^^

The PKCS#11 API uses mechanisms to specify cryptographic operations. A
mechanism defines the algorithm and parameters for operations such as
encryption, decryption, signing, verification, key generation, and key
derivation.

The following sections describe the mechanisms supported by SMW's PKCS#11.

Symmetric Key Generation Mechanisms
"""""""""""""""""""""""""""""""""""
.. list-table:: Symmetric Key Generation Mechanisms
   :header-rows: 1
   :name: p11_symmetric_keygen_mechanisms
   :class: wrap-table

   * - **Mechanism**
     - **Description**
   * - CKM_AES_KEY_GEN
     - Generate AES keys (128, 192, or 256 bits).
   * - CKM_DES_KEY_GEN
     - Generate single DES keys.
   * - CKM_DES3_KEY_GEN
     - Generate triple-length DES keys.
   * - CKM_SM4_KEY_GEN
     - Generate SM4 keys (NXP vendor define).
   * - CKM_GENERIC_SECRET_KEY_GEN
     - Generate generic secret keys.

Asymmetric Key Generation Mechanisms
""""""""""""""""""""""""""""""""""""
.. list-table:: Asymmetric Key Generation Mechanisms
   :header-rows: 1
   :name: p11_asymmetric_keygen_mechanisms
   :class: wrap-table

   * - **Mechanism**
     - **Description**
   * - CKM_RSA_PKCS_KEY_PAIR_GEN
     - Generate RSA key pairs.
   * - CKM_EC_KEY_PAIR_GEN
     - Generate EC key pairs.
   * - CKM_EC_EDWARDS_KEY_PAIR_GEN
     - Generate Edwards curve key pairs.
   * - CKM_EC_MONTGOMERY_KEY_PAIR_GEN
     - Generate Montgomery curve key pairs.
   * - CKM_RSA_X9_31_KEY_PAIR_GEN
     - Generate RSA key pairs.

Key Derivation Mechanisms
"""""""""""""""""""""""""
.. list-table:: Key Derivation Mechanisms
   :header-rows: 1
   :name: p11_key_derivation_mechanisms
   :class: wrap-table

   * - **Mechanism**
     - **Description**
   * - CKM_ECDH1_DERIVE
     - ECDH key derivation (Elliptic Curve Diffie-Hellman)
   * - CKM_HKDF_DERIVE
     - HMAC-based Key Derivation Function
   * - CKM_TLS12_MASTER_KEY_DERIVE
     - TLS 1.2 master secret derivation
   * - CKM_TLS12_KEY_AND_MAC_DERIVE
     - TLS 1.2 key and MAC derivation
   * - CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE
     - TLS 1.2 extended master secret derivation (:rfc:`7627`)
   * - CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH
     - TLS 1.2 extended master secret derivation using Diffie-Hellman (:rfc:`7627`)

ECDH Parameters
~~~~~~~~~~~~~~~
For ECDH key derivation (``CKM_ECDH1_DERIVE``):

.. code-block:: c

   typedef struct CK_ECDH1_DERIVE_PARAMS {
       CK_EC_KDF_TYPE kdf;            /* Key derivation function */
       CK_ULONG ulSharedDataLen;      /* Length of shared data in bytes */
       CK_BYTE_PTR pSharedData;       /* Shared data (e.g. additional input) */
       CK_ULONG ulPublicDataLen;      /* Length of public key data in bytes */
       CK_BYTE_PTR pPublicData;       /* Public key of other party */
   } CK_ECDH1_DERIVE_PARAMS;

HKDF Parameters
~~~~~~~~~~~~~~~
For HMAC-based Key Derivation (``CKM_HKDF_DERIVE``):

.. code-block:: c

   typedef struct CK_HKDF_PARAMS {
       CK_BBOOL bExtract;                  /* Perform extraction step */
       CK_BBOOL bExpand;                   /* Perform expansion step */
       CK_MECHANISM_TYPE prfHashMechanism; /* PRF hash mechanism */
       CK_ULONG ulSaltType;                /* Salt type */
       CK_BYTE_PTR pSalt;                  /* Salt data (if ulSaltType is CKF_HKDF_SALT_DATA) */
       CK_ULONG ulSaltLen;                 /* Length of salt in bytes */
       CK_OBJECT_HANDLE hSaltKey;          /* Salt key handle (if ulSaltType is CKF_HKDF_SALT_KEY) */
       CK_BYTE_PTR pInfo;                  /* Context and application specific information */
       CK_ULONG ulInfoLen;                 /* Length of info in bytes */
   } CK_HKDF_PARAMS;

Where `ulSaltType` can be\:

  - ``CKF_HKDF_SALT_NULL``: no salt supplied.
  - ``CKF_HKDF_SALT_DATA``: salt supplied as data in pSalt with length ulSaltLen.
  - ``CKF_HKDF_SALT_KEY``: salt supplied as key in the hSaltKey.

TLS 1.2 Master Key Derive Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For TLS 1.2 master secret derivation (``CKM_TLS12_MASTER_KEY_DERIVE``):

.. code-block:: c

   typedef struct CK_SSL3_RANDOM_DATA {
       CK_BYTE_PTR pClientRandom;     /* Client random data */
       CK_ULONG ulClientRandomLen;    /* Length of client random data in bytes */
       CK_BYTE_PTR pServerRandom;     /* Server random data */
       CK_ULONG ulServerRandomLen;    /* Length of server random data in bytes */
   } CK_SSL3_RANDOM_DATA;

   typedef struct CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
       CK_SSL3_RANDOM_DATA RandomInfo;     /* Client and server random data */
       CK_VERSION_PTR pVersion;            /* TLS protocol version (output) */
       CK_MECHANISM_TYPE prfHashMechanism; /* PRF hash mechanism (e.g. CKM_SHA256) */
   } CK_TLS12_MASTER_KEY_DERIVE_PARAMS;

TLS 1.2 Key and MAC Derive Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For TLS 1.2 key and MAC derivation (``CKM_TLS12_KEY_AND_MAC_DERIVE``):

.. code-block:: c

   typedef struct CK_SSL3_KEY_MAT_OUT {
       CK_OBJECT_HANDLE hClientMacSecret;  /* Client MAC secret key handle */
       CK_OBJECT_HANDLE hServerMacSecret;  /* Server MAC secret key handle */
       CK_OBJECT_HANDLE hClientKey;        /* Client encryption key handle */
       CK_OBJECT_HANDLE hServerKey;        /* Server encryption key handle */
       CK_BYTE_PTR pIVClient;              /* Client IV */
       CK_BYTE_PTR pIVServer;              /* Server IV */
   } CK_SSL3_KEY_MAT_OUT;

   typedef struct CK_TLS12_KEY_MAT_PARAMS {
       CK_ULONG ulMacSizeInBits;                     /* Length of MAC key in bits */
       CK_ULONG ulKeySizeInBits;                     /* Length of encryption key in bits */
       CK_ULONG ulIVSizeInBits;                      /* Length of IV in bits */
       CK_BBOOL bIsExport;                           /* Must be FALSE (export not supported) */
       CK_SSL3_RANDOM_DATA RandomInfo;               /* Client and server random data */
       CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial; /* Output key material */
       CK_MECHANISM_TYPE prfHashMechanism;           /* PRF hash mechanism (e.g. CKM_SHA256) */
   } CK_TLS12_KEY_MAT_PARAMS;

TLS 1.2 Extended Master Key Derive Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For TLS 1.2 extended master secret derivation
(``CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE`` and
``CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH``) as defined in :rfc:`7627`:

.. code-block:: c

   typedef struct CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS {
       CK_MECHANISM_TYPE prfHashMechanism; /* PRF hash mechanism (e.g. CKM_SHA256) */
       CK_BYTE_PTR pSessionHash;           /* Session hash as defined in RFC 7627 */
       CK_ULONG ulSessionHashLen;          /* Length of session hash in bytes */
       CK_VERSION_PTR pVersion;            /* TLS protocol version (output) */
   } CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS;

Symmetric Encryption Mechanisms
"""""""""""""""""""""""""""""""
.. list-table:: Symmetric Encryption Mechanisms
   :header-rows: 1
   :name: p11_symmetric_encryption_mechanisms
   :class: wrap-table

   * - **Mechanism**
     - **Description**
   * - CKM_AES_ECB
     - AES in Electronic Codebook mode
   * - CKM_AES_CBC
     - AES in Cipher Block Chaining mode
   * - CKM_AES_CTR
     - AES in Counter mode
   * - CKM_AES_CTS
     - AES in Cipher Text Stealing mode
   * - CKM_AES_XTS
     - AES in XEX-based Tweaked CodeBook mode with ciphertext stealing
   * - CKM_DES_ECB
     - DES in Electronic Codebook mode
   * - CKM_DES_CBC
     - DES in Cipher Block Chaining mode
   * - CKM_DES_CBC_PAD
     - DES in CBC mode with PKCS#7 padding
   * - CKM_DES3_ECB
     - Triple DES in Electronic Codebook mode
   * - CKM_DES3_CBC
     - Triple DES in Cipher Block Chaining mode
   * - CKM_SM4_ECB
     - SM4 in Electronic Codebook mode
   * - CKM_SM4_CBC
     - SM4 in Cipher Block Chaining mode
   * - CKM_SM4_CTR
     - SM4 in Counter mode
   * - CKM_AES_CFB128
     - Cipher Feedback mode
   * - CKM_AES_OFB
     - Output Feedback mode


AES-CTR Parameters
~~~~~~~~~~~~~~~~~~
For AES-CTR mode:

.. code-block:: c

   typedef struct CK_AES_CTR_PARAMS {
       CK_ULONG ulCounterBits;    /* Number of bits in counter block */
       CK_BYTE cb[16];            /* Counter block */
   } CK_AES_CTR_PARAMS;


.. _p11_asym_enc_mechanims:

Asymmetric Encryption
"""""""""""""""""""""
.. list-table:: Asymmetric Encryption Mechanisms
   :header-rows: 1
   :name: p11_asymmetric_encryption_mechanisms
   :class: wrap-table

   * - **Mechanism**
     - **Description**
   * - CKM_RSA_PKCS
     - RSA PKCS#1 v1.5 encryption
   * - CKM_RSA_PKCS_OAEP
     - RSA PKCS#1 OAEP encryption
   * - CKM_RSA_X_509
     - Raw RSA encryption (no padding)

RSA-OAEP Parameters
~~~~~~~~~~~~~~~~~~~
For RSA OAEP encryption:

.. code-block:: c

   typedef struct CK_RSA_PKCS_OAEP_PARAMS {
       CK_MECHANISM_TYPE hashAlg;            /* Hash algorithm */
       CK_RSA_PKCS_MGF_TYPE mgf;             /* Mask generation function */
       CK_RSA_PKCS_OAEP_SOURCE_TYPE source;  /* Source of encoding parameter */
       CK_VOID_PTR pSourceData;              /* Encoding parameter */
       CK_ULONG ulSourceDataLen;             /* Length of encoding parameter */
   } CK_RSA_PKCS_OAEP_PARAMS;


.. _p11_aead_mechanims:

Authentication Encryption Mechanisms (AEAD)
"""""""""""""""""""""""""""""""""""""""""""
.. list-table:: Authentication Encryption Mechanisms
   :header-rows: 1
   :name: p11_authenticated_encryption_mechanisms
   :class: wrap-table

   * - **Mechanism**
     - **Description**
   * - CKM_AES_GCM
     - AES in Galois/Counter Mode
   * - CKM_AES_CCM
     - AES in Counter with CBC-MAC mode
   * - CKM_CHACHA20_POLY1305
     - ChaCha20-Poly1305 AEAD encryption

AES-GCM Parameters
~~~~~~~~~~~~~~~~~~
For AES-GCM authenticated encryption non-message encrypt and decrypt
(``CKM_AES_GCM``):

.. code-block:: c

   typedef struct CK_GCM_PARAMS {
       CK_BYTE_PTR pIv;           /* Initialization vector */
       CK_ULONG ulIvLen;          /* Length of IV in bytes */
       CK_ULONG ulIvBits;         /* Length of IV in bits (if not byte-aligned) */
       CK_BYTE_PTR pAAD;          /* Additional authenticated data */
       CK_ULONG ulAADLen;         /* Length of AAD in bytes */
       CK_ULONG ulTagBits;        /* Length of authentication tag in bits */
   } CK_GCM_PARAMS;

AES-CCM Parameters
~~~~~~~~~~~~~~~~~~
For AES-CCM authenticated encryption non-message encrypt and decrypt
(``CKM_AES_CCM``):

.. code-block:: c

   typedef struct CK_CCM_PARAMS {
       CK_ULONG ulDataLen;        /* Length of data to be encrypted */
       CK_BYTE_PTR pNonce;        /* Nonce */
       CK_ULONG ulNonceLen;       /* Length of nonce in bytes */
       CK_BYTE_PTR pAAD;          /* Additional authenticated data */
       CK_ULONG ulAADLen;         /* Length of AAD in bytes */
       CK_ULONG ulMACLen;         /* Length of MAC in bytes */
   } CK_CCM_PARAMS;

AES-GCM Message Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~
For message-based AES-GCM authenticated encryption (``C_EncryptMessage``,
``C_DecryptMessage``, ``C_EncryptMessageBegin``, ``C_DecryptMessageBegin``,
``C_EncryptMessageNext``, ``C_DecryptMessageNext``):

.. code-block:: c

   typedef struct CK_GCM_MESSAGE_PARAMS {
       CK_BYTE_PTR           pIv;             /* Initialization vector */
       CK_ULONG              ulIvLen;         /* Length of IV in bytes */
       CK_ULONG              ulIvFixedBits;   /* Number of fixed bits in the IV */
       CK_GENERATOR_FUNCTION ivGenerator;     /* IV generator function */
       CK_BYTE_PTR           pTag;            /* Authentication tag (output on encrypt, input on decrypt) */
       CK_ULONG              ulTagBits;       /* Length of authentication tag in bits */
   } CK_GCM_MESSAGE_PARAMS;

Where `ivGenerator` can be:

  - ``CKG_NO_GENERATE``: the caller supplies the full IV in ``pIv``.
  - ``CKG_GENERATE``: the library generates the entire IV.
  - ``CKG_GENERATE_COUNTER``: the library generates the counter portion;
    ``ulIvFixedBits`` specifies how many high-order bits the caller provides in
    ``pIv``.
  - ``CKG_GENERATE_RANDOM``: the library generates a random IV.

AES-CCM Message Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~
For message-based AES-CCM authenticated encryption (``C_EncryptMessage``,
``C_DecryptMessage``, ``C_EncryptMessageBegin``, ``C_DecryptMessageBegin``,
``C_EncryptMessageNext``, ``C_DecryptMessageNext``):

.. code-block:: c

   typedef struct CK_CCM_MESSAGE_PARAMS {
       CK_ULONG              ulDataLen;         /* Length of plaintext/ciphertext data in bytes */
       CK_BYTE_PTR           pNonce;            /* Nonce */
       CK_ULONG              ulNonceLen;        /* Length of nonce in bytes */
       CK_ULONG              ulNonceFixedBits;  /* Number of fixed bits in the nonce */
       CK_GENERATOR_FUNCTION nonceGenerator;    /* Nonce generator function */
       CK_BYTE_PTR           pMAC;              /* Authentication MAC (output on encrypt, input on decrypt) */
       CK_ULONG              ulMACLen;          /* Length of MAC in bytes */
   } CK_CCM_MESSAGE_PARAMS;

Where `nonceGenerator` accepts the same values as ``ivGenerator`` in
``CK_GCM_MESSAGE_PARAMS`` (``CKG_NO_GENERATE``, ``CKG_GENERATE``,
``CKG_GENERATE_COUNTER``, ``CKG_GENERATE_RANDOM``).

ChaCha20-Poly1305 Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For single-part ChaCha20-Poly1305 authenticated encryption
(``CKM_CHACHA20_POLY1305``):

.. code-block:: c

   typedef struct CK_SALSA20_CHACHA20_POLY1305_PARAMS {
       CK_BYTE_PTR pNonce;     /* Nonce/IV */
       CK_ULONG    ulNonceLen; /* Length of nonce in bytes (8 or 12) */
       CK_BYTE_PTR pAAD;       /* Additional authenticated data */
       CK_ULONG    ulAADLen;   /* Length of AAD in bytes */
   } CK_SALSA20_CHACHA20_POLY1305_PARAMS;

ChaCha20-Poly1305 Message Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For message-based ChaCha20-Poly1305 authenticated encryption
(``C_EncryptMessage``, ``C_DecryptMessage``, ``C_EncryptMessageBegin``,
``C_DecryptMessageBegin``, ``C_EncryptMessageNext``, ``C_DecryptMessageNext``):

.. code-block:: c

   typedef struct CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
       CK_BYTE_PTR           pNonce;         /* Nonce/IV */
       CK_ULONG              ulNonceLen;     /* Length of nonce in bytes (8 or 12) */
       CK_GENERATOR_FUNCTION nonceGenerator; /* Nonce generator function */
       CK_BYTE_PTR           pTag;           /* Authentication tag (output on encrypt, input on decrypt) */
       CK_ULONG              ulTagBits;      /* Length of authentication tag in bits (must be 128) */
   } CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS;

Asymmetric Signature Mechanisms
"""""""""""""""""""""""""""""""
.. list-table:: Asymmetric Signature Mechanisms
   :header-rows: 1
   :name: p11_asymmetric_signature_mechanisms
   :class: wrap-table

   * - **Mechanism**
     - **Description**
   * - CKM_RSA_PKCS_PSS
     - RSA PSS signature of message already hashed. Limited to single part
   * - CKM_SHA1_RSA_PKCS_PSS
     - RSA PSS signature hashing message with SHA-1
   * - CKM_SHA224_RSA_PKCS_PSS
     - RSA PSS signature hashing message with SHA-224
   * - CKM_SHA256_RSA_PKCS_PSS
     - RSA PSS signature hashing message with SHA-256
   * - CKM_SHA384_RSA_PKCS_PSS
     - RSA PSS signature hashing message with SHA-384
   * - CKM_SHA512_RSA_PKCS_PSS
     - RSA PSS signature hashing message with SHA-512
   * - CKM_MD5_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with MD5
   * - CKM_SHA1_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA-1
   * - CKM_SHA224_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA-224
   * - CKM_SHA256_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA-256
   * - CKM_SHA384_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA-384
   * - CKM_SHA512_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA-512
   * - CKM_SHA3_224_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA3-224
   * - CKM_SHA3_256_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA3-256
   * - CKM_SHA3_384_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA3-384
   * - CKM_SHA3_512_RSA_PKCS
     - RSA PKCS#1 v1.5 signature hashing message with SHA3-512
   * - CKM_EDDSA
     - Edwards Curve signature. Supports optional parameters
   * - CKM_ECDSA
     - ECDSA signature of message already hashed. Limited to single part
   * - CKM_ECDSA_SHA1
     - ECDSA signature hashing message with SHA-1
   * - CKM_ECDSA_SHA224
     - ECDSA signature hashing message with SHA-224
   * - CKM_ECDSA_SHA256
     - ECDSA signature hashing message with SHA-256
   * - CKM_ECDSA_SHA384
     - ECDSA signature hashing message with SHA-384
   * - CKM_ECDSA_SHA512
     - ECDSA signature hashing message with SHA-512
   * - CKM_ECDSA_SHA3_224
     - ECDSA signature hashing message with SHA3-224
   * - CKM_ECDSA_SHA3_256
     - ECDSA signature hashing message with SHA3-256
   * - CKM_ECDSA_SHA3_384
     - ECDSA signature hashing message with SHA3-384
   * - CKM_ECDSA_SHA3_512
     - ECDSA signature hashing message with SHA3-512

RSA-PSS Parameters
~~~~~~~~~~~~~~~~~~
For RSA PSS Signature:

.. code-block:: c

   typedef struct CK_RSA_PKCS_PSS_PARAMS {
       CK_MECHANISM_TYPE    hashAlg; /* hash algorithm used in the PSS encoding */
       CK_RSA_PKCS_MGF_TYPE mgf;     /* Mask generation function to use on the encoded block */
       CK_ULONG             sLen;    /* Length, in bytes, of the salt value used in the PSS encoding */
   }

EdDSA Parameters
~~~~~~~~~~~~~~~~
For Edwards Curve signatures with optional context:

.. code-block:: c

   typedef struct CK_EDDSA_PARAMS {
       CK_BYTE_PTR pPhflag;           /* Indicates if Pre-hashed message */
       CK_ULONG ulContextDataLen;     /* Length of context in bytes between 0 and 255 */
       CK_BYTE_PTR pContext;          /* Context data for signature */
   } CK_EdDSA_PARAMS;


.. _p11_mac_mechanims:

Message Authentication Code (MAC)
"""""""""""""""""""""""""""""""""
.. list-table:: Message Authentication Code Mechanisms
  :header-rows: 1
  :name: p11_mac_mechanisms
  :class: wrap-table

  * - **Mechanism**
    - **Description**
  * - CKM_AES_CMAC_GENERAL
    - AES CMAC with variable output length
  * - CKM_DES3_CMAC_GENERAL
    - Triple DES CMAC with variable output length
  * - CKM_MD5_HMAC_GENERAL
    - HMAC with MD5 and variable output length
  * - CKM_SHA_1_HMAC_GENERAL
    - HMAC with SHA-1 and variable output length
  * - CKM_SHA224_HMAC_GENERAL
    - HMAC with SHA-224 and variable output length
  * - CKM_SHA256_HMAC_GENERAL
    - HMAC with SHA-256 and variable output length
  * - CKM_SHA384_HMAC_GENERAL
    - HMAC with SHA-384 and variable output length
  * - CKM_SHA512_HMAC_GENERAL
    - HMAC with SHA-512 and variable output length
  * - CKM_SHA3_224_HMAC_GENERAL
    - HMAC with SHA3-224 and variable output length
  * - CKM_SHA3_256_HMAC_GENERAL
    - HMAC with SHA3-256 and variable output length
  * - CKM_SHA3_384_HMAC_GENERAL
    - HMAC with SHA3-384 and variable output length
  * - CKM_SHA3_512_HMAC_GENERAL
    - HMAC with SHA3-512 and variable output length
  * - CKM_AES_CMAC
    - Full block size AES CMAC
  * - CKM_DES3_CMAC
    - Full block size DES3 CMAC
  * - CKM_MD5_HMAC
    - Full MD5 block HMAC
  * - CKM_SHA_1_HMAC
    - Full SHA-1 block HMAC
  * - CKM_SHA224_HMAC
    - Full SHA-224 block HMAC
  * - CKM_SHA256_HMAC
    - Full SHA-256 block HMAC
  * - CKM_SHA384_HMAC
    - Full SHA-384 block HMAC
  * - CKM_SHA512_HMAC
    - Full SHA-512 block HMAC
  * - CKM_SHA3_224_HMAC
    - Full SHA3-224 block HMAC
  * - CKM_SHA3_256_HMAC
    - Full SHA3-256 block HMAC
  * - CKM_SHA3_384_HMAC
    - Full SHA3-384 block HMAC
  * - CKM_SHA3_512_HMAC
    - Full SHA3-512 block HMAC
  * - CKM_TLS_MAC
    - TLS "finished" message MAC

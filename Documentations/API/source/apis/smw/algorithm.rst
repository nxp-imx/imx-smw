.. _algorithm-smw_attr_algo_t-encoding:

Cryptographic Algorithm (smw_attr_algo_t) encoding
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This chapter intends to detail the algorithm encoding definitions used to
describe cryptographic algorithms and their parameters within the SMW API.

The algorithm encoding is a 64-bit value that encapsulates all necessary
information to define and restrict cryptographic operations.

The same 64-bit encoding is used throughout the SMW API to specify:

  - Cryptographic algorithms (symmetric, asymmetric, hash functions).
  - Algorithm modes and parameters.
  - Permitted key algorithm when requested by the Security Subsystem.


.. kdoc-extension:: /public/smw/attr.h
   :typedefs: smw_attr_algo_t

.. table:: Algorithm encoding bit fields
   :name: table_algorithm_encoding
   :align: center
   :widths: 15 85
   :class: wrap-table

   +-------------+-----------------------------------------------------------------------------+
   | **Bits**    | **Description**                                                             |
   +=============+=============================================================================+
   | **[63:40]** | Reserved                                                                    |
   +-------------+-----------------------------------------------------------------------------+
   | **[39:32]** | Additional Algorithm Parameters :numref:`table_additional_parameters`       |
   +-------------+-----------------------------------------------------------------------------+
   | **[31:24]** | Operation Class :numref:`table_algorithm_operation`                         |
   +-------------+-----------------------------------------------------------------------------+
   | **[23:16]** | Hash :numref:`table_algorithm_hash`                                         |
   +-------------+-----------------------------------------------------------------------------+
   | **[15:8]**  | Define either the algorithm:\                                               |
   |             |                                                                             |
   |             |  - Mode :numref:`table_algorithm_mode`                                      |
   |             |  - Curve :numref:`table_algorithm_curve`                                    |
   |             |  - KDF :numref:`table_algorithm_kdf`                                        |
   |             |                                                                             |
   +-------------+-----------------------------------------------------------------------------+
   | **[7:0]**   | Main Algorithm :numref:`table_main_algorithm`                               |
   +-------------+-----------------------------------------------------------------------------+


Main algorithm
""""""""""""""

.. table:: Main Algorithm value
   :name: table_main_algorithm
   :align: center
   :widths: 8 44 48
   :class: wrap-table

   +-----------+----------------------------+--------------------------------------------------+
   | **Value** | **Define**                 | **Description**                                  |
   +===========+============================+==================================================+
   |  0x0      | SMW_ATTR_ALGO_NONE         | No algorithm defined.                            |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x1      | SMW_ATTR_ALGO_AES          | Advanced Encryption Standard.                    |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x2      | SMW_ATTR_ALGO_DES          | Data Encryption Standard.                        |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x3      | SMW_ATTR_ALGO_DES3         | Triple DES.                                      |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x4      | SMW_ATTR_ALGO_CHACHA20     | ChaCha20-Poly1305.                               |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x5      | SMW_ATTR_ALGO_SM4          | ShāngMì 4.                                       |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x6      | SMW_ATTR_ALGO_RSA          | Rivest–Shamir–Adleman.                           |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x7      | SMW_ATTR_ALGO_SM2          | ShāngMì 2.                                       |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x8      | SMW_ATTR_ALGO_HMAC         | Hash-based message authentication code.          |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x9      | SMW_ATTR_ALGO_DSA          | Digital Signature Algorithm.                     |
   +-----------+----------------------------+--------------------------------------------------+
   |  0xA      | SMW_ATTR_ALGO_ECDSA        | Elliptic Curve Digital Signature Algorithm.      |
   +-----------+----------------------------+--------------------------------------------------+
   |  0xB      | SMW_ATTR_ALGO_EDDSA        | Edwards-curve Digital Signature Algorithm.       |
   +-----------+----------------------------+--------------------------------------------------+
   |  0xC      | SMW_ATTR_ALGO_DH           | Diffie–Hellman.                                  |
   +-----------+----------------------------+--------------------------------------------------+
   |  0xD      | SMW_ATTR_ALGO_ECDH         | Elliptic-curve Diffie–Hellman.                   |
   +-----------+----------------------------+--------------------------------------------------+
   |  0xE      | SMW_ATTR_ALGO_HKDF         | HMAC-based Key Derivation Function.              |
   +-----------+----------------------------+--------------------------------------------------+
   |  0xF      | SMW_ATTR_ALGO_HKDF_EXTRACT | HMAC-based Key Derivation Function Extract step. |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x10     | SMW_ATTR_ALGO_HKDF_EXPAND  | HMAC-based Key Derivation Function Expand step.  |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x11     | SMW_ATTR_ALGO_TLS_1_2      | Transport Layer Security 1.2 Key Derivation.     |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x12     | SMW_ATTR_ALGO_TLS_1_3      | Transport Layer Security 1.3 Key Derivation.     |
   +-----------+----------------------------+--------------------------------------------------+
   |  0x80     | SMW_ATTR_ALGO_CKDF         | Custom Key Derivation Function.                  |
   +-----------+----------------------------+--------------------------------------------------+
   |  0xFF     | SMW_ATTR_ALGO_HASH         | Hash.                                            |
   +-----------+----------------------------+--------------------------------------------------+


.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_GET_ALGO


Mode
""""

.. table:: Algorithm Mode value
   :name: table_algorithm_mode
   :align: center
   :widths: 8 44 48
   :class: wrap-table

   +-----------+--------------------------+--------------------------------------------+
   | **Value** | **Define**               | **Description**                            |
   +===========+==========================+============================================+
   |  0x0      | SMW_ATTR_MODE_NONE       | No mode defined.                           |
   +-----------+--------------------------+--------------------------------------------+
   |  0x1      | SMW_ATTR_MODE_ECB_NO_PAD | Electronic Code Book No Padding.           |
   +-----------+--------------------------+--------------------------------------------+
   |  0x2      | SMW_ATTR_MODE_CBC_NO_PAD | Cipher block chaining No Padding.          |
   +-----------+--------------------------+--------------------------------------------+
   |  0x3      | SMW_ATTR_MODE_CFB        | Ciphertext Feedback.                       |
   +-----------+--------------------------+--------------------------------------------+
   |  0x4      | SMW_ATTR_MODE_CTR        | Counter Mode.                              |
   +-----------+--------------------------+--------------------------------------------+
   |  0x5      | SMW_ATTR_MODE_CTS        | Ciphertext Stealing.                       |
   +-----------+--------------------------+--------------------------------------------+
   |  0x6      | SMW_ATTR_MODE_OFB        | Output Feedback.                           |
   +-----------+--------------------------+--------------------------------------------+
   |  0x7      | SMW_ATTR_MODE_XTS        | XEX Tweakable Block Ciphertext Stealing.   |
   +-----------+--------------------------+--------------------------------------------+
   |  0x8      | SMW_ATTR_MODE_CCM        | Counter with CBC-MAC Mode.                 |
   +-----------+--------------------------+--------------------------------------------+
   |  0x9      | SMW_ATTR_MODE_GCM        | Galois/Counter Mode.                       |
   +-----------+--------------------------+--------------------------------------------+
   |  0xA      | SMW_ATTR_MODE_PKCS1_1_5  | Public-Key Cryptography Standards 1.5.     |
   +-----------+--------------------------+--------------------------------------------+
   |  0xB      | SMW_ATTR_MODE_OAEP       | Optimal Asymmetric Encryption Padding.     |
   +-----------+--------------------------+--------------------------------------------+
   |  0xC      | SMW_ATTR_MODE_PSS        | Probabilistic Signature Scheme.            |
   +-----------+--------------------------+--------------------------------------------+
   |  0xD      | SMW_ATTR_MODE_PKCS5      | Password-Based Cryptography Specification. |
   +-----------+--------------------------+--------------------------------------------+
   |  0xE      | SMW_ATTR_MODE_CMAC       | Cipher-based Message Authentication Code.  |
   +-----------+--------------------------+--------------------------------------------+
   |  0xF      | SMW_ATTR_MODE_POLY1305   | Poly1305-AES.                              |
   +-----------+--------------------------+--------------------------------------------+
   |  0x10     | SMW_ATTR_MODE_CLIENT     | Client (TLS 1.2).                          |
   +-----------+--------------------------+--------------------------------------------+
   |  0x11     | SMW_ATTR_MODE_SERVER     | Server (TLS 1.2).                          |
   +-----------+--------------------------+--------------------------------------------+
   |  0x12     | SMW_ATTR_MODE_NO_PAD     | Asymmetric Encryption with no padding.     |
   +-----------+--------------------------+--------------------------------------------+
   |  0xFF     | SMW_ATTR_MODE_ANY        | Any mode.                                  |
   +-----------+--------------------------+--------------------------------------------+


.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_GET_MODE SMW_ATTR_SET_MODE

Curve
"""""

.. table:: Algorithm Curve value
   :name: table_algorithm_curve
   :align: center
   :widths: 8 44 48
   :class: wrap-table

   +-----------+-----------------------------+-----------------------------+
   | **Value** | **Define**                  | **Description**             |
   +===========+=============================+=============================+
   |  0x0      | SMW_ATTR_CURVE_NONE         | No curve defined.           |
   +-----------+-----------------------------+-----------------------------+
   |  0x1      | SMW_ATTR_CURVE_SECP_R1      | Secp R1 curve (aka NIST P). |
   +-----------+-----------------------------+-----------------------------+
   |  0x2      | SMW_ATTR_CURVE_BRAINPOOL_R1 | Brainpool R1 curve.         |
   +-----------+-----------------------------+-----------------------------+
   |  0x3      | SMW_ATTR_CURVE_BRAINPOOL_T1 | Brainpool T1 curve.         |
   +-----------+-----------------------------+-----------------------------+
   |  0x4      | SMW_ATTR_CURVE_ED25519      | Twisted Edwards25519.       |
   +-----------+-----------------------------+-----------------------------+
   |  0x5      | SMW_ATTR_CURVE_ED448        | Twisted Edwards448.         |
   +-----------+-----------------------------+-----------------------------+
   |  0xFF     | SMW_ATTR_CURVE_ANY          | Any curve.                  |
   +-----------+-----------------------------+-----------------------------+


.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_GET_CURVE


Key Derivation Function
"""""""""""""""""""""""

.. table:: Algorithm Key Derivation Function value
   :name: table_algorithm_kdf
   :align: center
   :widths: 8 44 48
   :class: wrap-table

   +-----------+-----------------------------+------------------------------+
   | **Value** | **Define**                  | **Description**              |
   +===========+=============================+==============================+
   | 0xE       | SMW_ATTR_ALGO_HKDF          | HMAC Key derivation function |
   +-----------+-----------------------------+------------------------------+


.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_GET_KDF

Hash
""""

.. table:: Algorithm Hash value
   :name: table_algorithm_hash
   :align: center
   :widths: 8 44 48
   :class: wrap-table

   +----------+------------------------+------------------------------------+
   | **Value**| **Define**             | **Description**                    |
   +==========+========================+====================================+
   |  0x0     | SMW_ATTR_HASH_NONE     | No hash algorithm defined.         |
   +----------+------------------------+------------------------------------+
   |  0x1     | SMW_ATTR_HASH_MD5      | Message Digest 5.                  |
   +----------+------------------------+------------------------------------+
   |  0x2     | SMW_ATTR_HASH_SHA1     | Secure Hash Algorithm 1.           |
   +----------+------------------------+------------------------------------+
   |  0x3     | SMW_ATTR_HASH_SHA224   | Secure Hash Algorithm 2, 224 bits. |
   +----------+------------------------+------------------------------------+
   |  0x4     | SMW_ATTR_HASH_SHA256   | Secure Hash Algorithm 2, 256 bits. |
   +----------+------------------------+------------------------------------+
   |  0x5     | SMW_ATTR_HASH_SHA384   | Secure Hash Algorithm 2, 384 bits. |
   +----------+------------------------+------------------------------------+
   |  0x6     | SMW_ATTR_HASH_SHA512   | Secure Hash Algorithm 2, 512 bits. |
   +----------+------------------------+------------------------------------+
   |  0x7     | SMW_ATTR_HASH_SHA3_224 | Secure Hash Algorithm 3, 224 bits. |
   +----------+------------------------+------------------------------------+
   |  0x8     | SMW_ATTR_HASH_SHA3_256 | Secure Hash Algorithm 3, 256 bits. |
   +----------+------------------------+------------------------------------+
   |  0x9     | SMW_ATTR_HASH_SHA3_384 | Secure Hash Algorithm 3, 384 bits. |
   +----------+------------------------+------------------------------------+
   |  0xA     | SMW_ATTR_HASH_SHA3_512 | Secure Hash Algorithm 3, 512 bits. |
   +----------+------------------------+------------------------------------+
   |  0xB     | SMW_ATTR_HASH_SM3      | ShangMi 3.                         |
   +----------+------------------------+------------------------------------+
   |  0xC     | SMW_ATTR_HASH_SHAKE128 | Shake128.                          |
   +----------+------------------------+------------------------------------+
   |  0xD     | SMW_ATTR_HASH_SHAKE256 | Shake256.                          |
   +----------+------------------------+------------------------------------+
   |  0xFF    | SMW_ATTR_HASH_ANY      | Any hash algorithm.                |
   +----------+------------------------+------------------------------------+


.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_GET_HASH SMW_ATTR_SET_HASH


Class
"""""

.. table:: Algorithm Operation value
   :name: table_algorithm_operation
   :align: center
   :widths: 8 57 35
   :class: wrap-table

   +-----------+--------------------------------------+------------------------------------------------+
   | **Value** | **Define**                           | **Description**                                |
   +===========+======================================+================================================+
   |  0x0      | SMW_ATTR_CLASS_NONE                  | No class of operation defined.                 |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x1      | SMW_ATTR_CLASS_DIGEST                | Digest calculation.                            |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x2      | SMW_ATTR_CLASS_SYMMETRIC_ENCRYPTION  | Symmetric encryption.                          |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x3      | SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION | Asymmetric encryption.                         |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x4      | SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE  | Asymmetric signature.                          |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x5      | SMW_ATTR_CLASS_MAC                   | Message Authentication Code.                   |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x6      | SMW_ATTR_CLASS_AEAD                  | Authenticated Encryption with Associated Data. |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x7      | SMW_ATTR_CLASS_KEY_DERIVATION        | Key derivation.                                |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x8      | SMW_ATTR_CLASS_KEY_ATTESTATION       | Key attestation.                               |
   +-----------+--------------------------------------+------------------------------------------------+
   |  0x9      | SMW_ATTR_CLASS_KEY_AGREEMENT         | Key agreement.                                 |
   +-----------+--------------------------------------+------------------------------------------------+

.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_GET_CLASS

.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_ALGO_DIGEST
            SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION
            SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION_RSA
            SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA
            SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA
            SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_DSA
            SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA
            SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_TLS_1_2_NO_LABEL
            SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_TLS_1_2_CLIENT
            SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_TLS_1_2_SERVER
            SMW_ATTR_ALGO_MAC
            SMW_ATTR_ALGO_MAC_HMAC
            SMW_ATTR_ALGO_AEAD
            SMW_ATTR_ALGO_KEY_DERIVATION_HKDF
            SMW_ATTR_ALGO_KEY_DERIVATION_DH
            SMW_ATTR_ALGO_KEY_DERIVATION_ECDH
            SMW_ATTR_ALGO_KEY_DERIVATION_EDDSA
            SMW_ATTR_ALGO_KEY_DERIVATION_TLS12
            SMW_ATTR_ALGO_KEY_DERIVATION_TLS13
            SMW_ATTR_ALGO_KEY_ATTESTATION_MAC
            SMW_ATTR_ALGO_KEY_ATTESTATION_ECDSA
            SMW_ATTR_ALGO_KEY_AGREEMENT


Additional Parameters
"""""""""""""""""""""

.. table:: Additional Algorithm bitmask value
   :name: table_additional_parameters
   :align: center
   :widths: 27 8 25 40
   :class: wrap-table

   +---------------------------+------------+----------------------+-------------------------------------------------+
   | **Parameter**             | **Bit 39** | **Bits[38:32]**      | **Description**                                 |
   +===========================+============+======================+=================================================+
   | Salt length bytes         | 0x0        | 0 <= len <= hash len | RSA Signature Salt length.                      |
   +---------------------------+------------+----------------------+                                                 +
   | Min Salt length [1]_      | 0x1        | 0 <= len <= hash len |                                                 |
   +---------------------------+------------+----------------------+-------------------------------------------------+
   | MAC length bytes          | 0x0        | 0 <= len <= MAC len  | Truncated MAC length. `MAC len` is the          |
   +---------------------------+------------+----------------------+                                                 +
   | Min MAC length bytes [1]_ | 0x1        | 0 <= len <= MAC len  | algorithm length in bytes.                      |
   +---------------------------+------------+----------------------+-------------------------------------------------+
   | Tag length bytes          | 0x0        | 0 <= len <= Tag len  | AEAD Tag length. `Tag len` is                   |
   +---------------------------+------------+----------------------+                                                 +
   | Min Tag length bytes [1]_ | 0x1        | 0 <= len <= Tag len  | the algorithm length in bytes.                  |
   +---------------------------+------------+----------------------+-------------------------------------------------+
   | Signature Message Full    | 0x0        | \-                   | Asymmetric signature input message type.        |
   +---------------------------+------------+----------------------+                                                 +
   | Signature Message Hashed  | 0x1        | \-                   |                                                 |
   +---------------------------+------------+----------------------+-------------------------------------------------+
   | EDDSA pre-hashed          | \-         | 0x1                  | Asymmetric EDDSA signature type is pre-hashed.  |
   +---------------------------+------------+----------------------+-------------------------------------------------+
   | EDDSA context             | \-         | 0x2                  | Asymmetric EDDSA signature type is with context.|
   +---------------------------+------------+----------------------+-------------------------------------------------+

.. [1] Used for the key permitted algorithm definition only.


.. kdoc-extension:: /public/smw/attr.h
   :macros: SMW_ATTR_SET_LENGTH
            SMW_ATTR_GET_LENGTH
            SMW_ATTR_SET_MIN_LENGTH
            SMW_ATTR_IS_MIN_LENGTH
            SMW_ATTR_SET_SALT_LENGTH
            SMW_ATTR_GET_SALT_LENGTH
            SMW_ATTR_SET_MIN_SALT_LENGTH
            SMW_ATTR_IS_MIN_SALT_LENGTH
            SMW_ATTR_SET_MAC_LENGTH
            SMW_ATTR_GET_MAC_LENGTH
            SMW_ATTR_SET_MIN_MAC_LENGTH
            SMW_ATTR_IS_MIN_MAC_LENGTH
            SMW_ATTR_SET_TAG_LENGTH
            SMW_ATTR_GET_TAG_LENGTH
            SMW_ATTR_SET_MIN_TAG_LENGTH
            SMW_ATTR_IS_MIN_TAG_LENGTH
            SMW_ATTR_SET_MSG_HASHED
            SMW_ATTR_IS_MSG_HASHED
            SMW_ATTR_GET_SIGN_PARAM
            SMW_ATTR_SET_SIGN_PARAM
            SMW_ATTR_SET_SIGN_EDDSA_PREHASHED
            SMW_ATTR_IS_SIGN_EDDSA_PREHASHED
            SMW_ATTR_SET_SIGN_EDDSA_CONTEXT
            SMW_ATTR_IS_SIGN_EDDSA_CONTEXT

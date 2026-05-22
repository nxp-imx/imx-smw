.. _algorithm-psa_algorithm_t-encoding:

Cryptographic Algorithm (psa_algorithm_t) encoding
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This chapter intends to detail the algorithm encoding definitions used to
describe cryptographic algorithms and their parameters within the PSA API.

The algorithm encoding is a 32-bit value that encapsulates all necessary
information to define and restrict cryptographic operations.

The same 32-bit encoding is used throughout the PSA API to specify:

  - Cryptographic algorithms (symmetric, asymmetric, hash functions).
  - Algorithm modes and parameters.
  - Permitted key algorithm when requested by the Security Subsystem.

Typedef
"""""""
.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_algorithm_t

This is a structured bitfield that identifies the category and type of
algorithm. The range of algorithm identifier values is divided as follows:

  - 0x00000000
      Reserved as an invalid algorithm identifier.

  - 0x00000001 - 0x7fffffff
      Specification-defined algorithm identifiers. Algorithm identifiers
      defined by this standard always have bit 31 clear. Unallocated algorithm
      identifier values in this range are reserved for future use.

  - 0x80000000 - 0xffffffff
      Implementation-defined algorithm identifiers. Implementations that
      define additional algorithms must use an encoding with bit 31 set. The
      related support macros will be easier to write if these algorithm
      identifier encodings also respect the bitwise structure used by standard
      encodings.

For algorithms that can be applied to multiple key types, this identifier
does not encode the key type. For example, for symmetric ciphers based on a
block cipher, :c:type:`psa_algorithm_t` encodes the block cipher mode and the
padding mode while the block cipher itself is encoded via
:c:type:`psa_key_type_t`.


.. table:: Algorithm encoding bit fields
   :name: table_psa_algorithm_encoding
   :align: center
   :widths: 10 10 80
   :class: wrap-table

   +-----------+-------------+------------------------------------------------------------+
   | **Field** | **Bits**    | **Description**                                            |
   +===========+=============+============================================================+
   | V         | **[31]**    | Vendor additional algorithm identifier when set to 1.      |
   +-----------+-------------+------------------------------------------------------------+
   | CAT       | **[31:24]** | See `Algorithm Category`_.                                 |
   +-----------+-------------+------------------------------------------------------------+
   | S         | **[23]**    | For a cipher algorithm, this flag indicates a stream       |
   |           |             | cipher when set to 1.                                      |
   |           |             | For a key-derivation algorithm, this flag indicates a      |
   |           |             | key-stretching or password-hashing algorithm when set to 1.|
   +-----------+-------------+------------------------------------------------------------+
   | B         | **[22]**    | Flag to indicate an algorithm built on a block cipher when |
   |           |             | set to 1.                                                  |
   +-----------+-------------+------------------------------------------------------------+
   | LEN/T2    | **[21:16]** | LEN is the length of a MAC or AEAD tag, T2 is a            |
   |           |             | key-agreement algorithm sub-type.                          |
   +-----------+-------------+------------------------------------------------------------+
   | T1        | **[15:8]**  | Algorithm sub-type for most algorithm categories.          |
   +-----------+-------------+------------------------------------------------------------+
   | H         | **[7:0]**   | Hash algorithm sub-type, also used in any algorithm that   |
   |           |             | is parameterized by a hash.                                |
   +-----------+-------------+------------------------------------------------------------+

Algorithm Category
""""""""""""""""""
.. table:: Algorithm Category value
   :name: table_psa_algorithm_category
   :align: center
   :widths: 8 15 30
   :class: wrap-table

   +-----------+-----------------------+--------------------------------------------------+
   | **Value** | **Category**          | **Description**                                  |
   +===========+=======================+==================================================+
   |  0x00     | None                  | No algorithm defined. `PSA_ALG_NONE`             |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x02     | Hash                  | See `Hash algorithms`_.                          |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x03     | MAC                   | Message Authentication Code algorithms.          |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x04     | Cipher                | Symmetric cipher algorithms.                     |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x05     | AEAD                  | Authenticated Encryption with Associated Data.   |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x06     | Asymmetric Signature  | Asymmetric signature algorithms.                 |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x07     | Asymmetric encryption | Asymmetric encryption algorithms.                |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x08     | Key derivation        | Key derivation algorithms.                       |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x09     | Key agreement         | Key-agreement algorithms.                        |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x0C     | Key encapsulation     | Key-encapsulation algorithms.                    |
   +-----------+-----------------------+--------------------------------------------------+
   |  0x0A     | PAKE                  | PAKE algorithms.                                 |
   +-----------+-----------------------+--------------------------------------------------+

Hash Algorithms
"""""""""""""""
The table :numref:`table_psa_hash_algorithms` lists the hash algorithm
identifiers supported in the context of the Security Middleware library and
Secure Subsystems.

The Hash algorithm encoding follows the algorithm encoding format described in
:numref:`table_psa_algorithm_encoding`, where the category is set to 0x02
(Hash) and the HASH-TYPE field [7:0] contains the hash algorithm sub-type
identifier details in the :numref:`table_psa_hash_algorithms` table below.

.. table:: Hash Algorithm identifiers
   :name: table_psa_hash_algorithms
   :align: center
   :widths: 15 15 20 40
   :class: wrap-table

   +------------+---------------+---------------------------+------------------------------------+
   | **Value**  | **HASH-TYPE** | **Define**                | **Description**                    |
   +============+===============+===========================+====================================+
   | 0x02000003 |   0x03        | PSA_ALG_MD5               | Message Digest 5.                  |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000005 |   0x05        | PSA_ALG_SHA_1             | Secure Hash Algorithm 1.           |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000008 |   0x08        | PSA_ALG_SHA_224           | Secure Hash Algorithm 2, 224 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000009 |   0x09        | PSA_ALG_SHA_256           | Secure Hash Algorithm 2, 256 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x0200000A |   0x0A        | PSA_ALG_SHA_384           | Secure Hash Algorithm 2, 384 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x0200000B |   0x0B        | PSA_ALG_SHA_512           | Secure Hash Algorithm 2, 512 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x0200000C |   0x0C        | PSA_ALG_SHA_512_224       | SHA-512 truncated to 224 bits.     |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x0200000D |   0x0D        | PSA_ALG_SHA_512_256       | SHA-512 truncated to 256 bits.     |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000010 |   0x10        | PSA_ALG_SHA3_224          | Secure Hash Algorithm 3, 224 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000011 |   0x11        | PSA_ALG_SHA3_256          | Secure Hash Algorithm 3, 256 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000012 |   0x12        | PSA_ALG_SHA3_384          | Secure Hash Algorithm 3, 384 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000013 |   0x13        | PSA_ALG_SHA3_512          | Secure Hash Algorithm 3, 512 bits. |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000014 |   0x14        | PSA_ALG_SM3               | ShangMi 3.                         |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x02000015 |   0x15        | PSA_ALG_SHAKE256_512      | SHAKE256 with 512-bit output.      |
   +------------+---------------+---------------------------+------------------------------------+
   | 0x020000FF |   0xFF        | PSA_ALG_ANY_HASH          | Any hash algorithm.                |
   +------------+---------------+---------------------------+------------------------------------+

MAC Algorithms
""""""""""""""
The MAC algorithm encoding follows the algorithm encoding format described in
:numref:`table_psa_algorithm_encoding`, as detailed in the following
:numref:`table_psa_mac_algorithm_encoding`.

.. table:: MAC Algorithm encoding
   :name: table_psa_mac_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +------------+----------+-----------------------------------------------------------------+
   | **Field**  | **Bits** | **Description**                                                 |
   +============+==========+=================================================================+
   | V          | [31]     | =0                                                              |
   +------------+----------+-----------------------------------------------------------------+
   | CAT        | [30:24]  | =0x03 (MAC)                                                     |
   +------------+----------+-----------------------------------------------------------------+
   | S          | [23]     | =1                                                              |
   +------------+----------+-----------------------------------------------------------------+
   | B          | [22]     | See :numref:`table_psa_mac_algorithms`.                         |
   +------------+----------+-----------------------------------------------------------------+
   | LEN        | [21:16]  | Truncated MAC length if not 0.                                  |
   +------------+----------+-----------------------------------------------------------------+
   | W          | [15]     | Wildcard permitted algorithm policy:\                           |
   |            |          |                                                                 |
   |            |          |  - =0 indicates a specific MAC algorithm and MAC length.        |
   |            |          |  - =1 indicates a wildcard key usage policy, which              |
   |            |          |    permits the MAC algorithm with a MAC length at least         |
   |            |          |    equal to `LEN`. `LEN` can't be 0.                            |
   +------------+----------+-----------------------------------------------------------------+
   | MAC-TYPE   | [14:8]   | The MAC algorithm type. See :numref:`table_psa_mac_algorithms`. |
   +------------+----------+-----------------------------------------------------------------+
   | HASH-TYPE  | [7:0]    | Hash algorithm for HMAC (:numref:`table_psa_hash_algorithms`),  |
   |            |          | 0 for CMAC.                                                     |
   +------------+----------+-----------------------------------------------------------------+


.. table:: MAC Algorithm identifiers
   :name: table_psa_mac_algorithms
   :widths: 18 5 13 26 30
   :width: 100%
   :class: wrap-table

   +----------------+-------+--------------+-------------------------+-------------------------------------------+
   | **Value**      | **B** | **MAC-TYPE** | **Define**              | **Description**                           |
   +================+=======+==============+=========================+===========================================+
   | 0x038000hh (1) |   0   | 0x00         |  PSA_ALG_HMAC(hash_alg) | Hash-based Message Authentication Code.   |
   +----------------+-------+--------------+-------------------------+-------------------------------------------+
   | 0x03c00100     |   1   | 0x01         |  PSA_ALG_CMAC           | Cipher-based Message Authentication Code. |
   +----------------+-------+--------------+-------------------------+-------------------------------------------+
   | 0x03c00200     |   1   | 0x02         |  PSA_ALG_CBC_MAC        | CBC-MAC.                                  |
   +----------------+-------+--------------+-------------------------+-------------------------------------------+

(1) hh is the hash algorithm identifier as defined in the
    :numref:`table_psa_hash_algorithms`.

The above :numref:`table_psa_mac_algorithms` defines the default algorithm
identifier, specifying a standard length tag.

PSA_ALG_TRUNCATED_MAC() generates identifiers with non-default LEN values.

PSA_ALG_AT_LEAST_THIS_LENGTH_MAC() generates permitted-algorithm policies with
W = 1.

Cipher Algorithms
"""""""""""""""""
The Cipher algorithm encoding follows the algorithm encoding format described in
:numref:`table_psa_algorithm_encoding`, as detailed in the following
:numref:`table_psa_cipher_algorithm_encoding`.

.. table:: Cipher Algorithm encoding
   :name: table_psa_cipher_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +-------------+----------+-----------------------------------------------------------------------+
   | **Field**   | **Bits** | **Description**                                                       |
   +=============+==========+=======================================================================+
   | V           | [31]     | =0                                                                    |
   +-------------+----------+-----------------------------------------------------------------------+
   | CAT         | [30:24]  | =0x04 (Cipher)                                                        |
   +-------------+----------+-----------------------------------------------------------------------+
   | S           | [23]     | See :numref:`table_psa_cipher_algorithms`.                            |
   +-------------+----------+-----------------------------------------------------------------------+
   | B           | [22]     | See :numref:`table_psa_cipher_algorithms`.                            |
   +-------------+----------+-----------------------------------------------------------------------+
   | LEN         | [21:16]  | =0                                                                    |
   +-------------+----------+-----------------------------------------------------------------------+
   | C-TYPE      | [15:8]   | The Cipher algorithm type. See :numref:`table_psa_cipher_algorithms`. |
   +-------------+----------+-----------------------------------------------------------------------+
   | HASH-TYPE   | [7:0]    | =0                                                                    |
   +-------------+----------+-----------------------------------------------------------------------+

.. table:: Cipher Algorithm identifiers
   :name: table_psa_cipher_algorithms
   :widths: 12 4 4 8 25 25
   :width: 100%
   :class: wrap-table

   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | **Value**  | **S** | **B** | **C-TYPE**      | **Define**                | **Description**                            |
   +============+=======+=======+=================+===========================+============================================+
   | 0x04800100 |   1   |   0   |  0x01           | PSA_ALG_STREAM_CIPHER     | Stream cipher mode.                        |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04C01000 |   1   |   1   |  0x10           | PSA_ALG_CTR               | Counter Mode.                              |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04C01100 |   1   |   1   |  0x11           | PSA_ALG_CFB               | Cipher Feedback Mode.                      |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04C01200 |   1   |   1   |  0x12           | PSA_ALG_OFB               | Output Feedback Mode.                      |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04C01300 |   1   |   1   |  0x13           | PSA_ALG_CCM_STAR_NO_TAG   | CCM* mode without authentication tag.      |
   |            |       |       |                 |                           | The block cipher is determinded by the key |
   |            |       |       |                 |                           | type.                                      |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04C09300 |   1   |   1   |  0x93           | PSA_ALG_CCM_ANY_TAG       | CCM* Wildcard. Permits a key to be used    |
   |            |       |       |                 |                           | with any CCM* algorithm                    |
   |            |       |       |                 |                           | PSA_ALG_CCM_STAR_NO_TAG and AEAD algorithm |
   |            |       |       |                 |                           | PSA_ALG_CCM.                               |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x0440FF00 |   0   |   1   |  0xFF           | PSA_ALG_XTS               | XEX Tweakable Block Cipher.                |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04404000 |   0   |   1   |  0x40           | PSA_ALG_CBC_NO_PADDING    | Cipher Block Chaining without padding.     |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04404100 |   0   |   1   |  0x41           | PSA_ALG_CBC_PKCS7         | Cipher Block Chaining with PKCS#7 padding. |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+
   | 0x04404400 |   0   |   1   |  0x44           | PSA_ALG_ECB_NO_PADDING    | Electronic Block Chaining without padding. |
   +------------+-------+-------+-----------------+---------------------------+--------------------------------------------+

AEAD Algorithms
"""""""""""""""
The AEAD algorithm encoding follows the algorithm encoding format described in
:numref:`table_psa_algorithm_encoding`, as detailed in the following
:numref:`table_psa_aead_algorithm_encoding`.

.. table:: AEAD Algorithm encoding
   :name: table_psa_aead_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +------------+----------+-------------------------------------------------------------------+
   | **Field**  | **Bits** | **Description**                                                   |
   +============+==========+===================================================================+
   | V          | [31]     | =0                                                                |
   +------------+----------+-------------------------------------------------------------------+
   | CAT        | [30:24]  | =0x05 (AEAD)                                                      |
   +------------+----------+-------------------------------------------------------------------+
   | S          | [23]     | =0                                                                |
   +------------+----------+-------------------------------------------------------------------+
   | B          | [22]     | See :numref:`table_psa_aead_algorithms`.                          |
   +------------+----------+-------------------------------------------------------------------+
   | LEN        | [21:16]  | Specfies the output tag length from 1 to 31 bytes.                |
   +------------+----------+-------------------------------------------------------------------+
   | W          | [15]     | Wildcard permitted algorithm policy:\                             |
   |            |          |                                                                   |
   |            |          |  - =0 indicates a specific AEAD algorithm and tag length.         |
   |            |          |  - =1 indicates a wildcard key usage policy, which                |
   |            |          |    permits the AEAD algorithm with a tag length at least          |
   |            |          |    equal to `LEN`. `LEN` can't be 0.                              |
   +------------+----------+-------------------------------------------------------------------+
   | AEAD-TYPE  | [14:8]   | The AEAD algorithm type. See :numref:`table_psa_aead_algorithms`. |
   +------------+----------+-------------------------------------------------------------------+
   | HASH-TYPE  | [7:0]    | =0                                                                |
   +------------+----------+-------------------------------------------------------------------+


.. table:: AEAD Algorithm identifiers
   :name: table_psa_aead_algorithms
   :widths: 13 5 13 31 20
   :width: 100%
   :class: wrap-table

   +------------+-------+---------------+----------------------------+--------------------------------------------------------+
   | **Value**  | **B** | **AEAD-TYPE** | **Define**                 | **Description**                                        |
   +============+=======+===============+============================+========================================================+
   | 0x05500100 |   1   | 0x01          | PSA_ALG_CCM                | Counter with CBC-MAC. The block cipher is determined   |
   |            |       |               |                            | by the key type.                                       |
   +------------+-------+---------------+----------------------------+--------------------------------------------------------+
   | 0x05500200 |   1   | 0x02          | PSA_ALG_GCM                | Galois/Counter Mode. The block cipher is determined    |
   |            |       |               |                            | by the key type.                                       |
   +------------+-------+---------------+----------------------------+--------------------------------------------------------+
   | 0x05100500 |   0   | 0x05          | PSA_ALG_CHACHA20_POLY1305  | ChaCha20-Poly1305                                      |
   +------------+-------+---------------+----------------------------+--------------------------------------------------------+
   | 0x05100600 |   0   | 0x06          | PSA_ALG_XCHACHA20_POLY1305 | XChaCha20-Poly1305                                     |
   +------------+-------+---------------+----------------------------+--------------------------------------------------------+

The above :numref:`table_psa_aead_algorithms` defines the default algorithm
identifier, specifying the default tag length for the algorithm.

PSA_ALG_AEAD_WITH_SHORTENED_TAG() generates identifiers with alternative LEN
values.

PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG() generates wildcard
permitted-algorithm policies with W = 1.

Asymmetric Signature Algorithms
"""""""""""""""""""""""""""""""
The Asymmetric Signature algorithm encoding follows the algorithm encoding
format described in the :numref:`table_psa_algorithm_encoding`, as detailed in
the following :numref:`table_psa_asym_sign_algorithm_encoding`.

.. table:: Asymmetric Signature Algorithm encoding
   :name: table_psa_asym_sign_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +------------+----------+------------------------------------------+
   | **Field**  | **Bits** | **Description**                          |
   +============+==========+==========================================+
   | V          | [31]     | =0                                       |
   +------------+----------+------------------------------------------+
   | CAT        | [30:24]  | =0x06 (Asymmetric Signature)             |
   +------------+----------+------------------------------------------+
   | S          | [23]     | =0                                       |
   +------------+----------+------------------------------------------+
   | B          | [22]     | =0                                       |
   +------------+----------+------------------------------------------+
   | LEN        | [21:16]  | =0                                       |
   +------------+----------+------------------------------------------+
   | SIGN-TYPE  | [15:8]   | The Asymmetric Signature algorithm type. |
   |            |          | See :numref:`table_psa_sign_algorithms`. |
   +------------+----------+------------------------------------------+
   | HASH-TYPE  | [7:0]    | =0 or HASH-TYPE as defined in the        |
   |            |          | :numref:`table_psa_hash_algorithms`.     |
   +------------+----------+------------------------------------------+

.. table:: Signature Algorithm identifiers
   :name: table_psa_sign_algorithms
   :widths: 17 13 35 20
   :width: 100%
   :class: wrap-table

   +----------------+---------------+----------------------------------+--------------------------------------------+
   | **Value**      | **SIGN-TYPE** | **Define**                       | **Description**                            |
   +================+===============+==================================+============================================+
   | 0x060002hh (1) | 0x02          | PSA_ALG_RSA_PKCS1V15_SIGN(hash)  | PKCS#1 v1.5 signature with hash.           |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x06000200     | 0x02          | PSA_ALG_RSA_PKCS1V15_SIGN_RAW    | PKCS#1 v1.5 signature no hash.             |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x060003hh (1) | 0x03          | PSA_ALG_RSA_PSS(hash)            | RSA PSS signature with hash.               |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x060013hh     | 0x13          | PSA_ALG_RSA_PSS_ANY_SALT(hash)   | RSA PSS with any salt length.              |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x060006hh (1) | 0x06          | PSA_ALG_ECDSA(hash)              | ECDSA signature with hash.                 |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x06000600     | 0x06          | PSA_ALG_ECDSA_ANY                | ECDSA signature without hash restriction.  |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x060007hh (1) | 0x07          | PSA_ALG_DETERMINISTIC_ECDSA(hash)| Deterministic ECDSA (RFC 6979).            |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x06000800     | 0x08          | PSA_ALG_PURE_EDDSA               | Pure EdDSA signature.                      |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x0600090B     | 0x09          | PSA_ALG_ED25519PH                | Ed25519ph (pre-hashed Ed25519).            |
   +----------------+---------------+----------------------------------+--------------------------------------------+
   | 0x06000915     | 0x09          | PSA_ALG_ED448PH                  | Ed448ph (pre-hashed Ed448).                |
   +----------------+---------------+----------------------------------+--------------------------------------------+

(1) hh is the hash algorithm identifier as defined in the
    :numref:`table_psa_hash_algorithms`.

Asymmetric Encryption Algorithms
""""""""""""""""""""""""""""""""
The Asymmetric Encryption algorithm encoding follows the algorithm encoding
format described in the :numref:`table_psa_algorithm_encoding`, as detailed in
the following :numref:`table_psa_asym_enc_algorithm_encoding`.

.. table:: Asymmetric Encryption Algorithm encoding
   :name: table_psa_asym_enc_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +------------+----------+----------------------------------------------+
   | **Field**  | **Bits** | **Description**                              |
   +============+==========+==============================================+
   | V          | [31]     | =0                                           |
   +------------+----------+----------------------------------------------+
   | CAT        | [30:24]  | =0x07 (Asymmetric Encryption)                |
   +------------+----------+----------------------------------------------+
   | S          | [23]     | =0                                           |
   +------------+----------+----------------------------------------------+
   | B          | [22]     | =0                                           |
   +------------+----------+----------------------------------------------+
   | LEN        | [21:16]  | =0                                           |
   +------------+----------+----------------------------------------------+
   | ENC-TYPE   | [15:8]   | The Asymmetric Encryption algorithm type.    |
   |            |          | See :numref:`table_psa_asym_enc_algorithms`. |
   +------------+----------+----------------------------------------------+
   | HASH-TYPE  | [7:0]    | =0 or HASH-TYPE as defined in the            |
   |            |          | :numref:`table_psa_hash_algorithms`.         |
   +------------+----------+----------------------------------------------+

.. table:: Asymmetric Encryption Algorithm identifiers
   :name: table_psa_asym_enc_algorithms
   :widths: 17 12 30 25
   :width: 100%
   :class: wrap-table

   +----------------+--------------+----------------------------+--------------------------------+
   | **Value**      | **ENC-TYPE** | **Define**                 | **Description**                |
   +================+==============+============================+================================+
   | 0x07000200     | 0x02         | PSA_ALG_RSA_PKCS1V15_CRYPT | PKCS#1 v1.5 encryption.        |
   +----------------+--------------+----------------------------+--------------------------------+
   | 0x070003hh (1) | 0x03         | PSA_ALG_RSA_OAEP(hash)     | RSA OAEP encryption with hash. |
   +----------------+--------------+----------------------------+--------------------------------+

(1) hh is the hash algorithm identifier as defined in the
    :numref:`table_psa_hash_algorithms`.

Key Derivation Algorithms
"""""""""""""""""""""""""
The Key Derivation algorithm encoding follows the algorithm encoding
format described in the :numref:`table_psa_algorithm_encoding`, as detailed in
the following :numref:`table_psa_key_derive_algorithm_encoding`.


The key derivation algorithm identifiers have been extended with a specific
identifier to manage TLS 1.3 key derivation and agreement targeting the
ELE subsystem. The :numref:`table_psa_key_derivation_algorithms` defines the
PSA standard identifiers and the extended identifier is defined in the
:numref:`table_psa_key_derivation_vendor_algorithms`.

.. table:: Key Derivation Algorithm encoding
   :name: table_psa_key_derive_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +------------+----------+-------------------------------------------------------------+
   | **Field**  | **Bits** | **Description**                                             |
   +============+==========+=============================================================+
   | V          | [31]     | Can be 0 or 1:\                                             |
   |            |          |                                                             |
   |            |          |  - =0, :numref:`table_psa_key_derivation_algorithms`        |
   |            |          |  - =1, :numref:`table_psa_key_derivation_vendor_algorithms` |
   +------------+----------+-------------------------------------------------------------+
   | CAT        | [30:24]  | =0x08 (Key Derivation)                                      |
   +------------+----------+-------------------------------------------------------------+
   | S          | [23]     | See :numref:`table_psa_key_derivation_algorithms`.          |
   +------------+----------+-------------------------------------------------------------+
   | B          | [22]     | =0                                                          |
   +------------+----------+-------------------------------------------------------------+
   | LEN        | [21:16]  | =0                                                          |
   +------------+----------+-------------------------------------------------------------+
   | KDF-TYPE   | [15:8]   | The Key Derivation algorithm type.                          |
   |            |          | See :numref:`table_psa_key_derivation_algorithms`.          |
   +------------+----------+-------------------------------------------------------------+
   | HASH-TYPE  | [7:0]    | =0 or HASH-TYPE as defined in the                           |
   |            |          | :numref:`table_psa_hash_algorithms`.                        |
   +------------+----------+-------------------------------------------------------------+

.. table:: Key Derivation Algorithm identifiers (V=0)
   :name: table_psa_key_derivation_algorithms
   :widths: 15 5 12 33 15
   :width: 100%
   :class: wrap-table

   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | **Value**      | **S** | **KDF-TYPE** | **Define**                      | **Description**                            |
   +================+=======+==============+=================================+============================================+
   | 0x080001hh (1) |  0    | 0x01         | PSA_ALG_HKDF(hash)              | HMAC-based Key Derivation Function.        |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | 0x080004hh (1) |  0    | 0x04         | PSA_ALG_HKDF_EXTRACT(hash)      | HKDF Extract step only.                    |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | 0x080005hh (1) |  0    | 0x05         | PSA_ALG_HKDF_EXPAND(hash)       | HKDF Expand step only.                     |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | 0x080002hh (1) |  0    | 0x02         | PSA_ALG_TLS12_PRF(hash)         | TLS 1.2 PRF.                               |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | 0x080003hh (1) |  0    | 0x03         | PSA_ALG_TLS12_PSK_TO_MS(hash)   | TLS 1.2 PSK to MasterSecret.               |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | 0x08000609     |  0    | 0x06         | PSA_ALG_TLS12_ECJPAKE_TO_PMS    | TLS 1.2 EC J-PAKE to PMS.                  |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | 0x088001hh (1) |  1    | 0x01         | PSA_ALG_PBKDF2_HMAC(hash)       | PBKDF2 with HMAC.                          |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | 0x088002hh (1) |  1    | 0x02         | PSA_ALG_PBKDF2_AES_CMAC_PRF_128 | PBKDF2 with AES-CMAC-PRF-128.              |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+

(1) hh is the hash algorithm identifier as defined in the
    :numref:`table_psa_hash_algorithms`.

.. table:: Key Derivation Vendor Algorithm identifiers (V=1)
   :name: table_psa_key_derivation_vendor_algorithms
   :widths: 15 5 12 33 15
   :width: 100%
   :class: wrap-table

   +----------------+-------+--------------+---------------------------------+--------------------------------------------+
   | **Value**      | **S** | **KDF-TYPE** | **Define**                      | **Description**                            |
   +================+=======+==============+=================================+============================================+
   | 0x88000Dhh (1) |  0    | 0x0D         | PSA_ALG_VENDOR_TLS13            | TLS 1.3 key derivation and agreement.      |
   +----------------+-------+--------------+---------------------------------+--------------------------------------------+

(1) hh is the hash algorithm identifier as defined in the
    :numref:`table_psa_hash_algorithms`.

Key Agreement Algorithms
""""""""""""""""""""""""
The Key Agreement algorithm encoding follows the algorithm encoding
format described in the :numref:`table_psa_algorithm_encoding`, as detailed in
the following :numref:`table_psa_key_agree_algorithm_encoding`.

.. table:: Key Agreement Algorithm encoding
   :name: table_psa_key_agree_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +------------+----------+----------------------------------------------------+
   | **Field**  | **Bits** | **Description**                                    |
   +============+==========+====================================================+
   | V          | [31]     | =0                                                 |
   +------------+----------+----------------------------------------------------+
   | CAT        | [30:24]  | =0x09 (Key Agreement)                              |
   +------------+----------+----------------------------------------------------+
   | S          | [23]     | =0                                                 |
   +------------+----------+----------------------------------------------------+
   | B          | [22]     | =0                                                 |
   +------------+----------+----------------------------------------------------+
   | LEN        | [21:16]  | =0                                                 |
   +------------+----------+----------------------------------------------------+
   | KA-TYPE    | [15:8]   | The Key Agreement algorithm type.                  |
   |            |          | See :numref:`table_psa_key_agree_algorithms`.      |
   +------------+----------+----------------------------------------------------+
   | HASH-TYPE  | [7:0]    | =0                                                 |
   +------------+----------+----------------------------------------------------+

.. table:: Key Agreement Algorithm identifiers
   :name: table_psa_key_agree_algorithms
   :widths: 15 12 20 30
   :width: 100%
   :class: wrap-table

   +------------+-------------+--------------+--------------------------------+
   | **Value**  | **KA-TYPE** | **Define**   | **Description**                |
   +============+=============+==============+================================+
   | 0x09010000 | 0x01        | PSA_ALG_FFDH | Finite Field Diffie-Hellman.   |
   +------------+-------------+--------------+--------------------------------+
   | 0x09020000 | 0x02        | PSA_ALG_ECDH | Elliptic Curve Diffie-Hellman. |
   +------------+-------------+--------------+--------------------------------+

Password-authenticated key exchange (PAKE) Algorithm
""""""""""""""""""""""""""""""""""""""""""""""""""""
The PAKE algorithm encoding follows the algorithm encoding
format described in the :numref:`table_psa_algorithm_encoding`, as detailed in
the following :numref:`table_psa_pake_algorithm_encoding`.

.. table:: PAKE Algorithm encoding
   :name: table_psa_pake_algorithm_encoding
   :align: center
   :widths: 15 10 60
   :class: wrap-table

   +------------+----------+------------------------------------------+
   | **Field**  | **Bits** | **Description**                          |
   +============+==========+==========================================+
   | V          | [31]     | =0                                       |
   +------------+----------+------------------------------------------+
   | CAT        | [30:24]  | =0x0A (PAKE)                             |
   +------------+----------+------------------------------------------+
   | S          | [23]     | =0                                       |
   +------------+----------+------------------------------------------+
   | B          | [22]     | =0                                       |
   +------------+----------+------------------------------------------+
   | LEN        | [21:16]  | =0                                       |
   +------------+----------+------------------------------------------+
   | PAKE-TYPE  | [15:8]   | The PAKE algorithm type.                 |
   |            |          | See :numref:`table_psa_pake_algorithms`. |
   +------------+----------+------------------------------------------+
   | HASH-TYPE  | [7:0]    | =0                                       |
   +------------+----------+------------------------------------------+

.. table:: PAKE Algorithm identifiers
   :name: table_psa_pake_algorithms
   :widths: 13 10 23 20
   :width: 100%
   :class: wrap-table

   +----------------+---------------+-----------------------------+---------------------+
   | **Value**      | **PAKE-TYPE** | **Define**                  | **Description**     |
   +================+===============+=============================+=====================+
   | 0x0A0001hh (1) | 0x01          | PSA_ALG_JPAKE(hash)         | J-PAKE.             |
   +----------------+---------------+-----------------------------+---------------------+
   | 0x0A0004hh (1) | 0x04          | PSA_ALG_SPAKE2P_HMAC(hash)  | SPAKE2+ with HMAC.  |
   +----------------+---------------+-----------------------------+---------------------+
   | 0x0A0005hh (1) | 0x05          | PSA_ALG_SPAKE2P_CMAC(hash)  | SPAKE2+ with CMAC.  |
   +----------------+---------------+-----------------------------+---------------------+
   | 0x0A000609     | 0x06          | PSA_ALG_SPAKE2P_Matter      | SPAKE2+ for Matter. |
   +----------------+---------------+-----------------------------+---------------------+

(1) hh is the hash algorithm identifier as defined in the
    :numref:`table_psa_hash_algorithms`.

Algorithm Properties
""""""""""""""""""""
The PSA Crypto macros provides macros to query algorithm properties:

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_ALG_IS_HASH
            PSA_ALG_IS_HASH_AND_SIGN
            PSA_ALG_IS_MAC
            PSA_ALG_IS_MAC_TRUNCATED
            PSA_ALG_IS_BLOCK_CIPHER_MAC
            PSA_ALG_IS_CIPHER
            PSA_ALG_IS_STREAM_CIPHER
            PSA_ALG_IS_AEAD
            PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER
            PSA_ALG_IS_DETERMINISTIC_ECDSA
            PSA_ALG_IS_RANDOMIZED_ECDSA
            PSA_ALG_IS_ECDH
            PSA_ALG_IS_ECDSA
            PSA_ALG_IS_FFDH
            PSA_ALG_IS_HKDF
            PSA_ALG_IS_HKDF_EXTRACT
            PSA_ALG_IS_HKDF_EXPAND
            PSA_ALG_IS_PBKDF2_HMAC
            PSA_ALG_IS_HMAC
            PSA_ALG_IS_SIGN
            PSA_ALG_IS_SIGN_HASH
            PSA_ALG_IS_SIGN_MESSAGE
            PSA_ALG_IS_ASYMMETRIC_ENCRYPTION
            PSA_ALG_IS_KEY_DERIVATION
            PSA_ALG_IS_KEY_DERIVATION_STRETCHING
            PSA_ALG_IS_KEY_AGREEMENT
            PSA_ALG_IS_STANDALONE_KEY_AGREEMENT
            PSA_ALG_IS_RAW_KEY_AGREEMENT
            PSA_ALG_IS_PAKE
            PSA_ALG_IS_JPAKE
            PSA_ALG_IS_SPAKE2P
            PSA_ALG_IS_SPAKE2P_HMAC
            PSA_ALG_IS_SPAKE2P_CMAC
            PSA_ALG_IS_WILDCARD
            PSA_ALG_IS_KEY_ENCAPSULATION
            PSA_ALG_IS_RSA_OAEP
            PSA_ALG_IS_RSA_PKCS1V15_SIGN
            PSA_ALG_IS_RSA_PSS
            PSA_ALG_IS_RSA_PSS_ANY_SALT
            PSA_ALG_IS_RSA_PSS_STANDARD_SALT
            PSA_ALG_IS_SP800_108_COUNTER_HMAC
            PSA_ALG_IS_TLS12_PRF
            PSA_ALG_IS_TLS12_PSK_TO_MS
            PSA_ALG_IS_VENDOR_TLS13

Composite Algorithm
"""""""""""""""""""
Some algorithms can be composed with a hash algorithm. The composite algorithm
is constructed by combining a base algorithm with a hash algorithm. The
following :c:macro:`PSA_ALG_GET_HASH` macro is used to extract the hash algorithm
embedded within the composite algorithm's encoding.

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_ALG_GET_HASH
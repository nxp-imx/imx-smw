ELE capabilities
================

Key manager
^^^^^^^^^^^

.. table:: ELE Key type
   :align: center
   :class: wrap-table

   +--------------+-----------------------------+
   | **Key type** | **Key security size(s)**    |
   +==============+=============================+
   | AES          | 128 / 192 / 256             |
   +--------------+-----------------------------+
   | ECDSA NIST   | 224 / 256 / 384 / 521       |
   +--------------+-----------------------------+
   | ECDSA BR1    | 224 / 256 / 384             |
   +--------------+-----------------------------+
   | HMAC         | 224 / 256 / 384 / 512       |
   +--------------+-----------------------------+

Operations supported:
 - Generate
 - Export (only public key in HEX or Base64 format)
 - Delete

Key group limitation:
Key group ID is hard-coded in SMW's ELE subsystem support. There is one group
for transient key and one for persistent key. As the number of keys per group is
limited by ELE, key generation may failed if the maximum number of keys is
reached.

Persistent key:
To flush persistent key, "FLUSH_KEY" attribute must be set. When set, ELE
executes a strict operation and all keys defined as persistent are flushed. Note
that ELE uses a strict operation counter which is a replay attack counter, then
the number of strict operation is limited. So when possible it's better to
perform multiple persistent key operations (generate, import) before setting the
"FLUSH_KEY" attribute.

Key policy
""""""""""
When creating a new key, the key policy must be specified through the operation
key attributes list. The key policy definition is defined with a **POLICY** TLV
:ref:`tlv_variable-length-list`.

The following :numref:`ele_key_usage` lists all key usages applicable in ELE
subsystem. A key policy defines one or more key usage.

.. table:: ELE Key usages
   :name: ele_key_usage
   :align: center
   :width: 100%
   :class: wrap-table

   +----------------+------------------------------------------------------+
   | **USAGE**      | **Description**                                      |
   +================+======================================================+
   | ENCRYPT        | Permission to encrypt a message                      |
   +----------------+------------------------------------------------------+
   | DECRYPT        | Permission to decrypt a message                      |
   +----------------+------------------------------------------------------+
   | SIGN_MESSAGE   | Permission to sign a message                         |
   +----------------+------------------------------------------------------+
   | SIGN_HASH      | Permission to sign a message hashed                  |
   +----------------+------------------------------------------------------+
   | VERIFY_MESSAGE | Permission to verify the signature of a message      |
   +----------------+------------------------------------------------------+
   | VERIFY_HASH    | Permission to verify the signature of message hashed |
   +----------------+------------------------------------------------------+
   | DERIVE         | Permission to derive other keys from this key        |
   +----------------+------------------------------------------------------+


The following :numref:`ele_permitted_algorithm` lists all permitted algorithms
applicable in ELE subsystem. Only one permitted algorithm is allowed per key.

The key permitted algorithm definition:

 - can be defines once with one of the key usages or repeated to each key usage.
 - if more than one permitted algorithm is given in the key policy (one different
   per key usage or several per key usage), only the first algorithm is retained,
   others are ignored.

.. table:: ELE Key permitted algorithm
   :name: ele_permitted_algorithm
   :align: center
   :widths: 25 12 25 38
   :width: 100%
   :class: wrap-table


   +----------------+----------+--------------------------+-------------------------------------+
   | **TLV Type**                                         | **Comment**                         |
   +----------------+----------+--------------------------+                                     +
   | **ALGO**       | **HASH** | **MIN_LENGTH**           |                                     |
   +                +          +                          +                                     +
   |                |          | **LENGTH**               |                                     |
   +================+==========+==========================+=====================================+
   | HMAC           | SHA256   | From 8 to 32 bytes       | If not specified length is 32 bytes |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA384   | From 8 to 48 bytes       | If not specified length is 48 bytes |
   +----------------+----------+--------------------------+-------------------------------------+
   | ECB_NO_PADDING | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | CBC_NO_PADDING | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | CTR            | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ALL_CIPHER     | N/A      | N/A                      | Support all ciphers including CMAC  |
   +----------------+----------+--------------------------+-------------------------------------+
   | CCM            | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ALL_AEAD       | N/A      | N/A                      | Support all AEAD                    |
   +----------------+----------+--------------------------+-------------------------------------+
   | RSA_PKCS1V15   | N/A      | N/A                      | Support all hash                    |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA1     | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA224   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA256   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA384   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA512   | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | RSA_PSS        | N/A      | N/A                      | Support all hash                    |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA1     | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA224   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA256   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA384   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA512   | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ECDSA          | SHA224   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA256   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA384   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA512   | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+


Hash
^^^^

.. table:: ELE Hash
   :align: center
   :class: wrap-table

   +--------------------+
   | **Hash Algorithm** |
   +====================+
   | SHA224             |
   +--------------------+
   | SHA256             |
   +--------------------+
   | SHA384             |
   +--------------------+
   | SHA512             |
   +--------------------+

Signature
^^^^^^^^^

.. table:: ELE Signature
   :name: ele_signature
   :align: center
   :widths: 20 27 25 28
   :width: 100%
   :class: wrap-table

   +--------------------+--------------------+--------------------------+-----------------------+
   | **Signature Type** | **Key type**       | **Key security size(s)** | **Hash algorithm**    |
   +====================+====================+==========================+=======================+
   | ECDSA              | ECDSA NIST         | 224 / 256 / 384 / 521    | SHA224                |
   +                    +                    +                          +                       +
   |                    |                    |                          | SHA256                |
   +                    +                    +                          +                       +
   |                    |                    |                          | SHA384                |
   +                    +                    +                          +                       +
   |                    |                    |                          | SHA512                |
   +                    +                    +                          +                       +
   |                    |                    |                          | None (Message hashed) |
   +                    +--------------------+--------------------------+-----------------------+
   |                    | ECDSA BRAINPOOL R1 |  224 / 256 / 384 / 521   | SHA224                |
   +                    +                    +                          +                       +
   |                    |                    |                          | SHA256                |
   +                    +                    +                          +                       +
   |                    |                    |                          | SHA384                |
   +                    +                    +                          +                       +
   |                    |                    |                          | None (Message hashed) |
   +--------------------+--------------------+--------------------------+-----------------------+

Operations supported:
 - Sign
 - Verify

Sign operation
""""""""""""""
The following key policies must defined:

  - Usage:

    - SIGN_MESSAGE to sign a message to be hashed
    - SIGN_HASH to sign a message already hashed

  - Algorithm:

    - for an ECDSA Signature, ECDSA with any hash or a hash already as listed
      in :numref:`ele_signature`

Verify operation
""""""""""""""""
The following key policies must defined if a key identifier is used:

  - Usage:

    - VERIFY_MESSAGE to verify the signature of a message to be hashed
    - VERIFY_HASH to verify the signature of a message already hashed

  - Algorithm:

  -  ECDSA with any hash or a hash already as listed in :numref:`ele_signature`


Random
^^^^^^

Length: 1 to UINT32_MAX

HMAC
^^^^

.. table:: ELE Hmac
   :align: center
   :class: wrap-table

   +--------------+--------------------+
   | **Key type** | **Hash algorithm** |
   +==============+====================+
   | HMAC         | SHA256             |
   +              +--------------------+
   |              | SHA384             |
   +--------------+--------------------+

The key policy must defined:

  - Usage: SIGN_MESSAGE
  - Algorithm: HMAC with SHA256 or SHA384

The MAC size can be truncated if the key permitted algorithm limits the
MAC output length.

Cipher
^^^^^^

.. table:: ELE Cipher
   :align: center
   :class: wrap-table

   +--------------+----------+
   | **Key type** | **Mode** |
   +==============+==========+
   | AES          |   CBC    |
   +              +          +
   |              |   ECB    |
   +              +          +
   |              |   CTR    |
   +--------------+----------+

One-shot operations supported:
 - Encrypt
 - Decrypt

Encrypt operation
"""""""""""""""""
The following key policies must defined:

  - Usage: ENCRYPT
  - Algorithm:

    - CBC_NO_PADDING
    - ECB_NO_PADDING
    - CTR
    - ALL_CIPHER (any cipher mode)

Decrypt operation
"""""""""""""""""
The following key policies must defined if a key identifier is used:

  - Usage: DECRYPT
  - Algorithm:

    - CBC_NO_PADDING
    - ECB_NO_PADDING
    - CTR
    - ALL_CIPHER (any cipher mode)

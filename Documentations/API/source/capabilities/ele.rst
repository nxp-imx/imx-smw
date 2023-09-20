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
 - Import (only EdgeLock 2GO object)
 - Export (only public key in HEX or Base64 format)
 - Delete
 - Get key attributes
 - Get key buffers' length
 - Get key security size
 - Get key type name
 - Commit key storage

Key group:
The SMW Library is managing the ELE key group automatically. The library is
selecting a key group depending if a key is persistent/permanent or transient.
  - Persistent/Permanent keys are in key groups from 0 to 49.
  - Transient keys are in key groups from 50 to 99.

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
   | CMAC           | N/A      | N/A                      |                                     |
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

MAC
^^^

.. table:: ELE MAC
   :align: center
   :class: wrap-table

   +--------------+--------------------------+----------------+
   | **Key type** | **Key security size(s)** | **Algorithm**  |
   +==============+==========================+================+
   | AES          | 128 / 192 / 256          | CMAC           |
   +              +                          +                +
   |              |                          | CMAC_TRUNCATED |
   +--------------+--------------------------+----------------+
   | HMAC         | 224 / 256 / 384 / 512    | HMAC           |
   +              +                          +                +
   |              |                          | HMAC_TRUNCATED |
   +--------------+--------------------------+----------------+

The MAC size can be truncated if the key permitted algorithm limits the
MAC output length.

Operations supported:
 - Compute MAC
 - Verify MAC

Compute MAC operation
"""""""""""""""""""""
MAC generation operation can compute either a full MAC length or a truncated
MAC length. The operation algorithm and key permitted algorithm allows to
select the MAC length to be generated.

 .. table:: ELE MAC - Compute
   :align: center
   :widths: 22 30 13 35
   :width: 100%
   :class: wrap-table

   +----------------+----------------+----------+-----------------------------+
   | **MAC Length** | **Algorithm**  | **Hash** | **Key policy**              |
   +================+================+==========+=============================+
   | Full MAC       | CMAC           | N/A      | Usage: SIGN_MESSAGE         |
   +                +                +          +                             +
   |                |                |          | Algorithm: CMAC             |
   +                +----------------+----------+-----------------------------+
   |                | HMAC           | SHA256   | Usage: SIGN_MESSAGE         |
   +                +                +          +                             +
   |                |                | SHA384   | Algorithm: HMAC with        |
   |                |                |          | HASH=[256/384]              |
   +----------------+----------------+----------+-----------------------------+
   | Truncated MAC  | CMAC_TRUNCATED | N/A      | Usage: SIGN_MESSAGE         |
   +                +                +          +                             +
   | Minimum length |                |          | Algorithm: CMAC with        |
   |                |                |          | MIN_LENGTH=[min]            |
   +                +----------------+----------+-----------------------------+
   |                | HMAC_TRUNCATED | SHA256   | Usage: SIGN_MESSAGE         |
   +                +                +          +                             +
   |                |                | SHA384   | Algorithm: HMAC with        |
   |                |                |          | HASH=[256/384]              |
   |                |                |          | and MIN_LENGTH=[min]        |
   +----------------+----------------+----------+-----------------------------+
   | Truncated MAC  | CMAC_TRUNCATED | N/A      | Usage: SIGN_MESSAGE         |
   +                +                +          +                             +
   | Fix length     |                |          | Algorithm: CMAC with        |
   |                |                |          | LENGTH=[length]             |
   +----------------+----------------+----------+-----------------------------+
   |                | HMAC_TRUNCATED | SHA256   | Usage: SIGN_MESSAGE         |
   +                +                +          +                             +
   |                |                | SHA384   | Algorithm: HMAC with        |
   |                |                |          | HASH=[256/384]              |
   |                |                |          | and LENGTH=[min]            |
   +----------------+----------------+----------+-----------------------------+

Verify MAC operation
""""""""""""""""""""
MAC verification operation can verify either a full MAC length or a truncated
MAC length. The operation algorithm and key permitted algorithm allows to
select the MAC length to be generated.

 .. table:: ELE MAC - Verify
   :align: center
   :widths: 22 30 13 35
   :width: 100%
   :class: wrap-table

   +----------------+----------------+----------+-----------------------------+
   | **MAC Length** | **Algorithm**  | **Hash** | **Key policy**              |
   +================+================+==========+=============================+
   | Full MAC       | CMAC           | N/A      | Usage: VERIFY_MESSAGE       |
   +                +                +          +                             +
   |                |                |          | Algorithm: CMAC             |
   +                +----------------+----------+-----------------------------+
   |                | HMAC           | SHA256   | Usage: VERIFY_MESSAGE       |
   +                +                +          +                             +
   |                |                | SHA384   | Algorithm: HMAC with        |
   |                |                |          | HASH=[256/384]              |
   +----------------+----------------+----------+-----------------------------+
   | Truncated MAC  | CMAC_TRUNCATED | N/A      | Usage: VERIFY_MESSAGE       |
   +                +                +          +                             +
   | Minimum length |                |          | Algorithm: CMAC with        |
   |                |                |          | MIN_LENGTH=[min]            |
   +                +----------------+----------+-----------------------------+
   |                | HMAC_TRUNCATED | SHA256   | Usage: VERIFY_MESSAGE       |
   +                +                +          +                             +
   |                |                | SHA384   | Algorithm: HMAC with        |
   |                |                |          | HASH=[256/384]              |
   |                |                |          | and MIN_LENGTH=[min]        |
   +----------------+----------------+----------+-----------------------------+
   | Truncated MAC  | CMAC_TRUNCATED | N/A      | Usage: VERIFY_MESSAGE       |
   +                +                +          +                             +
   | Fix length     |                |          | Algorithm: CMAC with        |
   |                |                |          | LENGTH=[length]             |
   +----------------+----------------+----------+-----------------------------+
   |                | HMAC_TRUNCATED | SHA256   | Usage: VERIFY_MESSAGE       |
   +                +                +          +                             +
   |                |                | SHA384   | Algorithm: HMAC with        |
   |                |                |          | HASH=[256/384]              |
   |                |                |          | and LENGTH=[min]            |
   +----------------+----------------+----------+-----------------------------+

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

Device management
^^^^^^^^^^^^^^^^^

The following operations are available:

  - Device Attestation
  - Device UUID (in big endian format)


The device attestation requires a challenge value to guaranty the certificate
request. The challenge value maximum length depends of the device as listed in
the following table.

.. table:: ELE Attestation Challenge
   :name: ele_challenge
   :align: center
   :class: wrap-table

   +------------+-------------------------------+
   | **Device** | **Challenge Length in bytes** |
   +============+===============================+
   | i.MX8ULP   |  4                            |
   +------------+-------------------------------+
   | i.MX93     |  16                           |
   +------------+-------------------------------+

Data Storage manager
^^^^^^^^^^^^^^^^^^^^

Data Storage manager allows to store and retreive data. The data ID is a 32-bits
value with the exception of the 0xF00000E0 reserved for EdgeLock 2GO claimcode.

The subsystem allows to:

  - store and retreive user data.
  - encrypt and sign data (:numref:`ele_data_encrypt`) before storing it and
    retreive a TLV blob (:numref:`ele_data_blob`).
  - set encypted and signed data as READ_ONCE, meaning that when data is
    retreived the subsystem deletes the data.

The subsystem doesn't allow to:

  - delete a data.

**Notes**:

  - Data size is limited to 2048 bytes.
  - Data size must be aligned on a cipher block in case of data encryption. in
    other word, user must pad to the data.
  - Data lifecycle can be defined only when storing encrypted/signed data.

.. table:: ELE Data Encrypt/Sign
   :name: ele_data_encrypt
   :align: center
   :class: wrap-table

   +----------------+--------+---------------+
   | **Encryption** | **IV** | **Signature** |
   +================+========+===============+
   | ECB_NO_PADDING |  N/A   |  CMAC         |
   +----------------+--------+               +
   | CBC_NO_PADDING |  Yes   |               |
   +----------------+--------+               +
   | CTR            |  Yes   |               |
   +----------------+--------+               +
   | CFB            |  Yes   |               |
   +----------------+--------+---------------+

.. table:: ELE Data blob (encrypted and signed)
   :name: ele_data_blob
   :align: center
   :width: 100%
   :class: wrap-table

   +---------+--------------------+-----------------------------------------+
   | **Tag** | **Length (bytes)** | **Value/Description**                   |
   +=========+====================+=========================================+
   | 0x41    | 16                 | Device UUID in big endian format.       |
   +---------+--------------------+-----------------------------------------+
   | 0x45    | 16                 | Value of the IV used to encrypt data    |
   |         |                    | in case encryption algorithm use an IV. |
   |         |                    | The IV can be either given as input by  |
   |         |                    | the user or randomly generated by the   |
   |         |                    | subsystem (user must the IV buffer and  |
   |         |                    | its length to 0).                       |
   +---------+--------------------+-----------------------------------------+
   | 0x46    | Variable           | Encrypted data. Maximum length is 2048  |
   |         |                    | bytes.                                  |
   +---------+--------------------+-----------------------------------------+

ELE capabilities
================

Key manager
^^^^^^^^^^^

.. table:: ELE Key type
   :align: center
   :class: wrap-table

   +--------------+-----------------------------+------------------------------+
   | **Key type** | **Key security size(s)**    |         **Devices**          |
   |              |                             +------+---------+------+------+
   |              |                             | 8ULP |  91/93  |  943 |  95  |
   +==============+=============================+======+=========+======+======+
   | AES          | 128 / 192 / 256             |  X   |   X     |  X   |  X   |
   +--------------+-----------------------------+------+---------+------+------+
   | Secp R1      | 224 / 256 / 384 / 521       |  X   |   X     |  X   |  X   |
   +--------------+-----------------------------+------+---------+------+------+
   | Brainpool R1 | 224 / 256 / 384             |  X   |   X     |  X   |  X   |
   +--------------+-----------------------------+------+---------+------+------+
   | HMAC         | 224 / 256 / 384 / 512       |  X   |   X     |  X   |      |
   +--------------+-----------------------------+------+---------+------+------+
   | RSA          | 2048 / 3072 / 4096          |      |   X     |  X   |  X   |
   +--------------+-----------------------------+------+---------+------+------+
   | ED25519PH    | 255                         |      |   X     |      |      |
   +--------------+-----------------------------+------+---------+------+------+
   | PURE EDDSA   | 255                         |      |   X     |      |      |
   +--------------+-----------------------------+------+---------+------+------+

Operations supported:
 - Generate
 - Import (only EdgeLock 2GO object)
 - Export (only public key in HEX or Base64 format)
 - Delete
 - `Key Derivation`_
 - Get key attributes
 - Get key buffers' length
 - Get key security size
 - Get key type name
 - Commit key storage
 - `Key attestation`_

Key group:

The SMW Library is managing the ELE key group automatically. The library is
selecting a key group depending if a key is persistent/permanent or transient.

- Persistent/Permanent keys are in key groups from 0 to 49.
- Transient keys are in key groups from 50 to 99.

Key policy
""""""""""
When creating a new key, the key policy must be specified through the operation
key attributes.

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

.. table:: ELE Key permitted algorithm
   :name: ele_permitted_algorithm
   :align: center
   :widths: 25 12 25 38
   :width: 100%
   :class: wrap-table


   +----------------+----------+--------------------------+-------------------------------------+
   | **ALGO**       | **HASH** | **MIN_LENGTH**           | **Comment**                         |
   +                +          +                          +                                     +
   |                |          | **LENGTH**               |                                     |
   +================+==========+==========================+=====================================+
   | HMAC           | SHA256   | From 8 to 32 bytes       | If not specified length is 32 bytes |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA384   | From 8 to 48 bytes       | If not specified length is 48 bytes |
   +----------------+----------+--------------------------+-------------------------------------+
   | CBC_NO_PADDING | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | CFB            | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | CTR            | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ECB_NO_PADDING | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ALL_CIPHER     | N/A      | N/A                      | Support all ciphers including CMAC  |
   +----------------+----------+--------------------------+-------------------------------------+
   | CCM            | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ALL_AEAD       | N/A      | N/A                      | Support all AEAD                    |
   +----------------+----------+--------------------------+-------------------------------------+
   | RSA PKCS1V15   | N/A      | N/A                      | Support all hash                    |
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
   | RSA PSS        | N/A      | N/A                      | Support all hash                    |
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
   | ATTEST_CMAC    | N/A      | N/A                      | Attestation restricted key          |
   +----------------+----------+--------------------------+-------------------------------------+
   | ATTEST_ECDSA   | SHA224   | N/A                      | Attestation restricted key          |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA256   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA384   | N/A                      |                                     |
   +                +----------+--------------------------+-------------------------------------+
   |                | SHA512   | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ALL EDDSA      | ANY      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | PURE EDDSA     | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+
   | ED25519PH      | N/A      | N/A                      |                                     |
   +----------------+----------+--------------------------+-------------------------------------+

Hash
^^^^

.. table:: ELE Hash
   :align: center
   :class: wrap-table

   +--------------------+-------------+
   | **Hash Algorithm** | **Devices** |
   |                    +------+------+
   |                    | 8ULP |  9x  |
   +====================+======+======+
   | MD5                |      |  X   |
   +--------------------+------+------+
   | SHA1               |      |  X   |
   +--------------------+------+------+
   | SHA224             |  X   |  X   |
   +--------------------+------+------+
   | SHA256             |  X   |  X   |
   +--------------------+------+------+
   | SHA384             |  X   |  X   |
   +--------------------+------+------+
   | SHA512             |  X   |  X   |
   +--------------------+------+------+
   | SHA3_224           |      |  X   |
   +--------------------+------+------+
   | SHA3_256           |      |  X   |
   +--------------------+------+------+
   | SHA3_384           |      |  X   |
   +--------------------+------+------+
   | SHA3_512           |      |  X   |
   +--------------------+------+------+

Operations supported:
 - One shot and multi-part

Signature
^^^^^^^^^

.. table:: ELE Signature
   :name: ele_signature
   :align: center
   :widths: 20 13 35 32
   :width: 100%
   :class: wrap-table

   +--------------------+--------------+--------------------------+-------------------------+
   | **Signature Type** | **Key type** | **Key security size(s)** | **Hash algorithm**      |
   +====================+==============+==========================+=========================+
   | ECDSA              | Secp R1      | 224 / 256 / 384 / 521    | - SHA224                |
   |                    |              |                          | - SHA256                |
   |                    |              |                          | - SHA384                |
   |                    |              |                          | - SHA512                |
   +                    +--------------+--------------------------+-------------------------+
   |                    | Brainpool R1 |  224 / 256 / 384         | - SHA224                |
   |                    |              |                          | - SHA256                |
   |                    |              |                          | - SHA384                |
   +--------------------+--------------+--------------------------+-------------------------+
   | RSA_PKCS1V15       | RSA          | 2048 / 3072 / 4096       | - SHA224                |
   |                    |              |                          | - SHA256                |
   |                    |              |                          | - SHA384                |
   |                    |              |                          | - SHA512                |
   +--------------------+--------------+--------------------------+-------------------------+
   | RSA_PSS            | RSA          | 2048 / 3072 / 4096       | - SHA224                |
   |                    |              |                          | - SHA256                |
   |                    |              |                          | - SHA384                |
   |                    |              |                          | - SHA512                |
   +--------------------+--------------+--------------------------+-------------------------+
   | PURE_EDDSA         | ED25519      | 255                      | None (Message hashed    |
   |                    |              |                          | or not)                 |
   +--------------------+--------------+--------------------------+-------------------------+
   | EDDSA_PH           | ED25519      | 255                      | None (pre-hashed)       |
   +--------------------+--------------+--------------------------+-------------------------+

Operations supported:
 - Sign
 - Verify

.. note::
  Message to sign/verify is full or hashed depending on the algorithm 64-bits
  word definition additional parameters (bits[39:32]).

Sign operation
""""""""""""""
The following key policies must defined:

  - Usage:

    - SIGN_MESSAGE to sign a message to be hashed
    - SIGN_HASH to sign a message already hashed

  - Algorithm:

    - ECDSA Signature with hash or a message already hashed as listed
      in :numref:`ele_signature`
    - RSA Signature, PKCS1 v1.5 and PSS with hash as listed
      in :numref:`ele_signature`. Not supported on i.MX8ULP
    - EDDSA Signature with hash or a message already hashed as listed
      in :numref:`ele_signature`. Not supported on i.MX8ULP and i.MX95

Verify operation
""""""""""""""""
The following key policies must defined if a key identifier is used:

  - Usage:

    - VERIFY_MESSAGE to verify the signature of a message to be hashed
    - VERIFY_HASH to verify the signature of a message already hashed

  - Algorithm:

    - ECDSA Signature with hash or a message already hashed as listed
      in :numref:`ele_signature`
    - RSA PKCS1 v1.5 and PSS with hash as listed in :numref:`ele_signature`.
      Not supported on i.MX8ULP
    - EDDSA Signature with hash or a message already hashed as listed
      in :numref:`ele_signature`. Not supported on i.MX8ULP and i.MX95

Random
^^^^^^
Length: 1 to UINT32_MAX

MAC
^^^

.. table:: ELE MAC
   :align: center
   :class: wrap-table

   +--------------+--------------+--------------------------+
   | **MAC Type** | **Key type** | **Key security size(s)** |
   +==============+==============+==========================+
   | CMAC         | AES          | 128 / 192 / 256          |
   +--------------+--------------+--------------------------+
   | HMAC         | HMAC         | 224 / 256 / 384 / 512    |
   +--------------+--------------+--------------------------+

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

   +-----------------+--------------+--------------------------+
   | **Cipher Mode** | **Key type** | **Key security size(s)** |
   +=================+==============+==========================+
   | ECB No Padding  | AES          | 128 / 192 / 256          |
   +-----------------+              +                          +
   | CBC No Padding  |              |                          |
   +-----------------+              +                          +
   | CTR             |              |                          |
   +-----------------+              +                          +
   | CFB             |              |                          |
   +-----------------+              +                          +
   | OFB             |              |                          |
   +-----------------+--------------+--------------------------+

One-shot operations supported:
 - Encrypt
 - Decrypt

Encrypt operation
"""""""""""""""""
The following key policies must defined:

  - Usage: ENCRYPT
  - Algorithm:

    - ECB_NO_PADDING
    - CBC_NO_PADDING
    - CFB
    - CTR
    - OFB
    - ALL_CIPHER (any cipher mode)

Decrypt operation
"""""""""""""""""
The following key policies must defined if a key identifier is used:

  - Usage: DECRYPT
  - Algorithm:

    - ECB_NO_PADDING
    - CBC_NO_PADDING
    - CFB
    - CTR
    - OFB
    - ALL_CIPHER (any cipher mode)

AEAD
^^^^

.. table:: ELE AEAD
   :align: center
   :widths: 30 12 43 15
   :width: 100%
   :class: wrap-table

   +------------------------+--------------+-----------------------------------------+----------------+
   | **AEAD Mode**          | **Key type** | **IV length**                           | **Tag length** |
   +                        +              +                                         +                +
   |                        |              | **(bytes)**                             | **(bytes)**    |
   +========================+==============+=========================================+================+
   | CCM                    | AES          | 12                                      |       16       |
   +------------------------+              +-----------------------------------------+----------------+
   | GCM [1]_               |              | Encryption:                             |       16       |
   |                        |              |                                         |                |
   |                        |              | - 0 (subsystem generates full IV)       |                |
   |                        |              | - 4 (subsystem generates 8 bytes of IV) |                |
   |                        |              | - 12 (user supplied full IV)            |                |
   +                        +              +-----------------------------------------+                +
   |                        |              | Decryption:                             |                |
   |                        |              |                                         |                |
   |                        |              | - 12 (user supplied full IV)            |                |
   +------------------------+              +-----------------------------------------+----------------+
   | CHACHA20_POLY1305 [2]_ |              | 12                                      |       16       |
   +------------------------+--------------+-----------------------------------------+----------------+

.. [1] Not supported on i.MX8ULP

.. [2] Currently supported on i.MX91 and i.MX93

One-shot operations supported:
 - AEAD Encryption
 - AEAD Decryption


Device management
^^^^^^^^^^^^^^^^^
The following operations are available:

  - Device Attestation
  - Device UUID (in big endian format)
  - Device lifecycle


Device Attestation
""""""""""""""""""
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
   | 8ULP       |  4                            |
   +------------+-------------------------------+
   | 9x         |  16                           |
   +------------+-------------------------------+


Device lifecycle
""""""""""""""""
The device lifecycle operations supported are get and set device lifecycle.
The following table lists the device lifecycle supported when executing a
get or set device lifecycle.

.. warning::
  Changing the device lifecycle (set operation) is not revertable. Refer to
  the device documentation to get more details about the lifecycle.

.. table:: ELE Device lifecycle
   :name: ele_lifecycle
   :widths: 22 10 10 58
   :width: 100%
   :class: wrap-table

   +---------------+---------+---------+------------------------------------+
   | **Lifecycle** | **Get** | **Set** | **Comment**                        |
   +===============+=========+=========+====================================+
   | OPEN          |   Yes   |   Yes   |                                    |
   +---------------+---------+---------+------------------------------------+
   | CLOSED        |   Yes   |   Yes   | A signed image is required to boot |
   +---------------+---------+---------+------------------------------------+
   | CLOSED_LOCKED |   Yes   |   Yes   | A signed image is required to boot |
   +---------------+---------+---------+------------------------------------+
   | OEM_RETURN    |   No    |   Yes   | Device is no more OEM usable and   |
   |               |         |         | must be returned to NXP            |
   +---------------+---------+---------+------------------------------------+
   | NXP_RETURN    |   No    |   Yes   | Device is no more usable and       |
   |               |         |         | must be returned to NXP            |
   +---------------+---------+---------+------------------------------------+

Operation context
^^^^^^^^^^^^^^^^^

Operations supported:
 - Allocate
 - Cancel

Data Storage manager
^^^^^^^^^^^^^^^^^^^^

Data Storage manager allows to store and retrieve data. The data ID is a 32-bits
value with the exception of the 0xF00000E0 reserved for EdgeLock 2GO claimcode.

The subsystem allows to:

  - store, retrieve and delete user data.
  - encrypt and sign data (:numref:`ele_data_encrypt`) before storing it and
    retrieve a TLV blob (:numref:`ele_data_blob`).
  - set encrypted and signed data as READ_ONCE, meaning that when data is
    retrieved the subsystem deletes the data.

.. note::
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
   | ECB No Padding |  N/A   |  CMAC         |
   +----------------+--------+               +
   | CBC No Padding |  Yes   |               |
   +----------------+--------+               +
   | CFB            |  Yes   |               |
   +----------------+--------+               +
   | CTR            |  Yes   |               |
   +----------------+--------+---------------+

.. table:: ELE Data blob (encrypted and signed)
   :name: ele_data_blob
   :align: center
   :widths: 10 20 70
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

.. _key_attestation:

Key attestation
^^^^^^^^^^^^^^^
Key attestation only applies to the public key of asymmetric keys.

The subsystem allows to attest a public key of an asymmetric key present in
the subsystem key storage.

The public key attestation results in a certificate encoded as a signed TLV buffer,
in the table below (:numref:`key_attest_cert`):

.. table:: Key attestation certificate
   :name: key_attest_cert
   :align: center
   :widths: 10 20 70
   :width: 100%
   :class: wrap-table

   +---------+--------------------+-----------------------------------------+
   | **Tag** | **Length (bytes)** | **Value/Description**                   |
   +=========+====================+=========================================+
   | 0x41    | 4                  | Identifier, in the subsystem, of the    |
   |         |                    | key to attest.                          |
   +---------+--------------------+-----------------------------------------+
   | 0x42    | 4                  | Key permitted algorithm.                |
   +---------+--------------------+-----------------------------------------+
   | 0x43    | 4                  | Key usage flags.                        |
   +---------+--------------------+-----------------------------------------+
   | 0x44    | 2                  | Type of key.                            |
   +---------+--------------------+-----------------------------------------+
   | 0x45    | 4                  | Key security size in bits.              |
   +---------+--------------------+-----------------------------------------+
   | 0x46    | 4                  | Lifetime.                               |
   +---------+--------------------+-----------------------------------------+
   | 0x50    | Variable           | Input value chosen by the user, could   |
   |         |                    | be a random or the current data/time.   |
   +---------+--------------------+-----------------------------------------+
   | 0x51    | 4                  | Key identifier in the subsystem of the  |
   |         |                    | key used to attest the public key       |
   |         |                    | (sign this TLV).                        |
   +---------+--------------------+-----------------------------------------+
   | 0x52    | Variable           | Public key buffer.                      |
   +---------+--------------------+-----------------------------------------+
   | 0x53    | 1                  | Information about the key origin:       |
   |         |                    |                                         |
   |         |                    | - 0x01: Key has been generated by the   |
   |         |                    |   device.                               |
   |         |                    |                                         |
   |         |                    | - 0x02: Key has been imported into the  |
   |         |                    |   device.                               |
   +---------+--------------------+-----------------------------------------+
   | 0x54    | 16                 | Device UUID.                            |
   +---------+--------------------+-----------------------------------------+
   | 0x55    | 4                  | Key lifecycle usage flags:              |
   |         |                    |                                         |
   |         |                    | - OPEN: 0x01.                           |
   |         |                    |                                         |
   |         |                    | - CLOSED: 0x02.                         |
   |         |                    |                                         |
   |         |                    | - CLOSED_LOCKED: 0x04.                  |
   +---------+--------------------+-----------------------------------------+
   | 0x56    | 4                  | Algorithm used to sign the blob itself. |
   |         |                    | Field "Signature" of this blob.         |
   |         |                    |                                         |
   |         |                    | Possible values are:                    |
   |         |                    |                                         |
   |         |                    | - 0x01: CMAC.                           |
   |         |                    |                                         |
   |         |                    | - 0x02: ECDSA (hash of the payload must |
   |         |                    |   be the same as the signature key      |
   |         |                    |   size).                                |
   +---------+--------------------+-----------------------------------------+
   | 0x5E    | Variable           | Signature of all previous fields of     |
   |         |                    | this blob including the signature tag   |
   |         |                    | (0x5E) and signature length fields.     |
   +---------+--------------------+-----------------------------------------+

Storage Re-provisioning
^^^^^^^^^^^^^^^^^^^^^^^

This operation allows to reset and re-fill a new non-volatile storage that
has been rollback protected (using the commit operation).
This operation requires a specific tool called CST to sign the ELE Secure
Enclave re-provisioning request. The signature key is correlated to the
OEM SRKH fused.
CST tool can be downloaded from https://www.nxp.com/webapp/sps/download/license.jsp?colCode=IMX_CST_TOOL_NEW
or from https://gitlab.apertis.org/pkg/imx-code-signing-tool as sources.

The SMW library offers the possibility to create the message payload to be
signed with the CST tools (see :ref:smw_device_reprovision_prepare). The
buffer returned must be signed with CST tool and given as parameter of the
:ref:smw_device_reprovision API.

.. note::
  The OEM SRKH must be fused.

Key Derivation
^^^^^^^^^^^^^^

- TLS 1.2 (TLS1-PRF)

The subsystem supports generating the master secret, encryption/decryption
keys and IVs, and verify data. ELE does not allow some operations on data with
length less than the key size, so the key size of the base key used for ECDH(E)
dictates which ciphersuites can be used. For example, if the key size is 384
bits, you may only use ciphersuites that use SHA384.

Only ECDH(E) key exchange is supported, and the following ciphersuites:

.. table:: ELE supported ciphersuites
   :name: ele_ciphersuites
   :align: center
   :width: 100%
   :class: wrap-table

   +--------------------------------------+-------------------------------+
   | **SMW encryption name**              | **OpenSSL equivalent**        |
   +======================================+===============================+
   | SMW_TLS12_ENC_NAME_AES_128_CBC       | ECDHE-ECDSA-AES128-SHA256     |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_128_CCM       | ECDHE-ECDSA-AES128-CCM        |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_128_GCM       | ECDHE-ECDSA-AES128-GCM-SHA256 |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_256_CBC       | ECDHE-ECDSA-AES256-SHA384     |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_256_CCM       | ECDHE-ECDSA-AES256-CCM        |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_256_GCM       | ECDHE-ECDSA-AES256-GCM-SHA384 |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_CHACHA20_POLY1305 | ECDHE-ECDSA-CHACHA20-POLY1305 |
   +--------------------------------------+-------------------------------+

- TLS 1.3 (TLS13-KDF)

The early secret, ECDH shared secret, handshake secret and master secret are
computed internally and not exported. The subsystem supports derivation of the
following TLS1.3 secrets:

.. table:: ELE TLS1.3 secrets
   :name: ele_tls13_secrets
   :align: center
   :class: wrap-table

   +-------------------------------------+------------------------------------+
   | **TLS1.3 secret name**              | **Label without null termination** |
   +=====================================+====================================+
   | Binder key                          | "ext binder" or "res binder"       |
   +-------------------------------------+------------------------------------+
   | Client early traffic secret         | "c e traffic"                      |
   +-------------------------------------+------------------------------------+
   | Early exporter master secret        | "e exp master"                     |
   +-------------------------------------+------------------------------------+
   | Client handshake traffic secret     | "c hs traffic"                     |
   +-------------------------------------+------------------------------------+
   | Server handshake traffic secret     | "s hs traffic"                     |
   +-------------------------------------+------------------------------------+
   | Client application traffic secret 0 | "c ap traffic"                     |
   +-------------------------------------+------------------------------------+
   | Server application traffic secret 0 | "s ap traffic"                     |
   +-------------------------------------+------------------------------------+
   | Exporter master secret              | "exp master"                       |
   +-------------------------------------+------------------------------------+
   | Resumption master secret            | "res master"                       |
   +-------------------------------------+------------------------------------+

After the required secret is computed, the TLS1.3 API may be used to
further derive other keys and IVs, as required by `RFC 8446 <https://www.rfc-editor.org/rfc/rfc8446/>`_.

Any keys that are derived from these secrets need to have the proper attributes
set before doing the derivation. For example, from "s hs traffic", you may
derive an AES-128-GCM key to decrypt data and an HMAC-256 key to compute
the Finished data. In both cases, the key type, size, algorithm and usage
need to be set for the derived key.

.. note::
  Only supported on i.MX91 and i.MX93

ELE capabilities
================

Key manager
-----------

.. table:: ELE Key type
   :align: center
   :class: wrap-table

   +--------------------+--------------------------+--------------------------------+
   | **Key type**       | **Key security size(s)** |         **Devices**            |
   |                    |                          +------+---------+------+--------+
   |                    |                          | 8ULP |  91/93  |  943 | 95/952 |
   +====================+==========================+======+=========+======+========+
   | AES                | 128 / 192 / 256          |  X   |   X     |  X   |  X     |
   +--------------------+--------------------------+------+---------+------+--------+
   | Secp R1            | 224 / 256 / 384 / 521    |  X   |   X     |  X   |  X     |
   +--------------------+--------------------------+------+---------+------+--------+
   | Brainpool R1       | 224 / 256 / 384          |  X   |   X     |  X   |  X     |
   +--------------------+--------------------------+------+---------+------+--------+
   | HMAC               | 224 / 256 / 384 / 512    |  X   |   X     |  X   |  X     |
   +--------------------+--------------------------+------+---------+------+--------+
   | RSA                | 2048 / 3072 / 4096       |      |   X     |  X   |  X     |
   +--------------------+--------------------------+------+---------+------+--------+
   | ED25519            | 255                      |      |   X     |      |  X [1]_|
   +--------------------+--------------------------+------+---------+------+--------+
   | ED448              | 448                      |      |   X     |      |  X [1]_|
   +--------------------+--------------------------+------+---------+------+--------+
   | X25519             | 255                      |      |   X     |      |  X     |
   +--------------------+--------------------------+------+---------+------+--------+
   | X448               | 448                      |      |   X     |      |  X     |
   +--------------------+--------------------------+------+---------+------+--------+
   | EL2GO_PROV_OEM_KEY | N/A                      |      |   X     |      |  X     |
   +--------------------+--------------------------+------+---------+------+--------+

.. [1] Pre-Hashed signature is not supported on i.MX95 and i.MX952.

.. note:: The `EL2GO_PROV_OEM_KEY` key type is limited to the EdgeLock 2GO
  key import of the OEM Shared secret.

Operations supported:
 - Generate
 - `Key Import`_
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
^^^^^^^^^^
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
   :widths: 28 12 22 38
   :width: 100%
   :class: wrap-table


   +----------------------+----------+--------------------------+-------------------------------------+
   | **ALGO**             | **HASH** | **MIN_LENGTH**           | **Comment**                         |
   +                      +          +                          +                                     +
   |                      |          | **LENGTH**               |                                     |
   +======================+==========+==========================+=====================================+
   | HMAC                 | SHA256   | From 8 to 32 bytes       | If not specified length is 32 bytes |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA384   | From 8 to 48 bytes       | If not specified length is 48 bytes |
   +----------------------+----------+--------------------------+-------------------------------------+
   | CBC_NO_PADDING       | N/A      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | CFB                  | N/A      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | CTR                  | N/A      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ECB_NO_PADDING       | N/A      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | OFB                  | N/A      | N/A                      | Not supported on i.MX8ULP           |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ALL_CIPHER           | N/A      | N/A                      | Support all ciphers including CMAC  |
   +----------------------+----------+--------------------------+-------------------------------------+
   | CCM                  | N/A      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ALL_AEAD             | N/A      | N/A                      | Support all AEAD                    |
   +----------------------+----------+--------------------------+-------------------------------------+
   | RSA PKCS1V15         | N/A      | N/A                      | Support all hash                    |
   +                      +----------+--------------------------+-------------------------------------+
   | Asymmetric Signature | SHA1     | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA224   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA256   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA384   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA512   | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | RSA PSS              | N/A      | N/A                      | Support all hash                    |
   +                      +----------+--------------------------+-------------------------------------+
   | Asymmetric Signature | SHA1     | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA224   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA256   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA384   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA512   | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | RSA PKCS1V15         | N/A      | N/A                      |                                     |
   +                      +          +                          +                                     +
   | Asymmetric Encryption|          |                          |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | RSA OAEP             | N/A      | N/A                      | Support all hash                    |
   +                      +----------+--------------------------+-------------------------------------+
   | Asymmetric Encryption| SHA1     | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA224   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA256   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA384   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA512   | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | RSA PKCS1 ANY        | N/A      | N/A                      | Support any RSA Asymmetric          |
   +                      +          +                          +                                     +
   | Asymmetric Encryption|          |                          | Encryption                          |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ECDSA                | SHA224   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA256   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA384   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA512   | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | CMAC                 | N/A      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ATTEST_CMAC          | N/A      | N/A                      | Attestation restricted key          |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ATTEST_ECDSA         | SHA224   | N/A                      | Attestation restricted key          |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA256   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA384   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA512   | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ALL EDDSA            | ANY      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | PURE EDDSA           | N/A      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ED25519PH            | N/A      | N/A                      | Not supported on i.MX95             |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ED448PH              | N/A      | N/A                      | Not supported on i.MX95             |
   +----------------------+----------+--------------------------+-------------------------------------+
   | TLS1_3_MASTER_SECRET | SHA256   | N/A                      | Derivation restricted key           |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | SHA384   | N/A                      |                                     |
   +                      +----------+--------------------------+-------------------------------------+
   |                      | N/A      | N/A                      | Support all hash                    |
   +----------------------+----------+--------------------------+-------------------------------------+
   | ECDH HKDF            | SHA256   | N/A                      | Key agreement                       |
   +                      +----------+--------------------------+                                     +
   |                      | SHA384   | N/A                      |                                     |
   +                      +----------+--------------------------+                                     +
   |                      | ANY      | N/A                      |                                     |
   +----------------------+----------+--------------------------+-------------------------------------+
   | CKDF                 | N/A      | N/A                      | Custom Key Derivation Function.     |
   |                      |          |                          | Allow importing EL2GO OEM Secret Key|
   +----------------------+----------+--------------------------+-------------------------------------+


Hash
----

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
   | SHAKE256           |      |  X   |
   +--------------------+------+------+

Operations supported:
 - One shot and multi-part

.. note::
  The SHAKE256 is an extendable-output function (XOF) where digest length can
  be any length as detailed in the `FIPS 202<https://doi.org/10.6028/NIST.FIPS.202>`.


Signature
---------

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
   | PURE_EDDSA         | ED25519      | 255                      | None (Message)          |
   |                    +--------------+--------------------------+-------------------------+
   |                    | ED448        | 448                      | None (Message)          |
   +--------------------+--------------+--------------------------+-------------------------+
   | ED25519PH          | ED25519      | 255                      | None (pre-hashed)       |
   +--------------------+--------------+--------------------------+-------------------------+
   | ED448PH            | ED448        | 448                      | None (pre-hashed)       |
   +--------------------+--------------+--------------------------+-------------------------+

Operations supported:
 - Sign One-shot and Multi-part
 - Verify One-shot and Multi-part

.. note::
  Message to sign/verify is full or hashed depending on the algorithm 64-bits
  word definition additional parameters (bits[39:32]).

.. caution::
  Signature Multi-part is supported only if the hash operation is enabled.

Sign operation
^^^^^^^^^^^^^^
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
      in :numref:`ele_signature`. Not supported on i.MX8ULP, i.MX943 and i.MX95.

  - Opaque key or a plaintext key buffer are supported. Signature generation
    using plaintext key buffer:

    - For an EC key pair (Secp R1 and Twisted edwards), private key buffer
      must be set.
    - For RSA key pair, private key and modulus buffers must be set.
      ELE subsystem only supports RSA key pairs with default public
      exponent of 0x010001.

Verify operation
^^^^^^^^^^^^^^^^
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
      in :numref:`ele_signature`. Not supported on i.MX8ULP, i.MX943 and i.MX95.

  - Opaque key or a plaintext key buffer are supported. Signature verification
    using plaintext key buffer:

    - For an EC key pair (Secp R1 and Twisted edwards), public key buffer
      must be set.
    - For RSA key, public exponent and modulus buffer must be set.
      ELE subsystem only supports RSA key pairs with default public
      exponent of 0x010001.

Random
------
Length: 1 to UINT32_MAX

MAC
---

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
^^^^^^^^^^^^^^^^^^^^^^
MAC generation operation can compute either a full MAC length or a truncated
MAC length. The operation algorithm and key permitted algorithm allows to
select the MAC length to be generated.

ELE subsystem supports MAC operation using either a key ID or a plaintext key buffer.

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
^^^^^^^^^^^^^^^^^^^^
MAC verification operation can verify either a full MAC length or a truncated
MAC length. The operation algorithm and key permitted algorithm allows to
select the MAC length to be generated.

ELE subsystem supports MAC operation using either a key ID or a plaintext key buffer.

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
------

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
^^^^^^^^^^^^^^^^^
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
^^^^^^^^^^^^^^^^^
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
----

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
   | GCM [2]_               |              | Encryption:                             |       16       |
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

.. [2] Not supported on i.MX8ULP

.. note::
  The ELE subsystem supports AEAD encryption and decryption using either a key identifier or a plaintext key buffer.

One-shot operations supported:
 - AEAD Encryption
 - AEAD Decryption

Asymmetric encryption and decryption
------------------------------------

.. table:: ELE Asymmetric encryption and decryption
   :align: center
   :widths: 20 13 35 32
   :width: 100%
   :class: wrap-table

   +--------------------+--------------+-----------------------------+--------------------------+
   |**Encryption mode** | **Key type** | **Key security size(s)**    | **Hash algorithm**       |
   +====================+==============+=============================+==========================+
   | OAEP               | RSA          |  2048 / 3072 / 4096         | - SHA1                   |
   |                    |              |                             | - SHA224                 |
   |                    |              |                             | - SHA256                 |
   |                    |              |                             | - SHA384                 |
   |                    |              |                             | - SHA512                 |
   +--------------------+--------------+-----------------------------+--------------------------+
   | PKCS1V15           | RSA          |  2048 / 3072 / 4096         |  N/A                     |
   +--------------------+--------------+-----------------------------+--------------------------+

Operations supported:
 - Encryption
 - Decryption

.. note::
  - Asymmetric encryption and decryption operations are not supported on i.MX8ULP and i.MX943.

Device management
-----------------
The following operations are available:

  - Device Attestation
  - Device UUID (in big endian format)
  - Device lifecycle


Device Attestation
^^^^^^^^^^^^^^^^^^
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
^^^^^^^^^^^^^^^^
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
-----------------

Operations supported:
 - Allocate
 - Cancel

Data Storage manager
--------------------

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
---------------
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
-----------------------
This operation allows to reset and re-fill a new non-volatile storage that
has been rollback protected (using the commit operation).
This operation requires a specific tool to sign the ELE Secure
Enclave re-provisioning message. The signature key is correlated to the
OEM SRKH fused.

The NXP SPSDK tool can be used to sign the message and can be installed from
`SPSK releases <https://github.com/nxp-mcuxpresso/spsdk/releases>`_.
The documentation is available `here <https://spsdk.readthedocs.io/en/latest/index.html>`_.
The command used to sign is `nxpimage <https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html#nxpimage-signed-msg>`_.


The SMW library offers the possibility to create the message payload to be
signed (see :c:func:`smw_device_reprovision_prepare`).
The :c:func:`smw_device_reprovision` API will take as input the resulting
signed message.

.. note::
  The OEM SRKH must be fused.

Key Derivation
--------------
TLS 1.2 (TLS1-PRF)
^^^^^^^^^^^^^^^^^^
The subsystem supports generating the master secret, encryption/decryption
keys and IVs, and verify data. ELE does not allow some operations on data with
length less than the key size, so the key size of the base key used for ECDH(E)
dictates which ciphersuites can be used. For example, if the key size is 384
bits, you may only use ciphersuites that use SHA384.

Only ECDH(E) key exchange is supported, with SECP_R1 key type, and the following
ciphersuites:

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

TLS 1.3 (TLS13-KDF)
^^^^^^^^^^^^^^^^^^^
The early secret, ECDH shared secret, handshake secret and master secret are
computed internally and not exported. The SECP_R1, X25519 and X448 key types are
supported. The subsystem supports derivation of the following TLS1.3 secrets:

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
further derive other keys and IVs, as required by `RFC8446 <https://www.rfc-editor.org/rfc/rfc8446>`_.

Any keys that are derived from these secrets need to have the proper attributes
set before doing the derivation. For example, from "s hs traffic", you may
derive an AES-128-GCM key to decrypt data and an HMAC-256 key to compute
the Finished data. In both cases, the key type, size, algorithm and usage
need to be set for the derived key.

.. note::
  Only supported on i.MX91, i.MX93 and i.MX95

OEM Master key
^^^^^^^^^^^^^^
The OEM Master key is a key agreement between a secure host ECDSA key and a
device ECDSA key. The resulting key is a symmetric key used to derive two keys:

  - A wrap key to wrap secure key to import
  - A sign key to sign EdgeLock Enclave blob including the wrapped key and
    its attributes.

The OEM Master key requests a EdgeLock Enclave signed message to authenticate
the key attributes and derivation parameters.

The SMW library offers the possibility to pre-fill the message payload to be
signed (see :ref:smw_kdf_oem_master_key_args).

The NXP SPSDK tool can be used to sign the message and can be installed from
`SPSDK releases <https://github.com/nxp-mcuxpresso/spsdk/releases>`_.
The documentation is available `here <https://spsdk.readthedocs.io/en/latest/index.html>`_.
The command used to sign is `nxpimage <https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html#nxpimage-signed-msg>`_.


The OEM Master key attributes are almost pre-defined, the following
:numref:`oem_mk_attributes` lists the value to set in the signed payload
and the SMW key attributes.

The signed payload defined also a ``derived key group`` field where the key
will be stored. Value must be in the range [0:99]
SMW defined 2 groups range function of the key persistency:

  - 0:49 Groups of the persistent keys
  - 50:99 Groups of the transient keys

It's impossible during runtime to predict the group number where the key could
be stored if other keys are already present in the ELE NVM Secure Storage.
If the key group can't be known in advance, it's adviced to use the SMW
operation pre-filling the payload content (see :ref:`smw_kdf_oem_master_key_args`)
that will try to find a key group number where the key could be stored. Note,
even that, it's not 100% guaranty that the key group will have enough place to
store the key at the time the key derivation operation will be requested.

It's adviced to store this key as persistent key with a known key identifier.
In case of transient key the ELE FW will assign the key identifier after key
derivation operation success.

.. table:: OEM Master key attributes
   :name: oem_mk_attributes
   :align: center
   :class: wrap-table

   +----------------------+------------+-------------------------------------------+
   | Key attributes       | ELE value  | SMW value                                 |
   +======================+============+===========================================+
   | Key type             | 0x9200     | SMW_KEY_TYPE_NAME_DERIVE                  |
   +----------------------+------------+-------------------------------------------+
   | Security size (bits) | 256        | 256                                       |
   +----------------------+------------+-------------------------------------------+
   | Usage                | 0x00004000 | SMW_ATTR_USAGE_DERIVE                     |
   +----------------------+------------+-------------------------------------------+
   | Permitted algorithm  | 0x0800109  | SMW_ATTR_ALGO_KEY_DERIVATION_HKDF(SHA256) |
   +----------------------+------------+-------------------------------------------+
   | Lifetime             | 0x00000000 | SMW_ATTR_PERSISTENCE_TRANSIENT flag       |
   +                      +------------+-------------------------------------------+
   |                      | 0x00000001 | SMW_ATTR_PERSISTENCE_PERSISTENT flag      |
   +----------------------+------------+-------------------------------------------+
   | Lifecycle flags      | 0x00       | SMW_ATTR_LIFECYCLE_CURRENT                |
   +                      +------------+-------------------------------------------+
   |                      | 0x01       | SMW_ATTR_LIFECYCLE_OPEN                   |
   +                      +------------+-------------------------------------------+
   |                      | 0x02       | SMW_ATTR_LIFECYCLE_CLOSED                 |
   +                      +------------+-------------------------------------------+
   |                      | 0x03       | SMW_ATTR_LIFECYCLE_CLOSED_LOCKED          |
   +----------------------+------------+-------------------------------------------+

.. note::
  The OEM SRKH must be fused.

.. note::
  Only supported on i.MX8ULP, i.MX91 and i.MX93

Key Import
^^^^^^^^^^
ELE supports only key importation using trusted blob like EdgeLock 2GO blob and
EdgeLock Enclave blob.

EdgeLock 2GO blob
^^^^^^^^^^^^^^^^^
This service is a NXP service involving the EdgeLock 2GO server. The server
allows to provision key and data using blob created function of the device UUID
and OEM SRKH fused in the device. Visit `EdgeLock 2GO <http://www.nxp.com/edgelock2go>`_

EdgeLock Enclave blob
^^^^^^^^^^^^^^^^^^^^^
This service is a NXP service provided by the EdgeLock Enclave Firmware.
A EdgeLock Enclave blob is used to import the secure key. The blob contains the
key attributes, the wrapped key (AES CBC pad or ) and a blob signature (CMAC).

The wrapping key and the signing key are both derived from the
`OEM Master key`_. On device both keys are derived and kept internal, on
host side, the OEM Master key, the wrapping key and signing key must be
derived using the HMAC two steps standard
`RFC5869 <https://datatracker.ietf.org/doc/html/rfc5869.html>`_.

OEM import wrap and cmac keys derivation parameters:

  - The salt used in the first step: extract can be either:

    - A zeros string. Its length, in bytes, is equal to the hash algorithm
      (used in the key derivation process) length byte size.
    - Device SRKH. As salt length is the hash algorithm
      (used in the key derivation process) length byte size, device SRKH value
      could be truncated or concatenated with 0s to match the required salt length.
  - The IKM is the `OEM Master key`_ shared secret key
  - The fixed info in a byte string imposed by EdgeLock Secure Enclave Firmware.
    It differs switch derived key:

    - For wrapping key, fixed info is: “oemelefwkeyimportwrap256” string
      (quotation marks not included).
    - For signing key, fixed info is: “oemelefwkeyimportcmac256” string
      (quotation marks not included).
  - The key derivation algorithm is imposed by EdgeLock Secure Enclave
    Firmware as HKDF_SHA256.

The EdgeLock Enclave blob is encoded as described in :numref:`ele_import_blob`.

.. table:: EdgeLock Enclave blob
   :name: ele_import_blob
   :align: center
   :widths: 13 13 9 11 54
   :width: 100%
   :class: wrap-table

   +----------------------------+------+----------+------------------------------------------------------------------+
   | Field                      | TAG  | Length   | Description / Value                                              |
   |                            |      |          |                                                                  |
   |                            |      | (bytes)  |                                                                  |
   +============================+======+==========+==================================================================+
   | Magic                      | 0x40 | 21       | EdgeLock Secure Enclave identification blob.                     |
   |                            |      |          |                                                                  |
   |                            |      |          | Value is the hexadecimal string “edgelockenclaveimport”.         |
   |                            |      |          |                                                                  |
   |                            |      |          | [65 64 67 65 6c 6f 63 6b 65 6e 63 6c 61 76 65 69 6d 70 6f 72 74] |
   +----------------------------+------+----------+------------------------------------------------------------------+
   | Key ID                     | 0x41 | 4        | Key identifier in the subsystem:                                 |
   |                            |      |          |                                                                  |
   |                            |      |          |  - 0x0 if the key is transient.                                  |
   |                            |      |          |  - between 0x1 and 0x3FFFFFFF if the key is persistent.          |
   +----------------+-----------+------+----------+------------------------------------------------------------------+
   |                | Algorithm | 0x42 | 4        | ELE key permitted algorithm.                                     |
   +                +-----------+------+----------+------------------------------------------------------------------+
   | Key properties | Usage     | 0x43 | 4        | ELE key usage flags.                                             |
   +                +-----------+------+----------+------------------------------------------------------------------+
   |                | Type      | 0x44 | 2        | ELE Type of key.                                                 |
   +                +-----------+------+----------+------------------------------------------------------------------+
   |                | Bits      | 0x45 | 4        | Key security size in bits.                                       |
   +                +-----------+------+----------+------------------------------------------------------------------+
   |                | Lifetime  | 0x46 | 4        | ELE Lifetime:                                                    |
   |                |           |      |          |                                                                  |
   |                |           |      |          |  - 0xC0020000, transient key                                     |
   |                |           |      |          |  - 0xC0020001, persistent key                                    |
   |                |           |      |          |  - 0xC00200FF, permanent key                                     |
   +----------------+-----------+------+----------+------------------------------------------------------------------+
   | Key lifecycle              | 0x47 | 4        | ELE device lifecycle flags when key is usable:                   |
   |                            |      |          |                                                                  |
   |                            |      |          |  - OPEN: 0x01                                                    |
   |                            |      |          |  - CLOSED: 0x02                                                  |
   |                            |      |          |  - CLOSED_LOCKED: 0x04                                           |
   +----------------------------+------+----------+------------------------------------------------------------------+
   | OEM Master key identifier  | 0x50 | 4        | OEM Master key identifier resulting `OEM Master key`_.           |
   +----------------------------+------+----------+------------------------------------------------------------------+
   | Wrapping algorithm         | 0x51 | 4        | Wrapping algorithm of the key blob. This field is required to    |
   |                            |      |          | distinguish between different flavors of wrapping algorithms.    |
   |                            |      |          | Possible values are:                                             |
   |                            |      |          |                                                                  |
   |                            |      |          |  - 0x01: RFC 3394 wrapping.                                      |
   |                            |      |          |  - 0x02: AES-CBC wrapping (padding cipher, ISO7816-4 Appendix C).|
   +----------------------------+------+----------+------------------------------------------------------------------+
   | IV                         | 0x52 | 16       | IV to use for CBC wrapping.                                      |
   |                            |      |          | Not used if wrapping algorithm not equal 0x02.                   |
   +----------------------------+------+----------+------------------------------------------------------------------+
   | Signing algorithm          | 0x54 | 4        | Algorithm used to sign the blob itself. Field Signature of this  |
   |                            |      |          | blob.                                                            |
   |                            |      |          | It must be 0x01 (CMAC).                                          |
   +----------------------------+------+----------+------------------------------------------------------------------+
   | Wrapped private key        | 0x55 | Variable | Private key data in encrypted format as defined by the Wrapping  |
   |                            |      |          | Algorithm.                                                       |
   |                            |      |          | Key used to do the encryption must be wrapping key derived from  |
   |                            |      |          | the OEM Master key.                                              |
   +----------------------------+------+----------+------------------------------------------------------------------+
   | Signature                  | 0x5E | 16       | Signature of all previous fields of this blob including the      |
   |                            |      |          | signature tag (0x5E) and signature length fields.                |
   |                            |      |          | Key used to do the signature must be signing key derived from    |
   |                            |      |          | the OEM Master key.                                              |
   +----------------------------+------+----------+------------------------------------------------------------------+

Host example to derive OEM Master key
"""""""""""""""""""""""""""""""""""""
Here's an example of host source code C to derive the OEM Master key

In this example:

  - `MbedTLS Library <https://github.com/Mbed-TLS/mbedtls>`_ is used as third
    party cryptographic service.
  - ECDSA NIST 256 bits keypair are used on device and host side as based key
    of the OEM Master key agreement.
  - ECDH HKDF SHA256 algorithm is used for the key agreement operation.

  .. note::
     The following code is not complete, failure must be handled correctly and
     resource freed. The following examples aim to give the guidelines to
     write application on host and device.


#. On device, generates and exports an ECDSA NIST 256 bits keypair.

  The SMW API :ref:smw_generate_key is used to generate the key.
  The key is stored as a transient key.
  The public key is exported if the operation success. The public key is
  the device peer key that will be used to derive the OEM Master key on the
  host side.
  This key identifier will be identified in this example by ``ELE_base_id``
  The public key of this key will be identified in this example by ``ELE_peer_key``.

  .. code-block:: C
     :linenos:

     int res = -1;
     enum smw_status_code status = SMW_STATUS_OK;
     struct smw_generate_key_args args = { 0 };
     struct smw_key_descriptor key = { 0 };
     struct smw_key_attributes *attributes = &key.attributes;
     struct smw_keypair_buffer buffer = { 0 };

     /* Allocate the public key buffer of the key */
     buffer.gen.public_length = 64;
     buffer.gen.public_data = malloc(buffer.gen.public_length);
     if (!buffer.gen.public_data)
       return res;

   	 args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
   	 args.key_descriptor = &key;

     key.type_name = SMW_KEY_TYPE_NAME_SECP_R1;
     key.security_size = 256;
     key.buffer = &buffer;

     attributes.permitted_algo = SMW_ATTR_ALGO_KEY_AGREEMENT(SMW_ATTR_ALGO_ECDH,
                                                             SMW_ATTR_ALGO_HKDF,
                                                             SMW_ATTR_HASH_SHA256);
     attributes.usage_flags = SMW_ATTR_USAGE_DERIVE;
     attributes.attributes = SMW_ATTR_SET_PERSISTENCE(attributes.attributes,
                                                      SMW_ATTR_PERSISTENCE_TRANSIENT);

     status = smw_generate_key(&args);
     if (status != SMW_STATUS_OK) {
         free(buffer.gen.public_data);
         return -1;
     }

     /*
      * At this stage:
      *  - ``ELE_peer_key`` is the buffer.gen.public_data
      *  - ``ELE_base_id`` is the identifier returned in key.id
      */

     ...

#. On host, generates and exports an ECDSA NIST 256 bits keypair

  The public key is exported if the operation success. The public key is
  the host peer key that will be used to derive the OEM Master key on the
  device side.

  In this example, the Host peer key is named ``Host_peer_key``.

  .. code-block:: C
     :linenos:

     int res = -1;
     mbedtls_pk_context key;
     mbedtls_entropy_context entropy;
     mbedtls_ctr_drbg_context ctr_drbg;
     mbedtls_ecp_group grp;
     mbedtls_ecp_point Host_base_key;
     unsigned char Host_peer_key[MBEDTLS_ECP_MAX_PT_LEN];
     mbedtls_pk_type_t pk_alg = MBEDTLS_PK_ECKEY;
     size_t len = 0;

     mbedtls_pk_init(&key);
     mbedtls_entropy_init(&entropy);
     mbedtls_ctr_drbg_init(&ctr_drbg);


     res = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(pk_alg));
     if (res)
       /* Failure */

     res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                 &entropy,
                                 (const unsigned char *) "ecdsa",
                                 strlen(pers));
     if (res)
       /* Failure */

     res = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                               mbedtls_pk_ec(key),
                               mbedtls_ctr_drbg_random,
                               &ctr_drbg);
     if (res)
       /* Failure */

     mbedtls_ecp_group_init(&grp);
     mbedtls_ecp_point_init(&pt);

     res = mbedtls_ecp_export(ecp, &grp, NULL, &Host_base_key);
     if (res)
       /* Failure */

     res = mbedtls_ecp_point_write_binary(&grp, &Host_base_key,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &len, Host_peer_key,
                                          sizeof(Host_peer_key));
     if (res)
       /* Failure */

     /*
      * At this stage the ``Host_peer_key`` is the public key value starting with
      * the uncompress tag 0x4.
      */

     ...

#. On device, derive the OEM Master key

  * ``Host_peer_key`` is the host peer public key buffer.
  * ``ELE_base_id`` is the ELE base key identifier.

  Fixed info is optional. If set, its digest must be present in the signed
  content payload.

  Signed content payload must be configured as explained in `OEM Master key`_
  and where the peer public key digest must be the result of SHA256(``Host_peer_key``).
  This signed content payload key will be identified in this example by ``OEM_Payload``.

  In this example, the OEM Master key is a persistent key with a key identifier
  named ``ELE_OEM_MK_ID``. It's assumed that the signed payload is valid with
  slat flags set to 0 (no salt used to derived OEM Master key, wrapping and
  signing keys).
  In this example, the fixed info is not set.

    .. code-block:: C
       :linenos:

       int res = -1;
       enum smw_status_code status = SMW_STATUS_OK;
       struct smw_derive_key_args args = { 0 };
       struct smw_kdf_oem_master_key_args oem_mk_args = { 0 };
       struct smw_key_descriptor key_base = { 0 };
       struct smw_derived_key_descriptor key_derived = { 0 };

       args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
       args.key_descriptor_base = &key_base;
       args.kdf_name = SMW_KDF_NAME_OEM_MASTER_KEY;
       args.kdf_arguments = &oem_mk_args;
       args.store_derived_key = true; /* Request to store the key in Secure Storage */
       args.key_descriptor_base = &key_base;
       ergs.key_descriptor_derived = &key_derived;

       oem_mk_args.op = SMW_OEM_MK_OP_NAME_DERIVE;
       oem_mk_args.peer_public_buffer = Host_peer_key;
       oem_mk_args.peer_public_buffer_length = sizeof(Host_peer_key);
       oem_mk_args.payload = OEM_Payload;
       oem_mk_args.payload_length = sizeof(OEM_Payload);

       key_base.id = ELE_base_id;

       key_derived.type_name = SMW_KEY_TYPE_NAME_DERIVE;
       key_derived.security_size = 256;
       key_derived.id = ELE_OEM_MK_ID;
       key_derived.attributes.permitted_algo = SMW_ATTR_ALGO_KEY_DERIVATION_HKDF(SHA256);
       key_derived.attributes.usage_flags = SMW_ATTR_USAGE_DERIVE;
       key_derived.attributes.attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;


       status = smw_derive_key(&args);
       if (status != SMW_STATUS_OK)
           return -1;

       /*
        * At this stage, the OEM Master key is created in the EdgeLock Enclave,
        * as persistent key identifier ``ELE_OEM_MK_ID``
        */


   .. note::

      The wrapping and signing keys of the key import blob are not derived
      at this step but each time the Key Import API is executed.

#. On host, generates same OEM Master key

   This operation is done in two steps: key agreement and key derivation.

   In this example, the host OEM Master key identifier will be named
   ``Host_OEM_MK_ID``.

   #. Key agreement:

      This step generates a shared secret that will be used as input of key
      derivation step.

      The algorithm used is ECDH.

      In this example, the base key is the key generated in previous step and
      named ``Host_base_key``. The peer key is the device public key generated
      in previous step and named ``ELE_peer_key``.

      Here's a sample of code that can be used to generated the shared secret:

        .. code-block:: C
           :linenos:

           int res = -1;
           uint32_t peer_key_size = (256 / 8) * 2;
           uint32_t mbed_peer_key_size = peer_key_size + 1;
           uint8_t peer_key[mbed_peer_key_size];
           mbedtls_ecp_group grp;
           mbedtls_ecp_point peer_pt;
           mbedtls_mpi ecdh;

           /* Prepare public key */
           memset(&grp, 0, sizeof(grp));
           res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
           if (res != 0)
           	return failure;

           /* Prepare public key, a 0x04 leading byte must be added */
           peer_key[0] = 0x04;
           memcpy(peer_key_key + 1, ELE_peer_key, peer_key_size);

           /* Load public key from buffer */
           mbedtls_ecp_point_init(&peer_pt);
           res = mbedtls_ecp_point_read_binary(&grp, &peer_key, mbed_peer_key,
                                               mbed_peer_key_size);
           if (res != 0)
           	/* Failure */

           /* Compute ECDH */
           mbedtls_mpi_init(&ecdh);

           /*
            * The ``Host_base_key`` is the result of the key generated in
            * previous step.
            */
           res = mbedtls_ecdh_compute_shared(&grp, &ecdh, &peer_pt,
                                             &Host_base_key.private_d,
                                             my_mbedtls_rand, NULL);
           if (res != 0)
           	/* Failure */

           /*
            * At this point, the shared secret is the buffer located at
            * ecdh.private_p. Its size in bytes is 8 * ecdh.private_n
            * (ecdh.private_n is the size in limbs, i.e number of 64 bits blocks).
            *
            * CAUTION: Switch your environment configuration, MbedTLS may store
            * the shared secret ecdh.private_p in little endian BUT we need it
            * in big endian for the next step (key derivation).
            * Then a little endian to big endian conversion is needed.
            */

           ...

      .. note::

         ``my_mbedtls_rand`` must be a user function with the following
         definition: ``int my_mbedtls_rand(void *rng_state, unsigned char *output, size_t len)``.
         The function fills output buffer with a random value of len bytes.
         It must return 0 on success. Implementation depends on your environment.

   #. Key derivation:

      In this step, the shared secret buffer generated in previous step is
      used as input. Let's identify it as ``ecdh`` and ``ecdh_size``
      (size in bytes).

      .. note:: ECDH buffer must be in big endian.

      Here's a sample of code that can be used to derive the host OEM Master key
      named ``Host_OEM_MK`` key:

      .. code-block:: C
         :linenos:

         int res = -1;
         const mbedtls_md_info_t *md = NULL;
         uint32_t salt_size = 0;
         uint8_t *salt = NULL;
         uint32_t info_size = 0;
         uint8_t *info = NULL;
         uint32_t Host_OEM_MK_size = 256 / 8;
         uint8_t *Host_OEM_MK[Host_OEM_MK_size];

         /* Set md info */
         md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
         if (md == NULL)
            /* Failure */

         /*
          * In this example:
          * Salt is NULL and salt_size is 0: a string of zeros of SHA256 bytes
          * length will be used.
          *
          * Info is NULL and info_size is 0: no fixed info are used in the
          * derivation process.
          *
          * Both Salt and Fixed info could be enabled/set but previous steps
          * must defined the same.
          */
         res = mbedtls_hkdf(md, salt, salt_size, ecdh, ecdh_size, info,
                            info_size, Host_OEM_MK, Host_OEM_MK_size);
         if (res != 0)
            /* Failure */

         ...

#. On host, derives the wrapping key

  Use third party crypto service (MbedTLS library).

  In this step, the OEM Master key is the ``Host_OEM_MK`` key buffer generated
  in previous step is used as input.

  Here's a sample of code that can be used to derive the wrapping key identified
  by ``Host_OEM_WRAP_key`` key:

  .. code-block:: C
     :linenos:

     int res = -1;
     const mbedtls_md_info_t *md = NULL;
     uint32_t salt_size = 0;
     uint8_t *salt = NULL;
     uint32_t info_size = 24;
     uint8_t *info = "oemelefwkeyimportwrap256";
     uint32_t Host_OEM_WRAP_key_size = 256 / 8;
     uint8_t *Host_OEM_WRAP_key[Host_OEM_WRAP_key_size];

     /* Set md info */
     md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
     if (md == NULL)
       /* Failure */

     /*
      * In this example:
      * Salt is NULL and salt_size is 0: a string of zeros of SHA256 bytes
      * length will be used.
      *
      * Salt could be enabled/set but previous steps must defined the same.
      *
      * Info is imposed by ELE FW.
      */
     res = mbedtls_hkdf(md, salt, salt_size, Host_OEM_MK, Host_OEM_MK_size,
                        info, info_size, Host_OEM_WRAP_key,
                        Host_OEM_WRAP_key_size);
     if (res != 0)
       /* Failure */

     ...

#. On host, derives the signing key

  Use third party crypto service (MbedTLS library).

  In this step, the OEM Master key is the ``Host_OEM_MK`` key buffer generated
  in previous step is used as input.

  Here's a sample of code that can be used to derive the wrapping key identified
  by ``Host_OEM_CMAC_key`` key:

  .. code-block:: C
     :linenos:

     int res = -1;
     const mbedtls_md_info_t *md = NULL;
     uint32_t salt_size = 0;
     uint8_t *salt = NULL;
     uint32_t info_size = 24;
     uint8_t *info = "oemelefwkeyimportcmac256";
     uint32_t Host_OEM_CMAC_key_size = 256 / 8;
     uint8_t *Host_OEM_CMAC_key[Host_OEM_CMAC_key_size];

     /* Set md info */
     md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
     if (md == NULL)
       /* Failure */

     /*
      * In this example:
      * Salt is NULL and salt_size is 0: a string of zeros of SHA256 bytes
      * length will be used.
      *
      * Salt could be enabled/set but previous steps must defined the same.
      *
      * Info is imposed by ELE FW.
      */
     res = mbedtls_hkdf(md, salt, salt_size, Host_OEM_MK, Host_OEM_MK_size,
                        info, info_size, Host_OEM_CMAC_key,
                        Host_OEM_CMAC_key_size);
     if (res != 0)
       /* Failure */

     ...

#. On host, build the EdgeLock Enclave blob to import the key

  The blob must be builf by yourself and encoded as described
  in :numref:`ele_import_blob`.

  Third party crypto service (MbedTLS library) is used to wrap the
  imported key and signed the blob.

  Here's a sample of code that can be used to wrap the imported key
  with `RFC3394 <https://datatracker.ietf.org/doc/html/rfc3394>`_ algorithm:

  .. code-block:: C
     :linenos:

     uint32_t imported_key_size = 256 / 8;
     uint8_t imported_key[imported_key_size];
     uint32_t wrap_key_size = imported_key_size + 8; // RFC3394 algorithm adds 8 bytes
     uint8_t wrap_key[wrap_key_size];
     uint32_t out_len = 0;
     mbedtls_nist_kw_context kw_ctx;

     /* MbedTLS KW context init and setup */
     mbedtls_nist_kw_init(&kw_ctx);

     res = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES,
                                  Host_OEM_WRAP_key, 256, 1);
     if (res != 0)
       /* Failure */

     /* Execute key wrapping operation */
     res = mbedtls_nist_kw_wrap(&kw_ctx, MBEDTLS_KW_MODE_KW, imported_key,
                                imported_key_size, wrap_key, &out_len,
                                wrap_key_size);
     if (res != 0)
       /* Failure */

     ...


  Here's a sample of code that can be used to sign the blob with CMAC algorithm:

  .. code-block:: C
     :linenos:

     int res = -1;
     const mbedtls_cipher_info_t *cipher_info = NULL;
     uint32_t signature_size = 16; // Default CMAC output size
     uin32_t message_size = tlv_size - signature_size; // TLV size is the size in bytes of the full TLV buffer
     uint8_t tlv[tlv_size]; // The TLV buffer you built previously
     uint8_t *signature_ptr = tlv + message_size;

     cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
     if (cipher_info == NULL)
        return failure;

     res = mbedtls_cipher_cmac(cipher_info, Host_OEM_CMAC_key, 256, tlv,
                               message_size, signature_ptr);
     if (res != 0)
       /* Failure */

     ...


  Here's an example of EdgeLock Enclave blob to import an AES 256 bits key:
   - identifier = 0x66
   - permitted algorithm is defined to permit all ciphers mode
   - usage encrypt/decrypt
   - key is persistent
   - lifecycle is current device lifecycle
   - OEM Master key identifier = 0x2

  .. code-block:: C
     :linenos:

     uint8_t aes_key_ex[] = {
        0x40, 0x15, 0x65, 0x64, 0x67, 0x65, 0x6c, 0x6f,
        0x63, 0x6b, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76,
        0x65, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x41,
        0x04, 0x00, 0x00, 0x00, 0x66, 0x42, 0x04, 0x84,
        0xc0, 0xff, 0x00, 0x43, 0x04, 0x00, 0x00, 0x03,
        0x00, 0x44, 0x02, 0x24, 0x00, 0x45, 0x04, 0x00,
        0x00, 0x01, 0x00, 0x46, 0x04, 0xc0, 0x02, 0x00,
        0x01, 0x47, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50,
        0x04, 0x00, 0x00, 0x00, 0x02, 0x51, 0x04, 0x00,
        0x00, 0x00, 0x01, 0x54, 0x04, 0x00, 0x00, 0x00,
        0x01, 0x55, 0x28, 0x23, 0xb4, 0xa9, 0xf5, 0x9a,
        0x91, 0x9c, 0xd6, 0xfc, 0x6d, 0x27, 0xa7, 0xa6,
        0x27, 0x4e, 0xed, 0xf5, 0x6e, 0x92, 0x9f, 0x04,
        0xeb, 0xed, 0xef, 0xf0, 0x31, 0xe4, 0xc9, 0x51,
        0x9d, 0x12, 0x4d, 0x42, 0x50, 0xe8, 0x98, 0x82,
        0x95, 0x42, 0x96, 0x5e, 0x10, 0x77, 0x17, 0xd2,
        0x6c, 0x47, 0x55, 0x67, 0xf4, 0x0b, 0xeb, 0x7f,
        0x39, 0x31, 0xea, 0x8b, 0x86
     };

#. On device, import the key.

  The SMW API :ref:smw_import_key is used to import the key.

  In the following example, the key imported is the blob example of the AES
  256 bits key above.

 .. code-block:: C
    :linenos:

    int res = -1;
    enum smw_status_code status = SMW_STATUS_OK;
    struct smw_import_key_args args = { 0 };
    struct smw_key_descriptor key = { 0 };
    struct smw_key_attributes *attributes = &key.attributes;
    struct smw_keypair_buffer buffer = { 0 };

    /* Set the private key buffer to use the blob example */
    buffer.gen.public_length = sizeof(aes_key_ex);
    buffer.gen.public_data = aes_key_ex;

   	args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
   	args.key_descriptor = &key;

    key.id = 0x66:
    key.type_name = SMW_KEY_TYPE_NAME_AES;
    key.security_size = 256;
    key.buffer = &buffer;

    attributes.permitted_algo = SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(SMW_ATTR_ALGO_AES,
                                                                   SMW_ATTR_MODE_ANY);
    attributes.usage_flags = SMW_ATTR_USAGE_ENCRYPT | SMW_ATTR_USAGE_DECRYPT;
    attributes.attributes = SMW_ATTR_SET_PERSISTENCE(attributes.attributes,
                                                     SMW_ATTR_PERSISTENCE_PERSISTENT);


    status = smw_import_key(&args);

    ...

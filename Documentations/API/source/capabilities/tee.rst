TEE capabilities
================

Key manager
^^^^^^^^^^^

.. table:: TEE Key type
   :align: center
   :class: wrap-table

   +--------------+-----------------------------+
   | **Key type** | **Key security size(s)**    |
   +==============+=============================+
   | AES          | 128 / 192 / 256             |
   +--------------+-----------------------------+
   | DES          | 56                          |
   +--------------+-----------------------------+
   | DES3         | 112 / 168                   |
   +--------------+-----------------------------+
   | Secp R1      | 192 / 224 / 256 / 384 / 521 |
   +--------------+-----------------------------+
   | Ed25519      | 255                         |
   +--------------+-----------------------------+
   | RSA          | 256 to 4096 [1]_            |
   +--------------+-----------------------------+
   | HMAC         | 64 to 1024 bits [2]_        |
   +--------------+-----------------------------+
   | SM4          | 128                         |
   +--------------+-----------------------------+
   | HKDF IKM [3]_| 8 to 4096 bits [2]_         |
   +--------------+-----------------------------+

Operations supported:
 - Generate
 - Import
 - Export (only public key in HEX or Base64 format)
 - Delete
 - Get key attributes
 - Get key buffers' length
 - Get key security size
 - Get key type name
 - Commit key storage (do nothing)
 - `Key Derivation`_

.. [1] multiple of 2 bits
.. [2] multiple of 8 bits
.. [3] Only key import is supported. HKDF IKM keys cannot be generated. This key
       can be used as IKM for key derivation using HKDF.


Key policy
""""""""""
When creating a new key, the key policy must be specified through the operation
key attributes.

The following :numref:`tee_key_usage` lists all key usages applicable in TEE
subsystem. A key policy defines one or more key usage.

.. table:: TEE Key usages
   :name: tee_key_usage
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
   | EXPORT         | Permission to export the public key only             |
   +----------------+------------------------------------------------------+

The TEE subsystem doesn't define algorithm restriction per key usage.
Defining permitted algorithm(s) will not be taken into account and operation
will return the warning status `SMW_STATUS_KEY_POLICY_WARNING_IGNORED`.

Hash
^^^^

.. table:: TEE Hash
   :name: tee_hash
   :align: center
   :class: wrap-table

   +--------------------+
   | **Hash Algorithm** |
   +====================+
   | MD5                |
   +--------------------+
   | SHA1               |
   +--------------------+
   | SHA224             |
   +--------------------+
   | SHA256             |
   +--------------------+
   | SHA384             |
   +--------------------+
   | SHA512             |
   +--------------------+
   | SHA3_224           |
   +--------------------+
   | SHA3_256           |
   +--------------------+
   | SHA3_384           |
   +--------------------+
   | SHA3_512           |
   +--------------------+
   | SM3                |
   +--------------------+

Operations supported:
 - One shot and multi-part

Signature
^^^^^^^^^

.. table:: TEE Signature
   :align: center
   :widths: 20 13 35 32
   :width: 100%
   :class: wrap-table

   +--------------------+--------------+-----------------------------+--------------------------+
   | **Signature Type** | **Key type** | **Key security size(s)**    | **Hash algorithm**       |
   +====================+==============+=============================+==========================+
   | ECDSA              | Secp R1      | 192 / 224 / 256 / 384 / 521 | - SHA1                   |
   |                    |              |                             | - SHA224                 |
   |                    |              |                             | - SHA256                 |
   |                    |              |                             | - SHA384                 |
   |                    |              |                             | - SHA512                 |
   |                    |              |                             | - SHA3_224               |
   |                    |              |                             | - SHA3_256               |
   |                    |              |                             | - SHA3_384               |
   |                    |              |                             | - SHA3_512               |
   |                    |              |                             | - None (Message hashed)  |
   +--------------------+--------------+-----------------------------+--------------------------+
   | RSA_PKCS1V15       | RSA          | 256 to 4096 [4]_            | - MD5                    |
   |                    |              |                             | - SHA1                   |
   |                    |              |                             | - SHA224                 |
   |                    |              |                             | - SHA256                 |
   |                    |              |                             | - SHA384                 |
   |                    |              |                             | - SHA512                 |
   |                    |              |                             | - SHA3_224               |
   |                    |              |                             | - SHA3_256               |
   |                    |              |                             | - SHA3_384               |
   |                    |              |                             | - SHA3_512               |
   +--------------------+--------------+-----------------------------+--------------------------+
   | RSA_PSS            | RSA          | 256 to 4096 [4]_            | - SHA1                   |
   |                    |              |                             | - SHA224                 |
   |                    |              |                             | - SHA256                 |
   |                    |              |                             | - SHA384                 |
   |                    |              |                             | - SHA512                 |
   |                    |              |                             | - SHA3_224               |
   |                    |              |                             | - SHA3_256               |
   |                    |              |                             | - SHA3_384               |
   |                    |              |                             | - SHA3_512               |
   +--------------------+--------------+-----------------------------+--------------------------+
   | PURE_EDDSA         | ED25519      | 255                         | N/A                      |
   +--------------------+--------------+-----------------------------+--------------------------+
   | EDDSA_PH           | ED25519      | 255                         | None (pre-hashed)        |
   +--------------------+--------------+-----------------------------+--------------------------+
   | EDDSA_CTX          | ED25519      | 255                         | N/A                      |
   +--------------------+--------------+-----------------------------+--------------------------+

Operations supported:
 - Sign
 - Verify

.. note::
   Message to sign/verify is full or hashed depending on the algorithm 64-bits
   word definition additional parameters (bits[39:32]).

.. [4] multiple of 2 bits


MAC
^^^

.. table:: TEE MAC
   :align: center
   :class: wrap-table

   +---------------+--------------+--------------------------+----------+
   | **MAC Type**  | **Key type** | **Key security size(s)** | **Hash** |
   +===============+==============+==========================+==========+
   | CMAC          | AES          | 128 / 192 / 256          | N/A      |
   +---------------+--------------+--------------------------+----------+
   | HMAC          | HMAC         | 64 to 512 bits [5]_      | MD5      |
   +               +              +                          +----------+
   |               |              | 80 to 512 bits [5]_      | SHA1     |
   +               +              +                          +----------+
   |               |              | 112 to 512 bits [5]_     | SHA224   |
   +               +              +                          +----------+
   |               |              | 192 to 1024 bits [5]_    | SHA256   |
   +               +              +                          +----------+
   |               |              | 256 to 1024 bits [5]_    | SHA384   |
   +               +              +                          +----------+
   |               |              | 256 to 1024 bits [5]_    | SHA512   |
   +               +              +                          +----------+
   |               |              | 80 to 1024 bits [5]_     | SM3      |
   +---------------+--------------+--------------------------+----------+

.. [5] multiple of 8 bits

Operations supported:
 - Compute MAC
 - Verify MAC

Random
^^^^^^

Length: 1 to SIZE_MAX

Cipher
^^^^^^

.. table:: TEE Cipher
   :align: center
   :class: wrap-table


   +-----------------+--------------+--------------------------+
   | **Cipher Mode** | **Key type** | **Key security size(s)** |
   +=================+==============+==========================+
   | ECB No Padding  | AES          | 128 / 192 / 256          |
   +-----------------+              +                          +
   | CBC No Padding  |              |                          |
   +-----------------+              +                          +
   | CTS             |              |                          |
   +-----------------+              +                          +
   | CTR             |              |                          |
   +-----------------+              +                          +
   | XTS             |              |                          |
   +-----------------+--------------+--------------------------+
   | ECB No Padding  | DES          | 56                       |
   +-----------------+              +                          +
   | CBC No Padding  |              |                          |
   +-----------------+--------------+--------------------------+
   | ECB No Padding  | DES3         | 112 / 168                |
   +-----------------+              +                          +
   | CBC No Padding  |              |                          |
   +-----------------+--------------+--------------------------+
   | ECB No Padding  | SM4          | 128                      |
   +-----------------+              +                          +
   | CBC No Padding  |              |                          |
   +-----------------+              +                          +
   | CTR             |              |                          |
   +-----------------+--------------+--------------------------+


Operations supported:
 - Encrypt [6]_
 - Decrypt [6]_

.. [6] one shot and multi-part

Operation context
^^^^^^^^^^^^^^^^^

Operations supported:
 - Allocate
 - Cancel
 - Copy

AEAD
^^^^

.. table:: TEE AEAD
   :name: tee_aead
   :align: center
   :widths: 15 15 20 50
   :width: 100%
   :class: wrap-table

   +---------------+--------------+---------------+-------------------------------+
   | **AEAD Mode** | **Key type** | **IV length** | **Tag length**                |
   +               +              +               +                               +
   |               |              | **(bytes)**   | **(bytes)**                   |
   +===============+==============+===============+===============================+
   | CCM           | AES          | Up to 13      | 4 / 6 / 8 / 10 / 12 / 14 / 16 |
   +---------------+              +---------------+-------------------------------+
   | GCM           |              | Up to 16      | 12 / 13 / 14 / 15 / 16        |
   +---------------+--------------+---------------+-------------------------------+

.. note::
   User has the capability to request the TA to generate part of full operation
   IV in the limit of the maximum value depending of the operation mode as
   detailed in the :numref:`tee_aead`.

Operations supported:
 - Encryption one shot and multi-part
 - Decryption one shot and multi-part

Data Storage manager
^^^^^^^^^^^^^^^^^^^^

Data Storage manager allows to store and retrieve data. The data ID is a 32-bits
value.

The subsystem allows to:

  - store and retrieve user data.
  - delete a data.

The subsystem doesn't allow to:

  - encrypt and sign data before storing it.

Key Derivation
^^^^^^^^^^^^^^
Supported Key Derivation Functions
 - HMAC-based Key Derivation Function (HKDF)
 - ECDH Key Derivation Function

The subsystem supports deriving a key from an existing HKDF IKM or EC key
as well as from a plaintext buffer. Subsystem allows to store the derived key
upon user request and also allows exporting the derived key if the derived key
buffer is set.

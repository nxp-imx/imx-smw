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
   | ECDSA NIST   | 192 / 224 / 256 / 384 / 521 |
   +--------------+-----------------------------+
   | RSA          | 256 to 4096 [1]_            |
   +--------------+-----------------------------+
   | HMAC_MD5     | 64 to 512 bits [2]_         |
   +--------------+-----------------------------+
   | HMAC_SHA1    | 80 to 512 bits [2]_         |
   +--------------+-----------------------------+
   | HMAC_SHA224  | 112 to 512 bits [2]_        |
   +--------------+-----------------------------+
   | HMAC_SHA256  | 192 to 1024 bits [2]_       |
   +--------------+-----------------------------+
   | HMAC_SHA384  | 256 to 1024 bits [2]_       |
   +--------------+-----------------------------+
   | HMAC_SHA512  | 256 to 1024 bits [2]_       |
   +--------------+-----------------------------+
   | HMAC_SM3     | 80 to 1024 bits [2]_        |
   +--------------+-----------------------------+

Operations supported:
 - Generate
 - Import
 - Export (only public key in HEX or Base64 format)
 - Delete

.. [1] multiple of 2 bits
.. [2] multiple of 8 bits


Key policy
""""""""""
When creating a new key, the key policy must be specified through the operation
key attributes list. The key policy definition is defined with a **POLICY** TLV
:ref:`tlv_variable-length-list`.

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

.. caution::
   If key attribute **POLICY** is not specified, all key usages listed in
   the :numref:`tee_key_usage` are attributed to the created key.

Hash
^^^^

.. table:: TEE Hash
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
   | SM3                |
   +--------------------+



Signature
^^^^^^^^^

.. table:: TEE Signature
   :align: center
   :class: wrap-table

   +--------------+-----------------------------+----------+--------------------+
   | **Key type** | **Key security size(s)**    | **Hash** | **Signature type** |
   +==============+=============================+==========+====================+
   | ECDSA NIST   | 192 / 224 / 256 / 384 / 521 |  SHA224  | N/A                |
   +              +                             +          +                    +
   |              |                             |  SHA256  |                    |
   +              +                             +          +                    +
   |              |                             |  SHA384  |                    |
   +              +                             +          +                    +
   |              |                             |  SHA512  |                    |
   +--------------+-----------------------------+----------+--------------------+
   | RSA          | 256 to 4096 [3]_            |  MD5     |  RSASSA-PKCS1-V1_5 |
   +              +                             +          +                    +
   |              |                             |  SHA1    |  RSASSA-PSS        |
   +              +                             +          +                    +
   |              |                             |  SHA224  |                    |
   +              +                             +          +                    +
   |              |                             |  SHA256  |                    |
   +              +                             +          +                    +
   |              |                             |  SHA384  |                    |
   +--------------+-----------------------------+----------+--------------------+

Operations supported:
 - Sign
 - Verify

.. [3] multiple of 2 bits


MAC
^^^

.. table:: TEE MAC
   :align: center
   :class: wrap-table

   +--------------+--------------------------+---------------+----------+
   | **Key type** | **Key security size(s)** | **Algorithm** | **Hash** |
   +==============+==========================+===============+==========+
   | AES          | 128 / 192 / 256          | CMAC          | N/A      |
   +--------------+--------------------------+---------------+----------+
   | HMAC_MD5     | 64 to 512 bits [4]_      | HMAC          | MD5      |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA1    | 80 to 512 bits [4]_      | HMAC          | SHA1     |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA224  | 112 to 512 bits [4]_     | HMAC          | SHA224   |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA256  | 192 to 1024 bits [4]_    | HMAC          | SHA256   |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA384  | 256 to 1024 bits [4]_    | HMAC          | SHA384   |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA512  | 256 to 1024 bits [4]_    | HMAC          | SHA512   |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SM3     | 80 to 1024 bits [4]_     | HMAC          | SM3      |
   +--------------+--------------------------+---------------+----------+

.. [4] multiple of 8 bits

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

   +--------------+----------+
   | **Key type** | **Mode** |
   +==============+==========+
   | AES          |  CBC     |
   +              +          +
   |              |  CTR     |
   +              +          +
   |              |  CTS     |
   +              +          +
   |              |  ECB     |
   +              +          +
   |              |  XTS     |
   +--------------+----------+
   | DES          |  CBC     |
   +              +          +
   |              |  ECB     |
   +--------------+----------+
   | DES3         |  CBC     |
   +              +          +
   |              |  ECB     |
   +--------------+----------+

Operations supported:
 - Encrypt [5]_
 - Decrypt [5]_

.. [5] one shot and multi-part

Operation context
^^^^^^^^^^^^^^^^^

Operations supported:
 - Cancel
 - Copy


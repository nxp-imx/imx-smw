SECO capabilities
=================

Key manager
^^^^^^^^^^^

.. table:: SECO Key type
   :align: center
   :class: wrap-table

   +--------------+---------------------------+
   | **Key type** | **Key security size(s)**  |
   +==============+===========================+
   | AES          | 128 / 192 / 256           |
   +--------------+---------------------------+
   | Secp R1      | 256 / 384                 |
   +--------------+---------------------------+
   | Brainpool R1 | 256 / 384                 |
   +--------------+---------------------------+
   | HMAC         | 224 / 256 / 384 / 512     |
   +--------------+---------------------------+


Operations supported:
 - Generate
 - Export (only public key in HEX or Base64 format)
 - Delete
 - Derive [1]_
 - Get key attributes
 - Get key buffers' length
 - Get key security size
 - Get key type name
 - Commit key storage (do nothing)

Key group:
The SMW Library is managing the SECO key group automatically. The library is
selecting a key group depending if a key is persistent/permanent or transient.

  - Persistent/Permanent keys are in key groups from 0 to 511.
  - Transient keys are in key groups from 512 to 1023.

Persistent key:
To flush persistent key, "FLUSH_KEY" attribute must be set. When set, SECO
executes a strict operation and all keys defined as persistent are flushed. Note
that SECO uses a strict operation counter which is a replay attack counter, then
the number of strict operation is limited. So when possible it's better to
perform multiple persistent key operations (generate, import, delete) before
setting the "FLUSH_KEY" attribute.

.. [1] Only TLS12_KEY_EXCHANGE when hardware supports it


Key policy
""""""""""
The SECO subsystem doesn't support key policy attribute. Defining the key
attribute **POLICY** will be ignored and if attribute is defined the API
returns the warning `SMW_STATUS_KEY_POLICY_WARNING_IGNORED`.


Hash
^^^^

.. table:: SECO Hash
   :align: center
   :class: wrap-table

   +--------------------+
   | **Hash Algorithm** |
   +====================+
   | SHA1 [2]_          |
   +--------------------+
   | SHA224             |
   +--------------------+
   | SHA256             |
   +--------------------+
   | SHA384             |
   +--------------------+
   | SHA512             |
   +--------------------+

Operations supported:
 - One shot and multi-part [2]_

.. [2] Operation is performed by the SMW library

Signature
^^^^^^^^^

.. table:: SECO Signature
   :align: center
   :class: wrap-table

   +--------------+--------------------------+--------------------+
   | **Key type** | **Key security size(s)** | **Hash algorithm** |
   +==============+==========================+====================+
   | Secp R1      | 256                      | SHA256             |
   |              +--------------------------+--------------------+
   |              | 384                      | SHA384             |
   +--------------+--------------------------+--------------------+
   | Brainpool R1 | 256                      | SHA256             |
   |              +--------------------------+--------------------+
   |              | 384                      | SHA384             |
   +--------------+--------------------------+--------------------+

Operations supported:
 - Sign [3]_
 - Verify

.. [3] Attribute TLS_MAC_FINISH available only when hardware supports it

Random
^^^^^^

Length: 1 to UINT32_MAX

MAC
^^^

.. table:: SECO MAC
   :align: center
   :class: wrap-table

   +--------------+--------------------------+---------------+----------+
   | **Key type** | **Key security size(s)** | **Algorithm** | **Hash** |
   +==============+==========================+===============+==========+
   | AES          | 128 / 192 / 256          | CMAC          | N/A      |
   +--------------+--------------------------+---------------+----------+
   | HMAC         | 224                      | HMAC          | SHA224   |
   +--------------+--------------------------+---------------+----------+
   | HMAC         | 256                      | HMAC          | SHA256   |
   +--------------+--------------------------+---------------+----------+
   | HMAC         | 384                      | HMAC          | SHA384   |
   +--------------+--------------------------+---------------+----------+
   | HMAC         | 512                      | HMAC          | SHA512   |
   +--------------+--------------------------+---------------+----------+

HMAC Key generation and HMAC generation is not working on all SECO Firmware
and may return ``SMW_STATUS_SUBSYSTEM_FAILURE``.

Operations supported:
 - Compute MAC
 - Verify MAC

Cipher
^^^^^^

.. table:: SECO Cipher
   :align: center
   :class: wrap-table

   +--------------+----------+
   | **Key type** | **Mode** |
   +==============+==========+
   | AES          |   CBC    |
   +              +          +
   |              |   ECB    |
   +--------------+----------+

One-shot operations supported:
 - Encrypt
 - Decrypt

Operation context
^^^^^^^^^^^^^^^^^

Operations supported:
 - Allocate
 - Cancel

Data Storage manager
^^^^^^^^^^^^^^^^^^^^

Data Storage manager allows to store and retrieve data. The data ID is a 32-bits
value.

The subsystem allows to:

  - store and retrieve user data.

The subsystem doesn't allow to:

  - encrypt and sign data before storing it.
  - delete a data.

AEAD
^^^^

.. table:: SECO AEAD
   :align: center
   :class: wrap-table

   +--------------+----------+------------------------+------------------------+
   | **Key type** | **Mode** | **IV length (bytes)**  | **Tag length (bytes)** |
   +==============+==========+========================+========================+
   | AES          |   CCM    |       12 [4]_          |        16              |
   +              +----------+------------------------+------------------------+
   |              |   GCM    | Encryption: 0 or 4 [5]_|        16              |
   +              +          +                        +                        +
   |              |          | Decryption: 12         |                        |
   +--------------+----------+------------------------+------------------------+

.. [4] For CCM AEAD encryption and decryption operation, IV length should be
       12 bytes.

.. [5] For GCM AEAD Encryption operation, IV length can be either

   0 bytes, to request the subsystem to fully generate the IV.

   4 bytes, to request the subsystem to generate the rest of the IV bytes.

   For decryption operation, IV length should be 12 bytes.

One-shot operations supported:
 - AEAD Encryption
 - AEAD Decryption

Key Derivation
^^^^^^^^^^^^^^

- TLS 1.2 (TLS1-PRF) [6]_

SECO does not support multiple TLS1.2 operations, so the implementation of the
TLS1.2 API uses the context supplied as a parameter to store intermediate data when
attempting to generate the master secret. When calling the TLS1.2 API to compute
the key expansion, the input of this operation is merged with the context and the
actual operation is being executed. Thus, the master secret key id returned from
the first operation is not valid, and only be used after the subsequent key
expansion operation.

Only ECDH(E) key exchange is supported, and the following ciphersuites:

.. table:: SECO supported ciphersuites
   :name: seco_ciphersuites
   :align: center
   :width: 100%
   :class: wrap-table

   +--------------------------------------+-------------------------------+
   | **SMW encryption name**              | **OpenSSL equivalent**        |
   +======================================+===============================+
   | SMW_TLS12_ENC_NAME_AES_128_CBC       | ECDHE-ECDSA-AES128-SHA256     |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_128_GCM       | ECDHE-ECDSA-AES128-GCM-SHA256 |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_256_CBC       | ECDHE-ECDSA-AES256-SHA384     |
   +--------------------------------------+-------------------------------+
   | SMW_TLS12_ENC_NAME_AES_256_GCM       | ECDHE-ECDSA-AES256-GCM-SHA384 |
   +--------------------------------------+-------------------------------+

.. [6] Only when supported by the hardware

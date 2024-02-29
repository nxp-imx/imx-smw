SECO capabilities
================

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
   | ECDSA BR1    | 256 / 384                 |
   +--------------+---------------------------+
   | ECDSA NIST   | 256 / 384                 |
   +--------------+---------------------------+
   | HMAC_SHA224  | 224                       |
   +--------------+---------------------------+
   | HMAC_SHA256  | 256                       |
   +--------------+---------------------------+
   | HMAC_SHA384  | 384                       |
   +--------------+---------------------------+
   | HMAC_SHA512  | 512                       |
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

.. table:: SECO Signature
   :align: center
   :class: wrap-table

   +--------------+--------------------------+--------------------+
   | **Key type** | **Key security size(s)** | **Hash algorithm** |
   +==============+==========================+====================+
   | ECDSA BR1    | 256                      | SHA256             |
   |              +--------------------------+--------------------+
   |              | 384                      | SHA384             |
   +--------------+--------------------------+--------------------+
   | ECDSA NIST   | 256                      | SHA256             |
   |              +--------------------------+--------------------+
   |              | 384                      | SHA384             |
   +--------------+--------------------------+--------------------+

Operations supported:
 - Sign [2]_
 - Verify

.. [2] Attribute TLS_MAC_FINISH available only when hardware supports it

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
   | HMAC_SHA224  | 224                      | HMAC          | SHA224   |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA256  | 256                      | HMAC          | SHA256   |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA384  | 384                      | HMAC          | SHA384   |
   +--------------+--------------------------+---------------+----------+
   | HMAC_SHA512  | 512                      | HMAC          | SHA512   |
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
   | AES          |   CCM    |       12 [3]_          |        16              |
   +              +----------+------------------------+------------------------+
   |              |   GCM    | Encryption: 0 or 4 [4]_|        16              |
   +              +          +                        +                        +
   |              |          | Decryption: 12         |                        |
   +--------------+----------+------------------------+------------------------+

.. [3] For CCM AEAD encryption and decryption operation, IV length should be
       12 bytes.

.. [4] For GCM AEAD Encryption operation, IV length can be either

  - 0 bytes, to request the subsystem to fully generate the IV.
  - 4 bytes, to request the subsystem to generate the rest of the IV bytes.

   For decryption operation, IV length should be 12 bytes.

One-shot operations supported:
 - AEAD Encryption
 - AEAD Decryption

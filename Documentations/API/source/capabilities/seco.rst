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

.. [1] Only TLS12_KEY_EXCHANGE when hardware supports it


Key policy
""""""""""
The SECO subsystem doesn't support key policy attribute. Defining the key
attribute will be ignored and if attribute is defined the API
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
   :widths: 20 20 25 35
   :width: 100%
   :class: wrap-table

   +--------------------+--------------+--------------------------+--------------------+
   | **Signature Type** | **Key type** | **Key security size(s)** | **Hash algorithm** |
   +====================+==============+==========================+====================+
   | ECDSA              | Secp R1      | 256                      | SHA256             |
   |                    |              +--------------------------+--------------------+
   |                    |              | 384                      | SHA384             |
   |                    +--------------+--------------------------+--------------------+
   |                    | Brainpool R1 | 256                      | SHA256             |
   |                    |              +--------------------------+--------------------+
   |                    |              | 384                      | SHA384             |
   +--------------------+--------------+--------------------------+--------------------+

Operations supported:
 - Sign [3]_
 - Verify

.. [3] Attribute TLS_MAC_FINISH available only when hardware supports it

.. note::
   Message to sign/verify is full or hashed depending on the algorithm 64-bits
   word definition additional parameters (bits[39:32]).


Random
^^^^^^

Length: 1 to UINT32_MAX

MAC
^^^

.. table:: SECO MAC
   :align: center
   :class: wrap-table

   +--------------+--------------+-------------------------+----------+
   | **MAC Type** | **Key type** | **Key security size(s)**| **Hash** |
   +==============+==============+=========================+==========+
   | CMAC         | AES          | 128 / 192 / 256         | N/A      |
   +--------------+--------------+-------------------------+----------+
   | HMAC         | HMAC         | 224                     | SHA224   |
   +              +              +-------------------------+----------+
   |              |              | 256                     | SHA256   |
   +              +              +-------------------------+----------+
   |              |              | 384                     | SHA384   |
   +              +              +-------------------------+----------+
   |              |              | 512                     | SHA512   |
   +--------------+--------------+-------------------------+----------+

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

   +-----------------+--------------+--------------------------+
   | **Cipher Mode** | **Key type** | **Key security size(s)** |
   +=================+==============+==========================+
   | ECB No Padding  | AES          | 128 / 192 / 256          |
   +-----------------+              +                          +
   | CBC No Padding  |              |                          |
   +-----------------+--------------+--------------------------+

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
   :widths: 30 12 43 15
   :width: 100%
   :class: wrap-table

   +---------------+--------------+-----------------------------------------+----------------+
   | **AEAD Mode** | **Key type** | **IV length**                           | **Tag length** |
   +               +              +                                         +                +
   |               |              | **(bytes)**                             | **(bytes)**    |
   +===============+==============+=========================================+================+
   | CCM           | AES          | 12                                      |       16       |
   +---------------+              +-----------------------------------------+----------------+
   | GCM           |              | Encryption:                             |       16       |
   |               |              |                                         |                |
   |               |              | - 0 (subsystem generates full IV)       |                |
   |               |              | - 4 (subsystem generates 8 bytes of IV) |                |
   +               +              +-----------------------------------------+                +
   |               |              | Decryption:                             |                |
   |               |              |                                         |                |
   |               |              | - 12 (user supplied full IV)            |                |
   +---------------+--------------+-----------------------------------------+----------------+


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

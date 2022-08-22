HSM capabilities
================

Key manager
^^^^^^^^^^^

.. table::
   :align: left
   :class: wrap-table

   +--------------+---------------------------------+
   | **Key type** | **Key security size(s)**        |
   +==============+=================================+
   | AES          | 128 / 192 / 256                 |
   +--------------+---------------------------------+
   | ECDSA BR1    | 256 / 384                       |
   +--------------+---------------------------------+
   | ECDSA NIST   | 256 / 384                       |
   +--------------+---------------------------------+

Operations supported:
 - Generate
 - Export (only public key in HEX or Base64 format)
 - Delete
 - Derive [1]_

Key group limitation:
Key group ID is hard-coded in SMW's HSM subsystem support. There is one group
for transient key and one for persistent key. As the number of keys per group is
limited by HSM, key generation may failed if the maximum number of keys is
reached.

Persistent key:
To flush persistent key, "FLUSH_KEY" attribute must be set. When set, HSM
executes a strict operation and all keys defined as persistent are flushed. Note
that HSM uses a strict operation counter which is a replay attack counter, then
the number of strict operation is limited. So when possible it's better to
perform multiple persistent key operations (generate, import) before setting the
"FLUSH_KEY" attribute.

.. [1] Only TLS12_KEY_EXCHANGE when hardware supports it


Key policy
""""""""""
The HSM subsystem doesn't support key policy attribute. Defining the key
attribute **POLICY** will be ignored and if attribute is defined the API
returns the warning `SMW_STATUS_KEY_POLICY_WARNING_IGNORED`.


Hash
^^^^

Algorithm:
 - SHA224
 - SHA256
 - SHA384
 - SHA512

Signature
^^^^^^^^^

.. table::
   :align: left
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

HMAC
^^^^

.. table::
   :align: left
   :class: wrap-table

   +--------------+--------------------------+--------------------+
   | **Key type** | **Key security size(s)** | **Hash algorithm** |
   +==============+==========================+====================+
   | HMAC_SHA224  | 224 bits                 | SHA224             |
   +--------------+--------------------------+--------------------+
   | HMAC_SHA256  | 256 bits                 | SHA256             |
   +--------------+--------------------------+--------------------+
   | HMAC_SHA384  | 384 bits                 | SHA384             |
   +--------------+--------------------------+--------------------+
   | HMAC_SHA512  | 512 bits                 | SHA512             |
   +--------------+--------------------------+--------------------+

HMAC Key generation and HMAC generation is not working on all HSM Firmware
and may return ``SMW_STATUS_SUBSYSTEM_FAILURE``.

Cipher
^^^^^^

.. tabularcolumns:: |\Y{0.2}|\Y{0.2}|

.. table::
   :align: left
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

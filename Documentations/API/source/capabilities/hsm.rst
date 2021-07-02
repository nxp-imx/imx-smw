HSM capabilities
================

Key manager
^^^^^^^^^^^

.. table::
   :align: left
   :widths: auto

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

.. [1] Only TLS12_KEY_EXCHANGE when hardware supports it

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
   :widths: auto

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

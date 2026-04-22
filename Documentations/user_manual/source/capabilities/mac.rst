.. _capabilities_mac:

Message Authentication Code (MAC)
---------------------------------

This section documents the Message Authentication Code (MAC) operations supported across
different security subsystems (ELE, TEE, SECO) with their respective algorithms
and key types.

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: MAC Operations vs. subsystem
   :name: table_mac_operations_subsystem
   :align: center
   :widths: 25 15 10 10 10 30
   :class: wrap-table

   +-----------------------+----------------+---------+---------+----------+-------------------------------------+
   | **MAC Algorithm**     | **Processing** | **Subsystem**                | **Notes**                           |
   +                       +                +---------+---------+----------+                                     +
   |                       |                | **ELE** | **TEE** | **SECO** |                                     |
   +=======================+================+=========+=========+==========+=====================================+
   | HMAC                  | Single-Part    |    Y    |    Y    |  **Y***  | **SECO** Require specific Firmware. |
   +-----------------------+----------------+---------+---------+----------+-------------------------------------+
   | Truncated HMAC        | Single-Part    |    Y    |    N    |    N     | Generated HMAC Length is truncated. |
   |                       |                |         |         |          | MAC Length must be 8 bytes up to    |
   |                       |                |         |         |          | Full MAC Length.                    |
   +-----------------------+----------------+---------+---------+----------+-------------------------------------+
   | CMAC                  | Single-Part    |    Y    |    Y    |    Y     |                                     |
   +-----------------------+----------------+---------+---------+----------+-------------------------------------+
   | Truncated CMAC        | Single-Part    |    Y    |    N    |    N     | Generated CMAC Length is truncated. |
   |                       |                |         |         |          | MAC Length must be 8 bytes up to    |
   |                       |                |         |         |          | Full MAC Length.                    |
   +-----------------------+----------------+---------+---------+----------+-------------------------------------+


.. table:: MAC APIs
   :name: table_mac_apis
   :align: center
   :widths: 25 15 15 45
   :width: 100%
   :class: wrap-table

   +------------------------+----------------+---------+----------------------------+
   | **Operations**         | **Processing** | **API** | **Functions**              |
   +========================+================+=========+============================+
   | MAC Generation         | Single-Part    | SMW     | :c:func:`smw_mac`          |
   +                        +                +---------+----------------------------+
   |                        |                | PSA     | :c:func:`psa_mac_compute`  |
   +                        +                +---------+----------------------------+
   |                        |                | PKCS11  | C_SignInit()               |
   +                        +                +         +                            +
   |                        |                |         | C_Sign()                   |
   +                        +                +         +----------------------------+
   |                        |                |         | C_MessageSignInit()        |
   +                        +                +         +                            +
   |                        |                |         | C_SignMessage()            |
   +------------------------+----------------+---------+----------------------------+
   | MAC Verification       | Single-Part    | SMW     | :c:func:`smw_mac`          |
   +                        +                +---------+----------------------------+
   |                        |                | PSA     | :c:func:`psa_mac_verify`   |
   +                        +                +---------+----------------------------+
   |                        |                | PKCS11  | C_VerifyInit()             |
   +                        +                +         +                            +
   |                        +                |         | C_Verify()                 |
   +                        +                +         +----------------------------+
   |                        |                |         | C_MessageVerifyInit()      |
   +                        +                +         +                            +
   |                        |                |         | C_VerifyMessage()          |
   +------------------------+----------------+---------+----------------------------+


HMAC
^^^^

.. table:: HMAC Support Details
   :name: table_hmac_support_details
   :align: center
   :widths: 15 15 14 14 14
   :width: 100%
   :class: wrap-table

   +---------------+----------------+----------------+-----------+---------------+
   | **Hash**      | **MAC Length** | **Subsystem**  | **Key**                   |
   +               +                +                +-----------+---------------+
   |               | **(bytes)**    |                | **Opaque**| **Plaintext** |
   +===============+================+================+===========+===============+
   | MD5           | 16             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | N         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA-1         | 20             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | N         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA-224       | 28             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | Y         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA-256       | 32             | ELE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | Y         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA-384       | 48             | ELE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | Y         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA-512       | 64             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | Y         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA3-224      | 28             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | N         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA3-256      | 32             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | N         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA3-384      | 48             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | N         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SHA3-512      | 64             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | N         | N             |
   +---------------+----------------+----------------+-----------+---------------+
   | SM3           | 32             | ELE            | N         | N             |
   +               +                +----------------+-----------+---------------+
   |               |                | TEE            | Y         | Y             |
   +               +                +----------------+-----------+---------------+
   |               |                | SECO           | N         | N             |
   +---------------+----------------+----------------+-----------+---------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For MAC operations, keys must be configured with appropriate key usage flags:

.. table:: HMAC Key Usage Flags
   :name: table_hmac_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | MAC Generation        | SMW     | SMW_ATTR_USAGE_SIGN_MESSAGE   |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_MESSAGE    |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | MAC Verification      | SMW     | SMW_ATTR_USAGE_VERIFY_MESSAGE |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_MESSAGE  |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+

Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the HMAC permitted algorithms.

Depending of the subsystem, the HMAC generated can be truncated (refer to the
:numref:`table_mac_operations_subsystem`). In this case, the key permitted
algorithm can be set to limit key usage when HMAC generated is truncated.

The :numref:`table_permitted_key_algorithms_full_hmac` details the key
permitted algorithms for full HMAC operations across different APIs and hash.
The Truncated HMAC is supported with this permitted algorithm.

The :numref:`table_permitted_key_algorithms_truncated_hmac` details the key
permitted algorithms for Truncated HMAC operations.

.. table:: Permitted Algorithms for Full HMAC
   :name: table_permitted_key_algorithms_full_hmac
   :align: center
   :widths: 15 12 78
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **MAC**         | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | HMAC            | SMW     | SMW_ATTR_ALGO_MAC_HMAC(hash, mac)                                  |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``hash`` is one of SMW Attribute Hash algorithm define in       |
   |                 |         |    the :numref:`table_algorithm_hash`.                             |
   |                 |         |  - ``mac`` is 0                                                    |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_HMAC(hash)                                                 |
   |                 |         |                                                                    |
   |                 |         | Where ``hash`` is one of PSA Hash algorithm (`PSA_ALG_xxx`) such   |
   |                 |         | as PSA_ALG_IS_HASH(hash) is true. Refer to :c:func:`PSA_ALG_HMAC`. |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be one or more CKM_SHAxxx_HMAC   |
   |                 |         | value.                                                             |
   |                 |         |                                                                    |
   |                 |         | If multiple CKM_SHAxxx_HMAC values are set, the key                |
   |                 |         | permitted algorithm is HMAC any hash type.                         |
   +-----------------+---------+--------------------------------------------------------------------+

.. table:: Permitted Algorithms for Truncated HMAC
   :name: table_permitted_key_algorithms_truncated_hmac
   :align: center
   :widths: 15 10 80
   :width: 100%
   :class: wrap-table

   +-----------------+---------+----------------------------------------------------------------------+
   | **MAC**         | **API** | **Permitted Algorithm**                                              |
   +=================+=========+======================================================================+
   | HMAC fix        | SMW     | SMW_ATTR_ALGO_MAC_HMAC(hash, mac)                                    |
   | truncated       |         |                                                                      |
   | length          |         | Where:\                                                              |
   |                 |         |                                                                      |
   |                 |         |   - ``hash`` is one of SMW Attribute Hash algorithm define in        |
   |                 |         |     the :numref:`table_algorithm_hash`.                              |
   |                 |         |   - ``mac`` is output MAC length that can't exceed the full MAC      |
   |                 |         |     length as detailed in the :numref:`table_hmac_support_details`.  |
   |                 |         |                                                                      |
   +                 +---------+----------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(hash), mac_length)                |
   |                 |         |                                                                      |
   |                 |         | Where: \                                                             |
   |                 |         |                                                                      |
   |                 |         |   - ``hash`` is one of PSA Hash algorithm (`PSA_ALG_xxx`) such       |
   |                 |         |     as PSA_ALG_IS_HASH(hash) is true. Refer to                       |
   |                 |         |     :c:func:`PSA_ALG_HMAC`.                                          |
   |                 |         |   - ``mac_length`` is output MAC length that can't exceed the full   |
   |                 |         |     MAC length as detailed in the                                    |
   |                 |         |     :numref:`table_hmac_support_details`.                            |
   |                 |         |                                                                      |
   +-----------------+---------+----------------------------------------------------------------------+
   | HMAC minimum    | SMW     | SMW_ATTR_SET_MIN_MAC_LENGTH(SMW_ATTR_ALGO_MAC_HMAC(hash, 0), length) |
   | truncated       |         |                                                                      |
   | length          |         | Where:\                                                              |
   |                 |         |                                                                      |
   |                 |         |   - ``hash`` is one of SMW Attribute Hash algorithm define in        |
   |                 |         |     the :numref:`table_algorithm_hash`.                              |
   |                 |         |   - ``length`` is minimum output MAC length, can't exceed the full   |
   |                 |         |     MAC length as detailed in the                                    |
   |                 |         |     :numref:`table_hmac_support_details`.                            |
   |                 |         |                                                                      |
   +                 +---------+----------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_HMAC(hash), min_mac_length) |
   |                 |         |                                                                      |
   |                 |         | Where: \                                                             |
   |                 |         |                                                                      |
   |                 |         |   - ``hash`` is one of PSA Hash algorithm (`PSA_ALG_xxx`) such       |
   |                 |         |     as PSA_ALG_IS_HASH(hash) is true. Refer to                       |
   |                 |         |     :c:func:`PSA_ALG_HMAC`.                                          |
   |                 |         |   - ``min_mac_length`` is minimum output MAC length that can't       |
   |                 |         |     exceed the full MAC length as detailed in the                    |
   |                 |         |     :numref:`table_hmac_support_details`.                            |
   |                 |         |                                                                      |
   +-----------------+---------+----------------------------------------------------------------------+

CMAC
^^^^

.. table:: CMAC Support Details
   :name: table_cmac_support_details
   :align: center
   :widths: 15 15 14 14 14
   :width: 100%
   :class: wrap-table

   +---------------+---------------+----------------+-----------+---------------+
   | **Cipher**    | **MAC Size**  | **Subsystem**  | **Key**                   |
   +               +               +                +-----------+---------------+
   |               | **(bytes)**   |                | **Opaque**| **Plaintext** |
   +===============+===============+================+===========+===============+
   | AES           | 16            | ELE            | Y         | Y             |
   +               +               +----------------+-----------+---------------+
   |               |               | TEE            | Y         | Y             |
   +               +               +----------------+-----------+---------------+
   |               |               | SECO           | Y         | N             |
   +---------------+---------------+----------------+-----------+---------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For MAC operations, keys must be configured with appropriate key usage flags:

.. table:: CMAC Key Usage Flags
   :name: table_cmac_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | MAC Generation        | SMW     | SMW_ATTR_USAGE_SIGN_MESSAGE   |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_MESSAGE    |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | MAC Verification      | SMW     | SMW_ATTR_USAGE_VERIFY_MESSAGE |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_MESSAGE  |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+

Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the CMAC permitted algorithms.

.. table:: Permitted Algorithms for CMAC
   :name: table_permitted_key_algorithms_cmac
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **MAC**         | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | CMAC            | SMW     | SMW_ATTR_ALGO_MAC_CMAC(cipher)                                     |
   |                 |         |                                                                    |
   |                 |         | Where ``cipher`` is SMW_ATTR_CIPHER_AES.                           |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_CMAC                                                       |
   |                 |         |                                                                    |
   |                 |         | Refer to :c:func:`PSA_ALG_CMAC`.                                   |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_AES_CMAC value.           |
   +-----------------+---------+--------------------------------------------------------------------+

Depending of the subsystem, the CMAC generated can be truncated (refer to the
:numref:`table_mac_operations_subsystem`). In this case, the key permitted
algorithm can be set to limit key usage when CMAC generated is truncated.

The :numref:`table_permitted_key_algorithms_full_cmac` details the key
permitted algorithms for full CMAC operations across different APIs and hash.
The Truncated HMAC is supported with this permitted algorithm.

The :numref:`table_permitted_key_algorithms_truncated_cmac` details the key
permitted algorithms for Truncated CMAC operations.

.. table:: Permitted Algorithms for Full CMAC
   :name: table_permitted_key_algorithms_full_cmac
   :align: center
   :widths: 15 12 78
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **MAC**         | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | HMAC            | SMW     | SMW_ATTR_ALGO_MAC(algo, mode, mac)                                 |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |   - ``algo`` is SMW_ATTR_ALGO_AES.                                 |
   |                 |         |   - ``mode`` is SMW_ATTR_MODE_CMAC.                                |
   |                 |         |   - ``mac`` is 0                                                   |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_CMAC                                                       |
   |                 |         |                                                                    |
   |                 |         | Refer to :c:func:`PSA_ALG_CMAC`.                                   |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_AES_CMAC value.           |
   +-----------------+---------+--------------------------------------------------------------------+

.. table:: Permitted Algorithms for Truncated CMAC
   :name: table_permitted_key_algorithms_truncated_cmac
   :align: center
   :widths: 15 10 80
   :width: 100%
   :class: wrap-table

   +-----------------+---------+---------------------------------------------------------------------------+
   | **MAC**         | **API** | **Permitted Algorithm**                                                   |
   +=================+=========+===========================================================================+
   | CMAC fix        | SMW     | SMW_ATTR_ALGO_MAC(algo, mode, mac)                                        |
   | truncated       |         |                                                                           |
   | length          |         | Where:\                                                                   |
   |                 |         |                                                                           |
   |                 |         |   - ``algo`` is SMW_ATTR_ALGO_AES.                                        |
   |                 |         |   - ``mode`` is SMW_ATTR_MODE_CMAC.                                       |
   |                 |         |   - ``mac`` is output MAC length that can't exceed the full MAC           |
   |                 |         |     length as detailed in the :numref:`table_cmac_support_details`.       |
   |                 |         |                                                                           |
   +                 +---------+---------------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_TRUNCATED_MAC(PSA_ALG_CMAC, mac_length)                           |
   |                 |         |                                                                           |
   |                 |         | Where: \                                                                  |
   |                 |         |                                                                           |
   |                 |         |   - ``mac_length`` is output MAC length that can't exceed the full        |
   |                 |         |     MAC length as detailed in the                                         |
   |                 |         |     :numref:`table_cmac_support_details`.                                 |
   |                 |         |                                                                           |
   +-----------------+---------+---------------------------------------------------------------------------+
   | CMAC minimum    | SMW     | SMW_ATTR_SET_MIN_MAC_LENGTH(SMW_ATTR_ALGO_MAC(algo, mode, 0), length)     |
   | truncated       |         |                                                                           |
   | length          |         | Where:\                                                                   |
   |                 |         |                                                                           |
   |                 |         |   - ``algo`` is SMW_ATTR_ALGO_AES.                                        |
   |                 |         |   - ``mode`` is SMW_ATTR_MODE_CMAC.                                       |
   |                 |         |   - ``length`` is minimum output MAC length, can't exceed the full        |
   |                 |         |     MAC length as detailed in the                                         |
   |                 |         |     :numref:`table_cmac_support_details`.                                 |
   |                 |         |                                                                           |
   +                 +---------+---------------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(PSA_ALG_CMAC, min_mac_length)            |
   |                 |         |                                                                           |
   |                 |         | Where: \                                                                  |
   |                 |         |                                                                           |
   |                 |         |   - ``min_mac_length`` is minimum output MAC length that can't            |
   |                 |         |     exceed the full MAC length as detailed in the                         |
   |                 |         |     :numref:`table_cmac_support_details`.                                 |
   |                 |         |                                                                           |
   +-----------------+---------+---------------------------------------------------------------------------+

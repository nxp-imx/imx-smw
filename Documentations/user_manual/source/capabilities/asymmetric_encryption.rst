Asymmetric Encryption
---------------------

This section documents the asymmetric encryption operations supported across
different security subsystems (ELE, TEE, SECO) with their respective algorithms
and key types.

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: Asymmetric Encryption Operations vs. subsystem
   :name: table_asym_enc_operations_subsystem
   :align: center
   :widths: 10 17 15 10 10 10 23
   :class: wrap-table

   +--------------+---------------+----------------+---------+---------+----------+-----------------------------+
   | **Key Type** | **Algorithm** | **Processing** | **Subsystem**                | **Notes**                   |
   +              +               +                +---------+---------+----------+                             +
   |              |               |                | **ELE** | **TEE** | **SECO** |                             |
   +==============+===============+================+=========+=========+==========+=============================+
   | RSA          | PKCS#1 v1.5   | Single-Part    | **Y***  |    Y    |    N     | **ELE** not supported on:\  |
   |              |               |                |         |         |          |                             |
   |              |               |                |         |         |          |  - i.MX8ULP                 |
   |              |               |                |         |         |          |                             |
   +              +---------------+----------------+---------+---------+----------+                             +
   |              | OAEP          | Single-Part    |    Y    |    Y    |    N     |                             |
   +              +---------------+----------------+---------+---------+----------+                             +
   |              | No Padding    | Single-Part    |    N    |    Y    |    N     |                             |
   +--------------+---------------+----------------+---------+---------+----------+-----------------------------+


.. table:: Asymmetric Encryption APIs
   :name: table_asym_enc_apis
   :align: center
   :widths: 25 15 15 45
   :width: 100%
   :class: wrap-table

   +----------------+----------------+---------+------------------------------------+
   | **Operations** | **Processing** | **API** | **Functions**                      |
   +================+================+=========+====================================+
   | Encryption     | Single-Part    | SMW     | :c:func:`smw_asymmetric_encrypt`   |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_asymmetric_encrypt`   |
   +                +                +---------+------------------------------------+
   |                |                | PKCS11  | C_EncryptInit()                    |
   +                +                +         +                                    +
   |                |                |         | C_Encrypt()                        |
   +                +                +         +------------------------------------+
   |                |                |         | C_MessageEncryptInit()             |
   +                +                +         +                                    +
   |                |                |         | C_EncryptMessage()                 |
   +----------------+----------------+---------+------------------------------------+
   | Decryption     | Single-Part    | SMW     | :c:func:`smw_asymmetric_decrypt`   |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_asymmetric_decrypt`   |
   +                +                +---------+------------------------------------+
   |                |                | PKCS11  | C_DecryptInit()                    |
   +                +                +         +                                    +
   |                |                |         | C_Decrypt()                        |
   +                +                +         +------------------------------------+
   |                |                |         | C_MessageDecryptInit()             |
   +                +                +         +                                    +
   |                |                |         | C_DecryptMessage()                 |
   +----------------+----------------+---------+------------------------------------+


RSA PKCS#1 v1.5 Asymmetric Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: RSA PKCS#1 v1.5 Support Details
   :name: table_rsa_pkcs1_v15_asym_enc_support_details
   :align: center
   :widths: 35 15 14 14
   :class: wrap-table

   +--------------------+---------------+------------+---------------+
   | **Key Size**       | **Subsystem** | **Key**                    |
   +                    +               +------------+---------------+
   |                    |               | **Opaque** | **Plaintext** |
   +====================+===============+============+===============+
   | 2048 / 3072 / 4096 | ELE           | Y          | Y             |
   +--------------------+---------------+------------+---------------+
   | 256 to 4096        | TEE           | Y          | Y             |
   +                    +               +            +               +
   | multiple of 2 bits |               |            |               |
   +--------------------+---------------+------------+---------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For RSA PKCS#1 v1.5 Asymmetric Encryption operations, keys must be configured
with appropriate key usage flags:

.. table:: RSA PKCS#1 v1.5 Asymmetric encryption Key Usage Flags
   :name: table_rsa_pkcs1_v15_asym_enc_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | Encryption            | SMW     | SMW_ATTR_USAGE_ENCRYPT        |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_ENCRYPT         |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_ENCRYPT                   |
   +-----------------------+---------+-------------------------------+
   | Decryption            | SMW     | SMW_ATTR_USAGE_DECRYPT        |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_DECRYPT         |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_DECRYPT                   |
   +-----------------------+---------+-------------------------------+


Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the permitted RSA PKCS#1 v1.5 Asymmetric
Encryption algorithms.

.. table:: Permitted Algorithms for RSA PKCS#1 v1.5 Asymmetric Encryption
   :name: table_permitted_key_algorithms_rsa_pkcs1_v15_asym_enc
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+----------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                            |
   +=================+=========+====================================================+
   | RSA             | SMW     | SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION(mode, hash)    |
   |                 |         |                                                    |
   |                 |         | Where:\                                            |
   |                 |         |                                                    |
   |                 |         |  - ``mode`` is SMW_ATTR_ALGO_RSA_PKCS1V15.         |
   |                 |         |  - ``hash`` is the SMW_ATTR_HASH_NONE.             |
   +                 +---------+----------------------------------------------------+
   |                 | PSA     | Permitted algorithm is PSA_ALG_RSA_PKCS1V15_CRYPT. |
   +                 +---------+----------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_RSA_PKCS. |
   +-----------------+---------+----------------------------------------------------+

RSA OAEP Asymmetric Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: RSA OAEP Support Details
   :name: table_rsa_oaep_asym_enc_support_details
   :align: center
   :widths: 35 15 15 14 14
   :class: wrap-table

   +--------------------+----------+---------------+------------+---------------+
   | **Key Size**       | **Hash** | **Subsystem** | **Key**                    |
   +                    +          +               +------------+---------------+
   |                    |          |               | **Opaque** | **Plaintext** |
   +====================+==========+===============+============+===============+
   | 2048 / 3072 / 4096 | SHA1     | ELE           | Y          | Y             |
   +                    +          +               +            +               +
   |                    | SHA224   |               |            |               |
   +                    +          +               +            +               +
   |                    | SHA256   |               |            |               |
   +                    +          +               +            +               +
   |                    | SHA384   |               |            |               |
   +                    +          +               +            +               +
   |                    | SHA512   |               |            |               |
   +--------------------+----------+---------------+------------+---------------+
   | 256 to 4096        | SHA1     | TEE           | Y          | Y             |
   +                    +          +               +            +               +
   | multiple of 2 bits | SHA224   |               |            |               |
   +                    +          +               +            +               +
   |                    | SHA256   |               |            |               |
   +                    +          +               +            +               +
   |                    | SHA384   |               |            |               |
   +                    +          +               +            +               +
   |                    | SHA512   |               |            |               |
   +--------------------+----------+---------------+------------+---------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For RSA OAEP Asymmetric Encryption operations, keys must be configured
with appropriate key usage flags:

.. table:: RSA OAEP Asymmetric encryption Key Usage Flags
   :name: table_rsa_oaep_asym_enc_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | Encryption            | SMW     | SMW_ATTR_USAGE_ENCRYPT        |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_ENCRYPT         |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_ENCRYPT                   |
   +-----------------------+---------+-------------------------------+
   | Decryption            | SMW     | SMW_ATTR_USAGE_DECRYPT        |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_DECRYPT         |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_DECRYPT                   |
   +-----------------------+---------+-------------------------------+


Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the permitted RSA OAEP Asymmetric
Encryption algorithms.

.. table:: Permitted Algorithms for RSA OAEP Asymmetric Encryption
   :name: table_permitted_key_algorithms_rsa_oaep_asym_enc
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | RSA             | SMW     | SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION(mode, hash)                    |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``mode`` is SMW_ATTR_ALGO_RSA_OAEP.                             |
   |                 |         |  - ``hash`` is one of SMW Attribute Hash algorithm define in the   |
   |                 |         |    :numref:`table_algorithm_hash`.                                 |
   |                 |         |                                                                    |
   |                 |         | Supported hash are listed in the                                   |
   |                 |         | :numref:`table_rsa_oaep_asym_enc_support_details`.                 |
   |                 |         |                                                                    |
   |                 |         | Defining a hash algorithm as SMW_ATTR_HASH_ANY, allow to use the   |
   |                 |         | key for any hash algorithm.                                        |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_RSA_OAEP(hash)                                             |
   |                 |         |                                                                    |
   |                 |         | Where ``hash`` is one of PSA Hash algorithm (`PSA_ALG_xxx`) such   |
   |                 |         | as PSA_ALG_IS_HASH(hash) is true.                                  |
   |                 |         |                                                                    |
   |                 |         | Supported hash are listed in the                                   |
   |                 |         | :numref:`table_rsa_oaep_asym_enc_support_details`.                 |
   |                 |         |                                                                    |
   |                 |         | Defining a ``hash`` algorithm as PSA_ALG_ANY_HASH, allow to use    |
   |                 |         | the key for any hash algorithm.                                    |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_RSA_PKCS_OAEP.            |
   +-----------------+---------+--------------------------------------------------------------------+

RSA No Padding Asymmetric Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: RSA No Padding Support Details
   :name: table_rsa_no_padding_asym_enc_support_details
   :align: center
   :widths: 35 15 14 14
   :class: wrap-table

   +--------------------+---------------+------------+---------------+
   | **Key Size**       | **Subsystem** | **Key**                    |
   +                    +               +------------+---------------+
   |                    |               | **Opaque** | **Plaintext** |
   +====================+===============+============+===============+
   | 256 to 4096        | TEE           | Y          | Y             |
   +                    +               +            +               +
   | multiple of 2 bits |               |            |               |
   +--------------------+---------------+------------+---------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For RSA No Padding Asymmetric Encryption operations, keys must be configured
with appropriate key usage flags:

.. table:: RSA No Padding Asymmetric encryption Key Usage Flags
   :name: table_rsa_no_padding_asym_enc_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | Encryption            | SMW     | SMW_ATTR_USAGE_ENCRYPT        |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_ENCRYPT         |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_ENCRYPT                   |
   +-----------------------+---------+-------------------------------+
   | Decryption            | SMW     | SMW_ATTR_USAGE_DECRYPT        |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_DECRYPT         |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_DECRYPT                   |
   +-----------------------+---------+-------------------------------+


Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the permitted RSA No Padding Asymmetric
Encryption algorithms.

.. table:: Permitted Algorithms for RSA No Padding Asymmetric Encryption
   :name: table_permitted_key_algorithms_rsa_no_padding_asym_enc
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | RSA             | SMW     | SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION(mode, hash)                    |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``mode`` is SMW_ATTR_MODE_NO_PAD.                               |
   |                 |         |  - ``hash`` is the SMW_ATTR_HASH_NONE.                             |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | No defined.                                                        |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_RSA_X_509.                |
   +-----------------+---------+--------------------------------------------------------------------+

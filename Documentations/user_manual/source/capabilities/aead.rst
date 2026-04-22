Authentication Encryption with Associated Data (AEAD)
-----------------------------------------------------

This section documents the AEAD (Authentication Encryption with Associated Data)
operations supported across different security subsystems (ELE, TEE, SECO) with
their respective algorithms and modes.

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: AEAD Operations vs. subsystem
   :name: table_aead_operations_subsystem
   :align: center
   :widths: 10 15 15 10 10 10 30
   :class: wrap-table

   +--------------+------------------------+----------------+---------+---------+----------+-----------------------------+
   | **Key Type** | **Mode**               | **Processing** | **Subsystem**                | **Notes**                   |
   +              +                        +                +---------+---------+----------+                             +
   |              |                        |                | **ELE** | **TEE** | **SECO** |                             |
   +==============+========================+================+=========+=========+==========+=============================+
   | AES          | Counter with CBC-MAC   | Single-Part    |    Y    |    Y    |    Y     |                             |
   +              +                        +----------------+---------+---------+----------+                             +
   |              | (CCM)                  | Multi-Part     |    N    |    Y    |    N     |                             |
   +              +------------------------+----------------+---------+---------+----------+-----------------------------+
   |              | Galois/Counter Mode    | Single-Part    |  **Y*** |    Y    |    Y     | **ELE** not supported on:\  |
   +              +                        +----------------+---------+---------+----------+                             +
   |              | (GCM)                  | Multi-Part     |    N    |    Y    |    N     |  - i.MX8ULP                 |
   +              +------------------------+----------------+---------+---------+----------+                             +
   |              | ChaCha20-Poly1305      | Single-Part    |  **Y*** |    N    |    N     |                             |
   +              +                        +----------------+---------+---------+----------+                             +
   |              |                        | Multi-Part     |    N    |    N    |    N     |                             |
   +--------------+------------------------+----------------+---------+---------+----------+-----------------------------+

.. table:: AEAD APIs
   :name: table_aead_apis
   :align: center
   :widths: 25 15 15 45
   :width: 100%
   :class: wrap-table

   +----------------+----------------+---------+------------------------------------+
   | **Operations** | **Processing** | **API** | **SMW**                            |
   +================+================+=========+====================================+
   | Encryption     | Single-Part    | SMW     | :c:func:`smw_aead`                 |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_aead_encrypt`         |
   +                +                +---------+------------------------------------+
   |                |                | PKCS11  | C_EncryptInit()                    |
   +                +                +         +                                    +
   |                |                |         | C_Encrypt()                        |
   +                +                +         +------------------------------------+
   |                |                |         | C_MessageEncryptInit()             |
   +                +                +         +                                    +
   |                |                |         | C_EncryptMessage()                 |
   +                +----------------+---------+------------------------------------+
   |                | Multi-Part     | SMW     | :c:func:`smw_allocate_context`     |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_init`            |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_update_aad`      |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_update`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_final`           |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cancel_operation`     |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_aead_encrypt_setup`   |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_generate_nonce`  |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_set_nonce`       |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_set_lengths`     |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_update_ad`       |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_update`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_finish`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_abort`           |
   +                +                +---------+------------------------------------+
   |                |                | PKCS11  | C_EncryptInit()                    |
   +                +                +         +                                    +
   |                |                |         | C_EncryptUpdate()                  |
   +                +                +         +                                    +
   |                |                |         | C_EncryptFinal()                   |
   +                +                +         +------------------------------------+
   |                |                |         | C_MessageEncryptInit()             |
   +                +                +         +                                    +
   |                |                |         | C_EncryptMessageBegin()            |
   +                +                +         +                                    +
   |                |                |         | C_EncryptMessageNext()             |
   +                +                +         +                                    +
   |                |                |         | C_EncryptMessageFinal()            |
   +----------------+----------------+---------+------------------------------------+
   | Decryption     | Single-Part    | SMW     | :c:func:`smw_aead`                 |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_aead_decrypt`         |
   +                +                +---------+------------------------------------+
   |                |                | PKCS11  | C_DecryptInit()                    |
   +                +                +         +                                    +
   |                |                |         | C_Decrypt()                        |
   +                +                +         +------------------------------------+
   |                |                |         | C_MessageDecryptInit()             |
   +                +                +         +                                    +
   |                |                |         | C_DecryptMessage()                 |
   +                +----------------+---------+------------------------------------+
   |                | Multi-Part     | SMW     | :c:func:`smw_allocate_context`     |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_init`            |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_update_aad`      |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_update`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_aead_final`           |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cancel_operation`     |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_aead_decrypt_setup`   |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_set_nonce`       |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_set_lengths`     |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_update_ad`       |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_update`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_verify`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_aead_abort`           |
   +                +                +---------+------------------------------------+
   |                |                | PKCS11  | C_DecryptInit()                    |
   +                +                +         +                                    +
   |                |                |         | C_DecryptUpdate()                  |
   +                +                +         +                                    +
   |                |                |         | C_DecryptFinal()                   |
   +                +                +         +------------------------------------+
   |                |                |         | C_MessageDecryptInit()             |
   +                +                +         +                                    +
   |                |                |         | C_DecryptMessageBegin()            |
   +                +                +         +                                    +
   |                |                |         | C_DecryptMessageNext()             |
   +                +                +         +                                    +
   |                |                |         | C_DecryptMessageFinal()            |
   +----------------+----------------+---------+------------------------------------+

AES AEAD
^^^^^^^^

.. table:: AES AEAD Support Details
   :name: table_aes_aead_support_details
   :align: center
   :widths: 25 15 20 20
   :class: wrap-table

   +-----------------------+---------------+------------+-----------------+
   | **Key Security Size** | **Subsystem** | **Key**                      |
   +                       +               +------------+-----------------+
   | **(bits)**            |               | **Opaque** | **Plaintext**   |
   +=======================+===============+============+=================+
   | 128                   | ELE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | TEE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | SECO          | Y          | N               |
   +-----------------------+---------------+------------+-----------------+
   | 192                   | ELE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | TEE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | SECO          | Y          | N               |
   +-----------------------+---------------+------------+-----------------+
   | 256                   | ELE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | TEE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | SECO          | Y          | N               |
   +-----------------------+---------------+------------+-----------------+

.. table:: AES AEAD IV length Support
   :name: table_aes_aead_iv_length
   :align: center
   :widths: 25 15 40 20
   :width: 100%
   :class: wrap-table

   +-------------------+---------------+-----------------------------------------+----------------+
   | **Mode**          | **Subsystem** | **Nonce or IV length**                  | **Tag length** |
   +                   +               +                                         +                +
   |                   |               | **(bytes)**                             | **(bytes)**    |
   +===================+===============+=========================================+================+
   | Counter with      | ELE           | 12                                      |       16       |
   +                   +               +                                         +                +
   | CBC-MAC (CCM)     | SECO          |                                         |                |
   +                   +---------------+-----------------------------------------+----------------+
   |                   | TEE           | From 1 to 13                            | 4 / 6 / 8 /    |
   |                   |               |                                         | 10 / 12 / 14 / |
   |                   |               |                                         | 16             |
   +-------------------+---------------+-----------------------------------------+----------------+
   | Galois/Counter    | ELE           | Encryption:                             |       16       |
   | Mode (GCM)        |               |                                         |                |
   |                   |               | - 0 (subsystem generates full IV)       |                |
   |                   |               | - 4 (subsystem generates 8 bytes of IV) |                |
   |                   |               | - 12 (user supplied full IV)            |                |
   +                   +               +-----------------------------------------+                +
   |                   |               | Decryption:                             |                |
   |                   |               |                                         |                |
   |                   |               | - 12 (user supplied full IV)            |                |
   +                   +---------------+-----------------------------------------+----------------+
   |                   | SECO          | Encryption:                             |       16       |
   |                   |               |                                         |                |
   |                   |               | - 0 (subsystem generates full IV)       |                |
   |                   |               | - 4 (subsystem generates 8 bytes of IV) |                |
   +                   +               +-----------------------------------------+                +
   |                   |               | Decryption:                             |                |
   |                   |               |                                         |                |
   |                   |               | - 12 (user supplied full IV)            |                |
   +                   +---------------+-----------------------------------------+----------------+
   |                   | TEE           | From 1 to 16 (Recommended is 12)        | 12 / 13 / 14 / |
   |                   |               |                                         | 15 / 16        |
   +-------------------+---------------+-----------------------------------------+----------------+
   | ChaCha20-Poly1305 | ELE           | 12                                      |       16       |
   +-------------------+---------------+-----------------------------------------+----------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For AES AEAD operations, keys must be configured with appropriate key usage flags:

.. table:: AES AEAD Key Usage Flags
   :name: table_aes_aead_key_usage
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
The following table outlines the permitted AES AEAD algorithms.

.. table:: Permitted Algorithms for AES AEAD
   :name: table_permitted_key_algorithms_aes_aead
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | AES             | SMW     | SMW_ATTR_ALGO_AEAD(algo, mode, tag)                                |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``algo`` is SMW_ATTR_ALGO_AES.                                  |
   |                 |         |  - ``mode`` is one of the values of the following table.           |
   |                 |         |  - ``tag`` is 0. Not used for the key permitted algorithm.         |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Counter with CBC-MAC (CCM)                                  |
   |                 |         |      - SMW_ATTR_MODE_CCM                                           |
   |                 |         |    * - Galois/Counter Mode (GCM)                                   |
   |                 |         |      - SMW_ATTR_MODE_GCM                                           |
   |                 |         |    * - ChaCha20-Poly1305                                           |
   |                 |         |      - SMW_ATTR_MODE_POLY1305                                      |
   |                 |         |    * - Any mode                                                    |
   |                 |         |      - SMW_ATTR_MODE_ANY                                           |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | Permitted algorithm is one of the value of the following table.    |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Counter with CBC-MAC (CCM)                                  |
   |                 |         |      - PSA_ALG_CCM                                                 |
   |                 |         |    * - Galois/Counter Mode (GCM)                                   |
   |                 |         |      - PSA_ALG_GCM                                                 |
   |                 |         |    * - ChaCha20-Poly1305                                           |
   |                 |         |      - PSA_ALG_CHACHA20_POLY1305                                   |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be one of the mechanism of the   |
   |                 |         | following table. If multiple AEAD mechanisms are allowed, the key  |
   |                 |         | can be used with any of AEAD mechanisms listed below.              |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Counter with CBC-MAC (CCM)                                  |
   |                 |         |      - CKM_AES_CCM                                                 |
   |                 |         |    * - Galois/Counter Mode (GCM)                                   |
   |                 |         |      - CKM_AES_GCM                                                 |
   |                 |         |    * - ChaCha20-Poly1305                                           |
   |                 |         |      - CKM_CHACHA20_POLY1305                                       |
   |                 |         |                                                                    |
   +-----------------+---------+--------------------------------------------------------------------+

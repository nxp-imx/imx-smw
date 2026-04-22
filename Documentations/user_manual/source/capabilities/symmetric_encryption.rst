.. _capabilities_symmetric_encryption:

Symmetric Encryption
--------------------

This section documents the symmetric encryption operations supported across
different security subsystems (ELE, TEE, SECO) with their respective modes and
algorithms.

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: Symmetric Encryption Operations vs. subsystem
   :name: table_sym_enc_operations_subsystem
   :align: center
   :widths: 10 15 15 10 10 10
   :class: wrap-table

   +--------------+------------------------+----------------+---------+---------+----------+
   | **Key Type** | **Modes**              | **Processing** | **Subsystem**                |
   +              +                        +                +---------+---------+----------+
   |              |                        |                | **ELE** | **TEE** | **SECO** |
   +==============+========================+================+=========+=========+==========+
   | AES          | Electronic Codebook    | Single-Part    |    Y    |    Y    |    Y     |
   +              +                        +----------------+---------+---------+----------+
   |              | (ECB) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Cipher Block Chaining  | Single-Part    |    Y    |    Y    |    Y     |
   +              +                        +----------------+---------+---------+----------+
   |              | (CBC) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Counter (CTR)          | Single-Part    |    Y    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              |                        | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Cipher Feedback (CFB)  | Single-Part    |    Y    |    N    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              |                        | Multi-Part     |    N    |    N    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Output Feedback (OFB)  | Single-Part    |    Y    |    N    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              |                        | Multi-Part     |    N    |    N    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Ciphertext Stealing    | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              | (CTS)                  | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | XEX with Ciphertext    | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              | Stealing (XTS)         | Multi-Part     |    N    |    Y    |    N     |
   +--------------+------------------------+----------------+---------+---------+----------+
   | DES          | Electronic Codebook    | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              | (ECB) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Cipher Block Chaining  | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              | (CBC) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +--------------+------------------------+----------------+---------+---------+----------+
   | Triple DES   | Electronic Codebook    | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   | (DES3)       | (ECB) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Cipher Block Chaining  | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              | (CBC) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +--------------+------------------------+----------------+---------+---------+----------+
   | SM4          | Electronic Codebook    | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              | (ECB) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Cipher Block Chaining  | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              | (CBC) with no padding  | Multi-Part     |    N    |    Y    |    N     |
   +              +------------------------+----------------+---------+---------+----------+
   |              | Counter (CTR)          | Single-Part    |    N    |    Y    |    N     |
   +              +                        +----------------+---------+---------+----------+
   |              |                        | Multi-Part     |    N    |    Y    |    N     |
   +--------------+------------------------+----------------+---------+---------+----------+

.. table:: Symmetric Encryption APIs
   :name: table_sym_enc_apis
   :align: center
   :widths: 25 15 15 45
   :width: 100%
   :class: wrap-table

   +----------------+----------------+---------+------------------------------------+
   | **Operations** | **Processing** | **API** | **SMW**                            |
   +================+================+=========+====================================+
   | Encryption     | Single-Part    | SMW     | :c:func:`smw_cipher`               |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_cipher_encrypt`       |
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
   |                |                |         | :c:func:`smw_cipher_init`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cipher_update`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cipher_final`         |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cancel_operation`     |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_cipher_encrypt_setup` |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_generate_iv`   |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_set_iv`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_update`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_finish`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_abort`         |
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
   | Decryption     | Single-Part    | SMW     | :c:func:`smw_cipher`               |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_cipher_decrypt`       |
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
   |                |                |         | :c:func:`smw_cipher_init`          |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cipher_update`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cipher_final`         |
   +                +                +         +                                    +
   |                |                |         | :c:func:`smw_cancel_operation`     |
   +                +                +---------+------------------------------------+
   |                |                | PSA     | :c:func:`psa_cipher_decrypt_setup` |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_set_iv`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_update`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_finish`        |
   +                +                +         +                                    +
   |                |                |         | :c:func:`psa_cipher_abort`         |
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

AES Symmetric Encryption
^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: AES Support Details
   :name: table_aes_support_details
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


Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For AES Symmetric Encryption operations, keys must be configured with
appropriate key usage flags:

.. table:: AES Symmetric encryption Key Usage Flags
   :name: table_aes_sym_enc_key_usage
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
The following table outlines the permitted AES Symmetric Encryption algorithms.

.. table:: Permitted Algorithms for AES Symmetric Encryption
   :name: table_permitted_key_algorithms_aes_sym_enc
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | AES             | SMW     | SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(algo, mode)                     |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``algo`` is SMW_ATTR_ALGO_AES.                                  |
   |                 |         |  - ``mode`` is one of the value of the following table.            |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - SMW_ATTR_MODE_ECB_NO_PAD                                    |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - SMW_ATTR_MODE_CBC_NO_PAD                                    |
   |                 |         |    * - Counter (CTR)                                               |
   |                 |         |      - SMW_ATTR_MODE_CTR                                           |
   |                 |         |    * - Cipher Feedback (CFB)                                       |
   |                 |         |      - SMW_ATTR_MODE_CFB                                           |
   |                 |         |    * - Ciphertext Stealing (CTS)                                   |
   |                 |         |      - SMW_ATTR_MODE_CTS                                           |
   |                 |         |    * - Output Feedback (OFB)                                       |
   |                 |         |      - SMW_ATTR_MODE_OFB                                           |
   |                 |         |    * - XEX with Ciphertext Stealing (XTS)                          |
   |                 |         |      - SMW_ATTR_MODE_XTS                                           |
   |                 |         |    * - Any mode                                                    |
   |                 |         |      - SMW_ATTR_MODE_ANY                                           |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | Permitted alogithm is one of the value of the following table.     |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - PSA_ALG_ECB_NO_PADDING                                      |
   |                 |         |    * - Cipher Block Chaining (CBC) wtih no padding                 |
   |                 |         |      - PSA_ALG_CBC_NO_PADDING                                      |
   |                 |         |    * - Counter (CTR)                                               |
   |                 |         |      - PSA_ALG_CTR                                                 |
   |                 |         |    * - Cipher Feedback (CFB)                                       |
   |                 |         |      - PSA_ALG_CFB                                                 |
   |                 |         |    * - Output Feedback (OFB)                                       |
   |                 |         |      - PSA_ALG_OFB                                                 |
   |                 |         |    * - XEX with Ciphertext Stealing (XTS)                          |
   |                 |         |      - PSA_ALG_XTS                                                 |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be one of the mechanism of the   |
   |                 |         | following table. If multiple symmetric encryption mechanisms are   |
   |                 |         | allowed, the key can be used with any of symmetric encryption      |
   |                 |         | mechanisms listed below.                                           |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - CKM_AES_ECB                                                 |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - CKM_AES_CBC                                                 |
   |                 |         |    * - Counter (CTR)                                               |
   |                 |         |      - CKM_AES_CTR                                                 |
   |                 |         |    * - Ciphertext Stealing (CTS)                                   |
   |                 |         |      - CKM_AES_CTS                                                 |
   |                 |         |    * - XEX with Ciphertext Stealing (XTS)                          |
   |                 |         |      - CKM_AES_XTS                                                 |
   |                 |         |                                                                    |
   +-----------------+---------+--------------------------------------------------------------------+


DES Symmetric Encryption
^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: DES Support Details
   :name: table_des_support_details
   :align: center
   :widths: 25 15 20 20
   :class: wrap-table

   +-----------------------+---------------+------------+-----------------+
   | **Key Security Size** | **Subsystem** | **Key**                      |
   +                       +               +------------+-----------------+
   | **(bits)**            |               | **Opaque** | **Plaintext**   |
   +=======================+===============+============+=================+
   | 56                    | ELE           | N          | N               |
   +                       +---------------+------------+-----------------+
   |                       | TEE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | SECO          | N          | N               |
   +-----------------------+---------------+------------+-----------------+


Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For DES Symmetric Encryption operations, keys must be configured with
appropriate key usage flags:

.. table:: DES Symmetric encryption Key Usage Flags
   :name: table_des_sym_enc_key_usage
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
The following table outlines the permitted DES Symmetric Encryption algorithms.

.. table:: Permitted Algorithms for DES Symmetric Encryption
   :name: table_permitted_key_algorithms_des_sym_enc
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | DES             | SMW     | SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(algo, mode)                     |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``algo`` is SMW_ATTR_ALGO_DES.                                  |
   |                 |         |  - ``mode`` is one of the value of the following table.            |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - SMW_ATTR_MODE_ECB_NO_PAD                                    |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - SMW_ATTR_MODE_CBC_NO_PAD                                    |
   |                 |         |    * - Any mode                                                    |
   |                 |         |      - SMW_ATTR_MODE_ANY                                           |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | Permitted alogithm is one of the value of the following table.     |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - PSA_ALG_ECB_NO_PADDING                                      |
   |                 |         |    * - Cipher Block Chaining (CBC) wtih no padding                 |
   |                 |         |      - PSA_ALG_CBC_NO_PADDING                                      |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be one of the mechanism of the   |
   |                 |         | following table. If multiple symmetric encryption mechanisms are   |
   |                 |         | allowed, the key can be used with any of symmetric encryption      |
   |                 |         | mechanisms listed below.                                           |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - CKM_DES_ECB                                                 |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - CKM_DES_CBC                                                 |
   +-----------------+---------+--------------------------------------------------------------------+

Triple-DES (DES3) Symmetric Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: Triple-DES Support Details
   :name: table_des3_support_details
   :align: center
   :widths: 25 15 20 20
   :class: wrap-table

   +-----------------------+---------------+------------+-----------------+
   | **Key Security Size** | **Subsystem** | **Key**                      |
   +                       +               +------------+-----------------+
   | **(bits)**            |               | **Opaque** | **Plaintext**   |
   +=======================+===============+============+=================+
   | 112                   | ELE           | N          | N               |
   +                       +---------------+------------+-----------------+
   |                       | TEE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | SECO          | N          | N               |
   +-----------------------+---------------+------------+-----------------+
   | 168                   | ELE           | N          | N               |
   +                       +---------------+------------+-----------------+
   |                       | TEE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | SECO          | N          | N               |
   +-----------------------+---------------+------------+-----------------+


Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For Triple-DES Symmetric Encryption operations, keys must be configured with
appropriate key usage flags:

.. table:: Triple-DES Symmetric encryption Key Usage Flags
   :name: table_des3_sym_enc_key_usage
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
The following table outlines the permitted Triple-DES Symmetric Encryption
algorithms.

.. table:: Permitted Algorithms for Triple-DES Symmetric Encryption
   :name: table_permitted_key_algorithms_des3_sym_enc
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | Triple-DES      | SMW     | SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(algo, mode)                     |
   | (DES3)          |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``algo`` is SMW_ATTR_ALGO_DES3.                                 |
   |                 |         |  - ``mode`` is one of the value of the following table.            |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - SMW_ATTR_MODE_ECB_NO_PAD                                    |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - SMW_ATTR_MODE_CBC_NO_PAD                                    |
   |                 |         |    * - Any mode                                                    |
   |                 |         |      - SMW_ATTR_MODE_ANY                                           |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | Permitted alogithm is one of the value of the following table.     |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - PSA_ALG_ECB_NO_PADDING                                      |
   |                 |         |    * - Cipher Block Chaining (CBC) wtih no padding                 |
   |                 |         |      - PSA_ALG_CBC_NO_PADDING                                      |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be one of the mechanism of the   |
   |                 |         | following table. If multiple symmetric encryption mechanisms are   |
   |                 |         | allowed, the key can be used with any of symmetric encryption      |
   |                 |         | mechanisms listed below.                                           |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - CKM_DES3_ECB                                                |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - CKM_DES3_CBC                                                |
   +-----------------+---------+--------------------------------------------------------------------+

SM4 Symmetric Encryption
^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: SM4 Support Details
   :name: table_sm4_support_details
   :align: center
   :widths: 25 15 20 20
   :class: wrap-table

   +-----------------------+---------------+------------+-----------------+
   | **Key Security Size** | **Subsystem** | **Key**                      |
   +                       +               +------------+-----------------+
   | **(bits)**            |               | **Opaque** | **Plaintext**   |
   +=======================+===============+============+=================+
   | 128                   | ELE           | N          | N               |
   +                       +---------------+------------+-----------------+
   |                       | TEE           | Y          | Y               |
   +                       +---------------+------------+-----------------+
   |                       | SECO          | N          | N               |
   +-----------------------+---------------+------------+-----------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For SM4 Symmetric Encryption operations, keys must be configured with
appropriate key usage flags:

.. table:: SM4 Symmetric encryption Key Usage Flags
   :name: table_sm4_sym_enc_key_usage
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
The following table outlines the permitted SM4 Symmetric Encryption
algorithms.

.. table:: Permitted Algorithms for SM4 Symmetric Encryption
   :name: table_permitted_key_algorithms_sm4_sym_enc
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Key Type**    | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | SM4             | SMW     | SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(algo, mode)                     |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``algo`` is SMW_ATTR_ALGO_SM4.                                  |
   |                 |         |  - ``mode`` is one of the value of the following table.            |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - SMW_ATTR_MODE_ECB_NO_PAD                                    |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - SMW_ATTR_MODE_CBC_NO_PAD                                    |
   |                 |         |    * - Counter (CTR)                                               |
   |                 |         |      - SMW_ATTR_MODE_CTR                                           |
   |                 |         |    * - Any mode                                                    |
   |                 |         |      - SMW_ATTR_MODE_ANY                                           |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | Permitted alogithm is one of the value of the following table.     |
   |                 |         |                                                                    |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - PSA_ALG_ECB_NO_PADDING                                      |
   |                 |         |    * - Cipher Block Chaining (CBC) wtih no padding                 |
   |                 |         |      - PSA_ALG_CBC_NO_PADDING                                      |
   |                 |         |    * - Counter (CTR)                                               |
   |                 |         |      - PSA_ALG_CTR                                                 |
   |                 |         |                                                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be one of the mechanism of the   |
   |                 |         | following table. If multiple symmetric encryption mechanisms are   |
   |                 |         | allowed, the key can be used with any of symmetric encryption      |
   |                 |         | mechanisms listed below.                                           |
   |                 |         |                                                                    |
   |                 |         | .. list-table::                                                    |
   |                 |         |    :header-rows: 1                                                 |
   |                 |         |    :widths: 40 60                                                  |
   |                 |         |    :class: inner-table                                             |
   |                 |         |                                                                    |
   |                 |         |    * - **Mode**                                                    |
   |                 |         |      - **Value**                                                   |
   |                 |         |    * - Electronic Codebook (ECB) with no padding                   |
   |                 |         |      - CKM_SM4_ECB (Vendor define)                                 |
   |                 |         |    * - Cipher Block Chaining (CBC) with no padding                 |
   |                 |         |      - CKM_SM4_CBC (Vendor define)                                 |
   |                 |         |    * - Counter (CTR)                                               |
   |                 |         |      - CKM_SM4_CTR (Vendor define)                                 |
   +-----------------+---------+--------------------------------------------------------------------+

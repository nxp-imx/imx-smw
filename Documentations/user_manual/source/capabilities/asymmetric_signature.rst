Asymmetric Signature
--------------------

This section documents the asymmetric signature operations supported across
different security subsystems (ELE, TEE, SECO) with their respective algorithms
and key types.

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: Asymmetric Signature Operations vs. subsystem
   :name: table_asym_sign_operations_subsystem
   :align: center
   :widths: 25 15 10 10 10
   :class: wrap-table

   +-----------------------+----------------+---------+---------+----------+
   | **Signature Scheme**  | **Processing** | **Subsystem**                |
   +                       +                +---------+---------+----------+
   |                       |                | **ELE** | **TEE** | **SECO** |
   +=======================+================+=========+=========+==========+
   | ECDSA                 | Single-Part    |    Y    |    Y    |    Y     |
   +                       +----------------+---------+---------+----------+
   |                       | Multi-Part     |    Y    |    Y    |    N     |
   +-----------------------+----------------+---------+---------+----------+
   | EdDSA                 | Single-Part    |    Y    |    Y    |    N     |
   +                       +----------------+---------+---------+----------+
   |                       | Multi-Part     |    Y    |    Y    |    N     |
   +-----------------------+----------------+---------+---------+----------+
   | RSA PKCS#1 v 1.5      | Single-Part    |    Y    |    Y    |    N     |
   +                       +----------------+---------+---------+----------+
   |                       | Multi-Part     |    Y    |    Y    |    N     |
   +-----------------------+----------------+---------+---------+----------+
   | RSA PSS               | Single-Part    |    Y    |    Y    |    N     |
   +                       +----------------+---------+---------+----------+
   |                       | Multi-Part     |    Y    |    Y    |    N     |
   +-----------------------+----------------+---------+---------+----------+


.. table:: Asymmetric Signature APIs
   :name: table_asym_sign_apis
   :align: center
   :widths: 25 15 15 45
   :width: 100%
   :class: wrap-table

   +------------------------+----------------+---------+------------------------------+
   | **Operations**         | **Processing** | **API** | **Functions**                |
   +========================+================+=========+==============================+
   | Signature Generation   | Single-Part    | SMW     | :c:func:`smw_sign`           |
   +                        +                +         +                              +
   |                        |                |         |                              |
   +                        +                +---------+------------------------------+
   |                        |                | PSA     | :c:func:`psa_sign_hash`      |
   +                        +                +         +                              +
   |                        |                |         | :c:func:`psa_sign_message`   |
   +                        +                +---------+------------------------------+
   |                        |                | PKCS11  | C_SignInit()                 |
   +                        +                +         +                              +
   |                        |                |         | C_Sign()                     |
   +                        +                +         +------------------------------+
   |                        |                |         | C_MessageSignInit()          |
   +                        +                +         +                              +
   |                        |                |         | C_SignMessage()              |
   +                        +----------------+---------+------------------------------+
   |                        | Multi-Part     | SMW     | :c:func:`smw_sign_init`      |
   +                        +                +         +                              +
   |                        |                |         | :c:func:`smw_sign_update`    |
   +                        +                +         +                              +
   |                        |                |         | :c:func:`smw_sign_final`     |
   +                        +                +---------+------------------------------+
   |                        |                | PKCS11  | C_SignInit()                 |
   +                        +                +         +                              +
   |                        |                |         | C_SignUpdate()               |
   +                        +                +         +                              +
   |                        |                |         | C_SignFinal()                |
   +                        +                +         +------------------------------+
   |                        |                |         | C_MessageSignInit()          |
   +                        +                +         +                              +
   |                        |                |         | C_SignMessageBegin()         |
   +                        +                +         +                              +
   |                        |                |         | C_SignMessageNext()          |
   +                        +                +         +                              +
   |                        |                |         | C_SignMessageFinal()         |
   +------------------------+----------------+---------+------------------------------+
   | Signature Verification | Single-Part    | SMW     | :c:func:`smw_verify`         |
   +                        +                +---------+------------------------------+
   |                        |                | PSA     | :c:func:`psa_verify_hash`    |
   +                        +                +         +                              +
   |                        |                |         | :c:func:`psa_verify_message` |
   +                        +                +---------+------------------------------+
   |                        |                | PKCS11  | C_VerifyInit()               |
   +                        +                +         +                              +
   |                        |                |         | C_Verify()                   |
   +                        +                +         +------------------------------+
   |                        |                |         | C_MessageVerifyInit()        |
   +                        +                +         +                              +
   |                        |                |         | C_VerifyMessage()            |
   +                        +----------------+---------+------------------------------+
   |                        | Multi-Part     | SMW     | :c:func:`smw_verify_init`    |
   +                        +                +         +                              +
   |                        |                |         | :c:func:`smw_verify_update`  |
   +                        +                +         +                              +
   |                        |                |         | :c:func:`smw_verify_final`   |
   +                        +                +---------+------------------------------+
   |                        |                | PKCS11  | C_VerifyInit()               |
   +                        +                +         +                              +
   |                        |                |         | C_VerifyUpdate()             |
   +                        +                +         +                              +
   |                        |                |         | C_VerifyFinal()              |
   +                        +                +         +------------------------------+
   |                        |                |         | C_MessageVerifyInit()        |
   +                        +                +         +                              +
   |                        |                |         | C_VerifyMessageBegin()       |
   +                        +                +         +                              +
   |                        |                |         | C_VerifyMessageNext()        |
   +                        +                +         +                              +
   |                        |                |         | C_VerifyMessageFinal()       |
   +------------------------+----------------+---------+------------------------------+


ECDSA Signatures
^^^^^^^^^^^^^^^^

.. table:: ECDSA Support Details
   :name: table_ecdsa_support_details
   :align: center
   :widths: 17 10 14 14 14 13 17
   :width: 100%
   :class: wrap-table

   +---------------+-------------+---------------+----------------+-----------+------------+-----------------+
   | **Curve**     | **Size**    | **Subsystem** | **Message**                | **Key**                      |
   +               +             +               +----------------+-----------+------------+-----------------+
   |               | **(bits)**  |               | **Pre-hashed** | **Full**  | **Opaque** | **Plaintext**   |
   +===============+=============+===============+================+===========+============+=================+
   | Secp R1       | 192         | ELE           | N              | N         | N          | N               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | N              | N         | N          | N               |
   +               +-------------+---------------+----------------+-----------+------------+-----------------+
   |               | 224         | ELE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | N              | N         | N          | N               |
   +               +-------------+---------------+----------------+-----------+------------+-----------------+
   |               | 256         | ELE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | Y              | Y         | Y          | Y (verify only) |
   +               +-------------+---------------+----------------+-----------+------------+-----------------+
   |               | 384         | ELE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | Y              | Y         | Y          | Y (verify only) |
   +               +-------------+---------------+----------------+-----------+------------+-----------------+
   |               | 521         | ELE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | N              | N         | N          | N               |
   +---------------+-------------+---------------+----------------+-----------+------------+-----------------+
   | Brainpool R1  | 224         | ELE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | N              | N         | N          | N               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | N              | N         | N          | N               |
   +               +-------------+---------------+----------------+-----------+------------+-----------------+
   |               | 256         | ELE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | N              | N         | N          | N               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | Y              | Y         | Y          | Y (verify only) |
   +               +-------------+---------------+----------------+-----------+------------+-----------------+
   |               | 384         | ELE           | Y              | Y         | Y          | Y               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | TEE           | N              | N         | N          | N               |
   +               +             +---------------+----------------+-----------+------------+-----------------+
   |               |             | SECO          | Y              | Y         | Y          | Y (verify only) |
   +---------------+-------------+---------------+----------------+-----------+------------+-----------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For signature operations, keys must be configured with appropriate key usage
flags:

.. table:: ECDSA Key Usage Flags
   :name: table_ecdsa_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | Sign full message     | SMW     | SMW_ATTR_USAGE_SIGN_MESSAGE   |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_MESSAGE    |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | Sign message hashed   | SMW     | SMW_ATTR_USAGE_SIGN_HASH      |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_HASH       |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | Verify full message   | SMW     | SMW_ATTR_USAGE_VERIFY_MESSAGE |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_MESSAGE  |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+
   | Verify message hashed | SMW     | SMW_ATTR_USAGE_VERIFY_HASH    |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_HASH     |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+

Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the ECDSA permitted signature algorithms.

.. table:: Permitted Algorithms for ECDSA Asymmetric Signature
   :name: table_permitted_key_algorithms_ecdsa_asym_sign
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Signature**   | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | ECDSA           | SMW     | SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(curve, hash)              |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``curve`` is SMW_ATTR_CURVE_ANY.                                |
   |                 |         |  - ``hash`` is one of SMW Attribute Hash algorithm define in the   |
   |                 |         |    :numref:`table_algorithm_hash`.                                 |
   |                 |         |                                                                    |
   |                 |         | Defining a hash algorithm as SMW_ATTR_HASH_ANY, allow to use the   |
   |                 |         | key for any hash algorithm.                                        |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_ECDSA(hash)                                                |
   |                 |         |                                                                    |
   |                 |         | Where ``hash`` is one of PSA Hash algorithm (`PSA_ALG_xxx`) such   |
   |                 |         | as :c:macro:`PSA_ALG_IS_HASH` is true.                             |
   |                 |         |                                                                    |
   |                 |         | Defining a ``hash`` algorithm as PSA_ALG_ANY_HASH, allow to use    |
   |                 |         | the key for any hash algorithm.                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be one or more CKM_ECDSA_SHAxxx  |
   |                 |         | value.                                                             |
   |                 |         |                                                                    |
   |                 |         | If multiple CKM_ECDSA_SHAxx values are set, the key                |
   |                 |         | permitted algorithm is ECDSA Signature any hash type.              |
   +-----------------+---------+--------------------------------------------------------------------+


EdDSA Signatures
^^^^^^^^^^^^^^^^

.. table:: EdDSA Support Details
   :name: table_eddsa_support_details
   :align: center
   :widths: 15 14 14 14 14 14 14
   :width: 100%
   :class: wrap-table

   +---------------+---------------+----------------+-------------+-----------+------------+-----------------+
   | **Curve**     | **Subsystem** | **Message**                              | **Key**                      |
   +               +               +----------------+-------------+-----------+------------+-----------------+
   |               |               | **Pre-hashed** | **Context** | **Full**  | **Opaque** | **Plaintext**   |
   +===============+===============+================+=============+===========+============+=================+
   | Ed448         | ELE           | Y              | N           | Y         | Y          | Y               |
   +               +---------------+----------------+-------------+-----------+------------+-----------------+
   |               | TEE           | N              | N           | N         | N          | N               |
   +---------------+---------------+----------------+-------------+-----------+------------+-----------------+
   | Ed25519       | ELE           | Y              | N           | Y         | Y          | Y               |
   +               +---------------+----------------+-------------+-----------+------------+-----------------+
   |               | TEE           | Y              | Y           | Y         | Y          | Y               |
   +---------------+---------------+----------------+-------------+-----------+------------+-----------------+

.. note::
   - i.MX8ULP doesn't support the EdDSA signature.
   - i.MX943, i.MX95, i.MX952 Pre-Hashed signature is not supported.

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For signature operations, keys must be configured with appropriate key usage
flags:

.. table:: EdDSA Key Usage Flags
   :name: table_eddsa_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | Sign full message     | SMW     | SMW_ATTR_USAGE_SIGN_MESSAGE   |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_MESSAGE    |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | Sign message hashed   | SMW     | SMW_ATTR_USAGE_SIGN_HASH      |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_HASH       |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | Verify full message   | SMW     | SMW_ATTR_USAGE_VERIFY_MESSAGE |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_MESSAGE  |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+
   | Verify message hashed | SMW     | SMW_ATTR_USAGE_VERIFY_HASH    |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_HASH     |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+

Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the EdDSA permitted signature algorithms.

.. table:: Permitted Algorithms for EdDSA Asymmetric Signature
   :name: table_permitted_key_algorithms_eddsa_asym_sign
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Signature**   | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | EdDSA           | SMW     | SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA(curve, hash, param)       |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - For ED25519 Pre-hashed signature scheme:\                       |
   |                 |         |                                                                    |
   |                 |         |      - ``curve`` is SMW_ATTR_CURVE_ED25519                         |
   |                 |         |      - ``hash`` is SMW_ATTR_HASH_NONE                              |
   |                 |         |      - ``param`` is SMW_ATTR_SIGN_PARAM_EDDSA_PREHASHED            |
   |                 |         |                                                                    |
   |                 |         |  - For ED25519 with context signature scheme:\                     |
   |                 |         |                                                                    |
   |                 |         |      - ``curve`` is SMW_ATTR_CURVE_ED25519                         |
   |                 |         |      - ``hash`` is SMW_ATTR_HASH_NONE                              |
   |                 |         |      - ``param`` is SMW_ATTR_SIGN_PARAM_EDDSA_CONTEXT              |
   |                 |         |                                                                    |
   |                 |         |  - For ED448 Pre-hashed signature scheme:\                         |
   |                 |         |                                                                    |
   |                 |         |      - ``curve`` is SMW_ATTR_CURVE_ED448                           |
   |                 |         |      - ``hash`` is SMW_ATTR_HASH_NONE                              |
   |                 |         |      - ``param`` is SMW_ATTR_SIGN_PARAM_EDDSA_PREHASHED            |
   |                 |         |                                                                    |
   |                 |         |  - For Pure EDDSA with or without context signature scheme:\       |
   |                 |         |                                                                    |
   |                 |         |      - ``curve`` is SMW_ATTR_CURVE_ANY                             |
   |                 |         |      - ``hash`` is SMW_ATTR_HASH_NONE                              |
   |                 |         |      - ``param`` is SMW_ATTR_SIGN_PARAM_EDDSA_NONE                 |
   |                 |         |                                                                    |
   |                 |         |  - For any signature scheme:\                                      |
   |                 |         |                                                                    |
   |                 |         |      - ``curve`` is SMW_ATTR_CURVE_ANY                             |
   |                 |         |      - ``hash`` is SMW_ATTR_HASH_ANY                               |
   |                 |         |      - ``param`` is SMW_ATTR_SIGN_PARAM_EDDSA_NONE                 |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     |  - For ED25519 Pre-hashed signature scheme use PSA_ALG_ED25519PH   |
   |                 |         |  - For ED448 Pre-hashed signature scheme use PSA_ALG_ED448PH       |
   |                 |         |  - For Pure EDDSA signature scheme use PSA_ALG_PURE_EDDSA          |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_EDDSA value. It will      |
   |                 |         | allow to support any type of Edwards signature scheme.             |
   +-----------------+---------+--------------------------------------------------------------------+


RSA PKCS#1 v1.5 Signatures
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: RSA PKCS#1 v1.5 Support Details
   :name: table_rsa_pkcs1_v1_5_support_details
   :align: center
   :widths: 20 15 14 15 14 14
   :width: 100%
   :class: wrap-table

   +--------------------+----------+---------------+-------------+------------+---------------+
   | **Key Size**       | **Hash** | **Subsystem** | **Message** | **Key**                    |
   +                    +          +               +-------------+------------+---------------+
   |                    |          |               |  **Full**   | **Opaque** | **Plaintext** |
   +====================+==========+===============+=============+============+===============+
   | 2048 / 3072 / 4096 | SHA-224  | ELE           | Y           | Y          | Y             |
   +                    +          +               +             +            +               +
   |                    | SHA-256  |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA-384  |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA-512  |               |             |            |               |
   +--------------------+----------+---------------+-------------+------------+---------------+
   | 256 to 4096        | MD5      | TEE           | Y           | Y          | Y             |
   +                    +          +               +             +            +               +
   | multiple of 2 bits | SHA-1    |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA-224  |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA-256  |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA-384  |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA-512  |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA3-224 |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA3-256 |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA3-384 |               |             |            |               |
   +                    +          +               +             +            +               +
   |                    | SHA3-512 |               |             |            |               |
   +--------------------+----------+---------------+-------------+------------+---------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For signature operations, keys must be configured with appropriate key usage
flags:

.. table:: RSA PKCS#1 v1.5 Key Usage Flags
   :name: table_rsa_pkcs1_v1_5_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | Sign full message     | SMW     | SMW_ATTR_USAGE_SIGN_MESSAGE   |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_MESSAGE    |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | Verify full message   | SMW     | SMW_ATTR_USAGE_VERIFY_MESSAGE |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_MESSAGE  |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+

Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the RSA PKCS#1 v1.5 permitted signature algorithm.

.. table:: Permitted Algorithms for RSA PKCS1 v1.5 Asymmetric Signature
   :name: table_permitted_key_algorithms_pkcs1_v1_5_asym_sign
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Signature**   | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | RSA PKCS#1 v1.5 | SMW     | SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(mode, hash, salt)           |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``mode`` is SMW_ATTR_MODE_PKCS1_1_5                             |
   |                 |         |  - ``hash`` is one of SMW Attribute Hash algorithm define in the   |
   |                 |         |    :numref:`table_algorithm_hash`.                                 |
   |                 |         |  - ``salt`` is 0                                                   |
   |                 |         |                                                                    |
   |                 |         | Defining a hash algorithm as SMW_ATTR_HASH_ANY, allow to use the   |
   |                 |         | key for any hash algorithm.                                        |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_RSA_PKCS1V15_SIGN(hash)                                    |
   |                 |         |                                                                    |
   |                 |         | Where ``hash`` is one of PSA Hash algorithm (`PSA_ALG_xxx`) such   |
   |                 |         | as :c:macro:`PSA_ALG_IS_HASH` is true.                             |
   |                 |         |                                                                    |
   |                 |         | Defining a ``hash`` algorithm as PSA_ALG_ANY_HASH, allow to use    |
   |                 |         | the key for any hash algorithm.                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_RSA_PKCS or               |
   |                 |         | CKM_SHAxxx_RSA_PKCS value.                                         |
   |                 |         |                                                                    |
   |                 |         | If CKM_RSA_PKCS is set or if multiple CKM_SHAxxx_RSA_PKCS          |
   |                 |         | are set, the key permitted algorithm is RSA PKCS1V15 Signature any |
   |                 |         | hash type.                                                         |
   +-----------------+---------+--------------------------------------------------------------------+


RSA PSS Signatures
^^^^^^^^^^^^^^^^^^

.. table:: RSA PSS Support Details
   :name: table_rsa_pss_support_details
   :align: center
   :widths: 14 15 14 11 23 10 11
   :width: 100%
   :class: wrap-table

   +--------------------+----------+---------------+-------------+---------------------+------------+---------------+
   | **Key Size**       | **Hash** | **Subsystem** | **Message** | **Salt**            | **Key**                    |
   +                    +          +               +-------------+                     +------------+---------------+
   |                    |          |               |  **Full**   | (**bytes**)         | **Opaque** | **Plaintext** |
   +====================+==========+===============+=============+=====================+============+===============+
   | 2048 / 3072 / 4096 | SHA-224  | ELE           | Y           | 0 <= len <= HashLen | Y          | Y             |
   +                    +          +               +             +                     +            +               +
   |                    | SHA-256  |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA-384  |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA-512  |               |             |                     |            |               |
   +--------------------+----------+---------------+-------------+---------------------+------------+---------------+
   | 256 to 4096        | SHA-1    | TEE           | Y           | 0 <= len <= HashLen | Y          | Y             |
   +                    +          +               +             +                     +            +               +
   | multiple of 2 bits | SHA-224  |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA-256  |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA-384  |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA-512  |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA3-224 |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA3-256 |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA3-384 |               |             |                     |            |               |
   +                    +          +               +             +                     +            +               +
   |                    | SHA3-512 |               |             |                     |            |               |
   +--------------------+----------+---------------+-------------+---------------------+------------+---------------+

Key attributes
""""""""""""""
Key Usage
~~~~~~~~~
For signature operations, keys must be configured with appropriate key usage
flags:

.. table:: RSA PSS Key Usage Flags
   :name: table_rsa_pss_key_usage
   :align: center
   :widths: 25 12 35
   :width: 100%
   :class: wrap-table

   +-----------------------+---------+-------------------------------+
   | **Operation**         | **API** | **Required Key Usage**        |
   +=======================+=========+===============================+
   | Sign full message     | SMW     | SMW_ATTR_USAGE_SIGN_MESSAGE   |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_SIGN_MESSAGE    |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_SIGN                      |
   +-----------------------+---------+-------------------------------+
   | Verify full message   | SMW     | SMW_ATTR_USAGE_VERIFY_MESSAGE |
   +                       +---------+-------------------------------+
   |                       | PSA     | PSA_KEY_USAGE_VERIFY_MESSAGE  |
   +                       +---------+-------------------------------+
   |                       | PKCS11  | CKA_VERIFY                    |
   +-----------------------+---------+-------------------------------+

Permitted Algorithm
~~~~~~~~~~~~~~~~~~~
The following table outlines the RSA PSS permitted signature algorithms.

.. table:: Permitted Algorithms for RSA PSS Asymmetric Signature
   :name: table_permitted_key_algorithms_rsa_pss_asym_sign
   :align: center
   :widths: 15 15 70
   :width: 100%
   :class: wrap-table

   +-----------------+---------+--------------------------------------------------------------------+
   | **Signature**   | **API** | **Permitted Algorithm**                                            |
   +=================+=========+====================================================================+
   | RSA PSS         | SMW     | SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(mode, hash, salt)           |
   |                 |         |                                                                    |
   |                 |         | Where:\                                                            |
   |                 |         |                                                                    |
   |                 |         |  - ``mode`` is SMW_ATTR_MODE_PSS                                   |
   |                 |         |  - ``hash`` is one of SMW Attribute Hash algorithm define in the   |
   |                 |         |    :numref:`table_algorithm_hash`.                                 |
   |                 |         |  - ``salt`` is 0                                                   |
   |                 |         |                                                                    |
   |                 |         | Defining a hash algorithm as SMW_ATTR_HASH_ANY, allow to use the   |
   |                 |         | key for any hash algorithm.                                        |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PSA     | PSA_ALG_RSA_PSS(hash)                                              |
   |                 |         |                                                                    |
   |                 |         | Where ``hash`` is one of PSA Hash algorithm (`PSA_ALG_xxx`) such   |
   |                 |         | as :c:macro:`PSA_ALG_IS_HASH` is true.                             |
   |                 |         |                                                                    |
   |                 |         | Defining a ``hash`` algorithm as PSA_ALG_ANY_HASH, allow to use    |
   |                 |         | the key for any hash algorithm.                                    |
   +                 +---------+--------------------------------------------------------------------+
   |                 | PKCS11  | Key's CKA_ALLOWED_MECHANISMS must be CKM_RSA_PKCS_PSS or           |
   |                 |         | CKM_SHAxxx_RSA_PKCS_PSS value.                                     |
   |                 |         |                                                                    |
   |                 |         | If CKM_RSA_PKCS_PSS is set or if multiple CKM_SHAxxx_RSA_PKCS_PSS  |
   |                 |         | are set, the key permitted algorithm is RSA PSS Signature any      |
   |                 |         | hash type.                                                         |
   +-----------------+---------+--------------------------------------------------------------------+

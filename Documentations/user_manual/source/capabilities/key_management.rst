Key Management
--------------

This section documents the key management operations supported across
different security subsystems (ELE, TEE, SECO) with their respective key types
and sizes.

Supported Operations versus Subsystems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. table:: Key Management Operations vs. subsystem
   :name: table_key_mgmt_operations_subsystem
   :align: center
   :widths: 20 25 10 10 10 25
   :width: 100%
   :class: wrap-table

   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | **Operations**                           | **Subsystem**                | **Notes**                            |
   +                                          +---------+---------+----------+                                      +
   |                                          | **ELE** | **TEE** | **SECO** |                                      |
   +==================+=======================+=========+=========+==========+======================================+
   | `Generate Key`_                          |    Y    |    Y    |    Y     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `Delete Key`_                            |    Y    |    Y    |    Y     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `Import Key`_    | Plaintext             |    N    |    Y    |    N     |                                      |
   +                  +-----------------------+---------+---------+----------+--------------------------------------+
   |                  | EdgeLock 2GO blob     |    Y    |    N    |    N     |                                      |
   +                  +-----------------------+---------+---------+----------+--------------------------------------+
   |                  | EdgeLock Enclave blob |    Y    |    N    |    N     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `Export Public Key`_                     |    Y    |    Y    |    Y     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `Key Derivation`_| HKDF                  |    N    |    Y    |    N     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `Key Agreement`_ | ECDH                  |    N    |    Y    |    N     |                                      |
   +                  +-----------------------+---------+---------+----------+--------------------------------------+
   |                  | OEM Master key        |    Y    |    N    |    N     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `TLS 1.2 (PRF)`_                         |    Y    |    N    | **Y***   | **SECO** Require specific Firmware.  |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `TLS 1.3 (TLS13-KDF)`_                   |    Y    |    N    |    N     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `Get key attributes`_                    |    Y    |    Y    | **Y***   | **SECO** managed limited attributes. |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+
   | `Public key attestation`_                |    Y    |    N    |    N     |                                      |
   +------------------+-----------------------+---------+---------+----------+--------------------------------------+

Asymmetric Keys
^^^^^^^^^^^^^^^
This section documents the asymmetric keys supported across different
security subsystems (ELE, TEE, SECO) with their respective key sizes in bits.


Secp R1
"""""""

.. table:: Secp R1 vs. subsystem
   :name: table_secp_r1_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+-----------------------------+
   | **Subsystem** | **Security size in bits**   |
   +===============+=============================+
   | ELE           | 192 / 224 / 256 / 384 / 521 |
   +---------------+-----------------------------+
   | TEE           | 192 / 224 / 256 / 384 / 521 |
   +---------------+-----------------------------+
   | SECO          | 256 / 384                   |
   +---------------+-----------------------------+

Brainpool R1
""""""""""""

.. table:: Brainpool R1 vs. subsystem
   :name: table_brainpool_r1_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+---------------------------+
   | **Subsystem** | **Security size in bits** |
   +===============+===========================+
   | ELE           | 224 / 256 / 384           |
   +---------------+---------------------------+
   | TEE           | Not supported             |
   +---------------+---------------------------+
   | SECO          | 256 / 384                 |
   +---------------+---------------------------+

Twisted Edwards
"""""""""""""""
Aka. ED25519 and ED448

.. table:: Twisted Edwards vs. subsystem
   :name: table_twisted_edwards_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+---------------------------+
   | **Subsystem** | **Security size in bits** |
   +===============+===========================+
   | ELE           | 255 / 448                 |
   +---------------+---------------------------+
   | TEE           | 255                       |
   +---------------+---------------------------+
   | SECO          | Not supported             |
   +---------------+---------------------------+

Montgomery
""""""""""
Aka. X25519 and X448

.. table:: Montgomery vs. subsystem
   :name: table_montgomery_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+---------------------------+
   | **Subsystem** | **Security size in bits** |
   +===============+===========================+
   | ELE           | 255 / 448                 |
   +---------------+---------------------------+
   | TEE           | Not supported             |
   +---------------+---------------------------+
   | SECO          | Not supported             |
   +---------------+---------------------------+

RSA Keys
""""""""

.. table:: RSA vs. subsystem
   :name: table_rsa_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+----------------------------------+----------------------------+
   | **Subsystem** | **Security size in bits**        | **Comment**                |
   +===============+==================================+============================+
   | ELE           | 2048 / 3072 / 4096               | Not supported on i.MX8ULP. |
   +---------------+----------------------------------+----------------------------+
   | TEE           | 256 to 4096 (multiple of 2 bits) |                            |
   +---------------+----------------------------------+----------------------------+
   | SECO          | Not supported                    |                            |
   +---------------+----------------------------------+----------------------------+


Symmetric Keys
^^^^^^^^^^^^^^
This section documents the symmetric keys supported across different
security subsystems (ELE, TEE, SECO) with their respective key sizes in bits.

AES
"""

.. table:: AES vs. subsystem
   :name: table_aes_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+---------------------------+
   | **Subsystem** | **Security size in bits** |
   +===============+===========================+
   | ELE           | 128 / 192 / 256           |
   +---------------+---------------------------+
   | TEE           | 128 / 192 / 256           |
   +---------------+---------------------------+
   | SECO          | 128 / 192 / 256           |
   +---------------+---------------------------+

DES
"""

.. table:: DES vs. subsystem
   :name: table_des_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+---------------------------+
   | **Subsystem** | **Security size in bits** |
   +===============+===========================+
   | ELE           | Not supported             |
   +---------------+---------------------------+
   | TEE           | 56                        |
   +---------------+---------------------------+
   | SECO          | Not supported             |
   +---------------+---------------------------+

Triple-DES
""""""""""
Aka. DES3

.. table:: Triple-DES vs. subsystem
   :name: table_des3_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+---------------------------+
   | **Subsystem** | **Security size in bits** |
   +===============+===========================+
   | ELE           | Not supported             |
   +---------------+---------------------------+
   | TEE           | 112 / 168                 |
   +---------------+---------------------------+
   | SECO          | Not supported             |
   +---------------+---------------------------+

SM4
"""

.. table:: SM4 vs. subsystem
   :name: table_sm4_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+---------------------------+
   | **Subsystem** | **Security size in bits** |
   +===============+===========================+
   | ELE           | Not supported             |
   +---------------+---------------------------+
   | TEE           | 128                       |
   +---------------+---------------------------+
   | SECO          | Not supported             |
   +---------------+---------------------------+


HMAC
""""

.. table:: HMAC vs. subsystem
   :name: table_hmac_subsystem
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+--------------------------------------+-----------------------------------------+
   | **Subsystem** | **Security size in bits**            | **Comment**                             |
   +===============+======================================+=========================================+
   | ELE           | 224 / 256 / 384 / 512                |                                         |
   +---------------+--------------------------------------+-----------------------------------------+
   | TEE           | 64 to 1024 bits (multiple of 8 bits) |                                         |
   +---------------+--------------------------------------+-----------------------------------------+
   | SECO          | 224 / 256 / 384 / 512                | Require specific Firmware.              |
   +               +                                      +                                         +
   |               |                                      | Build option ENABLE_TLS must be set ON. |
   +---------------+--------------------------------------+-----------------------------------------+


Generate Key
^^^^^^^^^^^^
The **generate key** operation is used to generate cryptographic persistent or
transient keys within a secure subsystem storage.

.. table:: Generate Key APIs Comparison
   :name: table_generate_key_apis_comparison
   :align: center
   :widths: 25 15 60
   :width: 100%
   :class: wrap-table

   +------------------+---------+----------------------------------------------+
   | **Key Type**     | **API** | **Function** / **Key Type** or **Mechanism** |
   +==================+=========+==============================================+
   | **Asymmetric Keys**                                                       |
   +------------------+---------+----------------------------------------------+
   | Secp R1          | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_SECP_R1                    |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_ECC_FAMILY_SECP_R1                       |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKeyPair()                          |
   +                  +         +                                              +
   |                  |         | CKM_EC_KEY_PAIR_GEN                          |
   +------------------+---------+----------------------------------------------+
   | Brainpool R1     | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_BRAINPOOL_R1               |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_ECC_FAMILY_BRAINPOOL_P_R1                |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | Not defined                                  |
   +------------------+---------+----------------------------------------------+
   | Twisted Edwards  | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   | (ED25519/ED448)  |         | SMW_KEY_TYPE_NAME_ED25519                    |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_ED448                      |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_ECC_FAMILY_TWISTED_EDWARDS               |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKeyPair()                          |
   +                  +         +                                              +
   |                  |         | CKM_EC_EDWARDS_KEY_PAIR_GEN                  |
   +------------------+---------+----------------------------------------------+
   | Montgomery       | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   | (X25519/X448)    |         | SMW_KEY_TYPE_NAME_X25519                     |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_X448                       |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_ECC_FAMILY_MONTGOMERY                    |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKeyPair()                          |
   +                  +         +                                              +
   |                  |         | CKM_EC_MONTGOMERY_KEY_PAIR_GEN               |
   +------------------+---------+----------------------------------------------+
   | RSA              | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_RSA                        |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_KEY_TYPE_RSA_KEY_PAIR                    |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKeyPair()                          |
   +                  +         +                                              +
   |                  |         | CKM_RSA_PKCS_KEY_PAIR_GEN                    |
   +                  +         +                                              +
   |                  |         | CKM_RSA_X9_31_KEY_PAIR_GEN                   |
   +------------------+---------+----------------------------------------------+
   | **Symmetric Keys**                                                        |
   +------------------+---------+----------------------------------------------+
   | AES              | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_AES                        |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_KEY_TYPE_AES                             |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKey()                              |
   +                  +         +                                              +
   |                  |         | CKM_AES_KEY_GEN                              |
   +------------------+---------+----------------------------------------------+
   | DES              | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_DES                        |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_KEY_TYPE_DES                             |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKey()                              |
   +                  +         +                                              +
   |                  |         | CKM_DES_KEY_GEN                              |
   +------------------+---------+----------------------------------------------+
   | Triple-DES       | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_DES3                       |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_KEY_TYPE_DES3                            |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKey()                              |
   +                  +         +                                              +
   |                  |         | CKM_DES3_KEY_GEN                             |
   +------------------+---------+----------------------------------------------+
   | SM4              | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_SM4                        |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_KEY_TYPE_SM4                             |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKey()                              |
   +                  +         +                                              +
   |                  |         | CKM_SM4_KEY_GEN (NXP vendor define)          |
   +------------------+---------+----------------------------------------------+
   | HMAC             | SMW     | :c:func:`smw_generate_key`                   |
   +                  +         +                                              +
   |                  |         | SMW_KEY_TYPE_NAME_HMAC                       |
   +                  +---------+----------------------------------------------+
   |                  | PSA     | :c:func:`psa_generate_key`                   |
   +                  +         +                                              +
   |                  |         | PSA_KEY_TYPE_HMAC                            |
   +                  +---------+----------------------------------------------+
   |                  | PKCS11  | C_GenerateKey()                              |
   +                  +         +                                              +
   |                  |         | CKM_GENERIC_SECRET_KEY_GEN                   |
   +------------------+---------+----------------------------------------------+

.. _key_management_delete:

Delete Key
^^^^^^^^^^
The **delete key** operation allows removing a previously generated or imported
persistent or transient key from the subsystem system storage.

.. table:: Delete Key APIs Comparison
   :name: table_delete_key_apis_comparison
   :align: center
   :widths: 15 60
   :width: 100%
   :class: wrap-table

   +---------+---------------------------+
   | **API** | **Function**              |
   +=========+===========================+
   | SMW     | :c:func:`smw_delete_key`  |
   +---------+---------------------------+
   | PSA     | :c:func:`psa_destroy_key` |
   +---------+---------------------------+
   | PKCS11  | C_DestroyObject()         |
   +---------+---------------------------+

.. _key_management_import:

Import Key
^^^^^^^^^^
The **import key** operation allows importing a key material (plaintext or
encrypted) in the subsystem system storage. The key can be persistent or
transient.

Plaintext
"""""""""

.. table:: Import Plaintext Key APIs Comparison
   :name: table_import_plain_key_apis_comparison
   :align: center
   :widths: 25 15 60
   :width: 100%
   :class: wrap-table

   +------------------+---------+------------------------------------+
   | **Key Type**     | **API** | **Function** / **Key Type**        |
   +==================+=========+====================================+
   | **Asymmetric Keys**                                             |
   +------------------+---------+------------------------------------+
   | Secp R1          | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_SECP_R1          |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_ECC_FAMILY_SECP_R1             |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_EC                             |
   +------------------+---------+------------------------------------+
   | Brainpool R1     | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_BRAINPOOL_R1     |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_ECC_FAMILY_BRAINPOOL_P_R1      |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | Not defined                        |
   +------------------+---------+------------------------------------+
   | Twisted Edwards  | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   | (ED25519/ED448)  |         | SMW_KEY_TYPE_NAME_ED25519          |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_ED448            |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_ECC_FAMILY_TWISTED_EDWARDS     |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_EC_EDWARDS                     |
   +------------------+---------+------------------------------------+
   | Montgomery       | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   | (X25519/X448)    |         | SMW_KEY_TYPE_NAME_X25519           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_X448             |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_ECC_FAMILY_MONTGOMERY          |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_EC_MONTGOMERY                  |
   +------------------+---------+------------------------------------+
   | RSA              | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_RSA              |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_KEY_TYPE_RSA_KEY_PAIR          |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_RSA                            |
   +------------------+---------+------------------------------------+
   | **Symmetric Keys**                                              |
   +------------------+---------+------------------------------------+
   | AES              | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_AES              |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_KEY_TYPE_AES                   |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_AES                            |
   +------------------+---------+------------------------------------+
   | DES              | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_DES              |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_KEY_TYPE_DES                   |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_DES                            |
   +------------------+---------+------------------------------------+
   | Triple-DES       | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_DES3             |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_KEY_TYPE_DES3                  |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_DES3                           |
   +------------------+---------+------------------------------------+
   | SM4              | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_SM4              |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_KEY_TYPE_SM4                   |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_SM4 (NXP vendor define)        |
   +------------------+---------+------------------------------------+
   | HMAC             | SMW     | :c:func:`smw_import_key`           |
   +                  +         +                                    +
   |                  |         | SMW_KEY_TYPE_NAME_HMAC             |
   +                  +---------+------------------------------------+
   |                  | PSA     | :c:func:`psa_import_key`           |
   +                  +         +                                    +
   |                  |         | PSA_KEY_TYPE_HMAC                  |
   +                  +---------+------------------------------------+
   |                  | PKCS11  | C_CreateObject()                   |
   +                  +         +                                    +
   |                  |         | CKK_GENERIC_SECRET                 |
   +                  +         +                                    +
   |                  |         | CKK_MD5_HMAC                       |
   +                  +         +                                    +
   |                  |         | CKK_SHA_1_HMAC                     |
   +                  +         +                                    +
   |                  |         | CKK_SHA224_HMAC                    |
   +                  +         +                                    +
   |                  |         | CKK_SHA256_HMAC                    |
   +                  +         +                                    +
   |                  |         | CKK_SHA384_HMAC                    |
   +                  +         +                                    +
   |                  |         | CKK_SHA512_HMAC                    |
   +                  +         +                                    +
   |                  |         | CKK_SHA3_224_HMAC                  |
   +                  +         +                                    +
   |                  |         | CKK_SHA3_256_HMAC                  |
   +                  +         +                                    +
   |                  |         | CKK_SHA3_384_HMAC                  |
   +                  +         +                                    +
   |                  |         | CKK_SHA3_512_HMAC                  |
   +------------------+---------+------------------------------------+


EdgeLock 2GO blob
"""""""""""""""""
This service is a NXP provisioning service involving the NXP EdgeLock 2GO
server. It's only supported by the EdgeLock Enclave (ELE).

The server allows to provision key and data embedded in blob. Visit
`EdgeLock 2GO <http://www.nxp.com/edgelock2go>`_.

The type of key blob to import is identified by the key location attribute:

  - SMW API, the key location is defined by the 'storage_id' field
    of the key attribute in the key descriptor (refer to
    the :c:type:`smw_key_descriptor`).
  - PSA API, the key location is defined by the 'lifefime' field of the
    key attribute (refer to the :c:type:`psa_key_attributes_t`). The location
    is defined by the bits[31:8] of the field.


.. table:: EdgeLock 2GO - Location
   :name: table_key_el2go_location
   :align: center
   :width: 100%
   :class: wrap-table

   +-------------------+------------------+---------------------------+
   |                   | **SMW**          | **PSA**                   |
   +                   +                  +                           +
   |                   | **'storage_id'** | **'lifetime' bits[31:8]** |
   +===================+==================+===========================+
   | EdgeLock 2GO Key  | 0x00E00000       | 0xE00000                  |
   +-------------------+------------------+---------------------------+
   | EdgeLock 2GO Data | 0x00E08000       | 0xE08000                  |
   +-------------------+------------------+---------------------------+

The SMW or PSA key import API allows to import EdgeLock 2GO blob of type key
or data.


EdgeLock Enclave blob
"""""""""""""""""""""
This service is a NXP service provided by the EdgeLock Secure Enclave Firmware.
A EdgeLock Enclave blob is used to import secure keys. The blob contains the
key attributes, the wrapped key (AES CBC padded or RFC 3394) and a blob
signature (CMAC).

The wrapping key and the signing key are both derived from the
`OEM Master key`_. On device both keys are derived and kept internal, on
host side, the OEM Master key, the wrapping key and signing key must be
derived using the HMAC two steps standard
`RFC5869 <https://datatracker.ietf.org/doc/html/rfc5869.html>`_.

OEM import WRAP and CMAC keys derivation parameters:

  - The salt used in the first step: extract can be either:

    - A zeros string. Its length, in bytes, is equal to the hash algorithm
      (used in the key derivation process) length byte size.
    - Device SRKH. As salt length is the hash algorithm
      (used in the key derivation process) length byte size, device SRKH value
      could be truncated or concatenated with 0s to match the required salt length.

  - The IKM is the `OEM Master key`_ shared secret key
  - The fixed info in a byte string imposed by EdgeLock Secure Enclave Firmware.
    It differs switch derived key:

    - For wrapping key, fixed info is: “oemelefwkeyimportwrap256” string
      (quotation marks not included).
    - For signing key, fixed info is: “oemelefwkeyimportcmac256” string
      (quotation marks not included).
  - The key derivation algorithm is imposed by EdgeLock Secure Enclave
    Firmware as HKDF_SHA256.

The EdgeLock Enclave blob is encoded as described in :numref:`ele_import_blob`.

.. table:: EdgeLock Enclave blob
   :name: ele_import_blob
   :align: center
   :widths: 13 13 9 11 54
   :width: 100%
   :class: wrap-table

   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | **Field**                  | **Tag**  | **Length**  | **Description / Value**                                          |
   |                            |          |             |                                                                  |
   |                            |          | **(bytes)** |                                                                  |
   +============================+==========+=============+==================================================================+
   | Magic                      |   0x40   | 21          | EdgeLock Secure Enclave identification blob.                     |
   |                            |          |             |                                                                  |
   |                            |          |             | Value is the hexadecimal string “edgelockenclaveimport”.         |
   |                            |          |             |                                                                  |
   |                            |          |             | [65 64 67 65 6c 6f 63 6b 65 6e 63 6c 61 76 65 69 6d 70 6f 72 74] |
   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | Key ID                     |   0x41   | 4           | Key identifier in the subsystem:                                 |
   |                            |          |             |                                                                  |
   |                            |          |             |  - 0x0 if the key is transient.                                  |
   |                            |          |             |  - between 0x1 and 0x3FFFFFFF if the key is persistent.          |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   |                | Algorithm |   0x42   | 4           | ELE key permitted algorithm.                                     |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   | Key properties | Usage     |   0x43   | 4           | ELE key usage flags.                                             |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   |                | Type      |   0x44   | 2           | ELE Type of key.                                                 |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   |                | Bits      |   0x45   | 4           | Key security size in bits.                                       |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   |                | Lifetime  |   0x46   | 4           | ELE Lifetime:                                                    |
   |                |           |          |             |                                                                  |
   |                |           |          |             |  - 0xC0020000, transient key                                     |
   |                |           |          |             |  - 0xC0020001, persistent key                                    |
   |                |           |          |             |  - 0xC00200FF, permanent key                                     |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Key lifecycle              |   0x47   | 4           | ELE device lifecycle flags when key is usable:                   |
   |                            |          |             |                                                                  |
   |                            |          |             |  - OEM OPEN: 0x01                                                |
   |                            |          |             |  - OEM CLOSED: 0x02                                              |
   |                            |          |             |  - OEM CLOSED_LOCKED: 0x04                                       |
   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | OEM Master key identifier  |   0x50   | 4           | OEM Master key identifier resulting `OEM Master key`_.           |
   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | Wrapping algorithm         |   0x51   | 4           | Wrapping algorithm of the key blob. This field is required to    |
   |                            |          |             | distinguish between different flavors of wrapping algorithms.    |
   |                            |          |             | Possible values are:                                             |
   |                            |          |             |                                                                  |
   |                            |          |             |  - 0x01: RFC 3394 wrapping.                                      |
   |                            |          |             |  - 0x02: AES-CBC wrapping (padding cipher, ISO7816-4 Appendix C).|
   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | IV                         |   0x52   | 16          | IV to use for CBC wrapping.                                      |
   |                            |          |             | Not used if wrapping algorithm not equal 0x02.                   |
   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | Signing algorithm          |   0x54   | 4           | Algorithm used to sign the blob itself. Field Signature of this  |
   |                            |          |             | blob.                                                            |
   |                            |          |             | It must be 0x01 (CMAC).                                          |
   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | Wrapped private key        |   0x55   | Variable    | Private key data in encrypted format as defined by the Wrapping  |
   |                            |          |             | Algorithm.                                                       |
   |                            |          |             | Key used to do the encryption must be wrapping key derived from  |
   |                            |          |             | the OEM Master key.                                              |
   +----------------------------+----------+-------------+------------------------------------------------------------------+
   | Signature                  |   0x5E   | 16          | Signature of all previous fields of this blob including the      |
   |                            |          |             | signature tag (0x5E) and signature length fields.                |
   |                            |          |             | Key used to do the signature must be signing key derived from    |
   |                            |          |             | the OEM Master key.                                              |
   +----------------------------+----------+-------------+------------------------------------------------------------------+

.. _ELE_blob_example:

Usage Example (with OEM Master key derivation)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Here's an example of host source code C to derive the OEM Master key

In this example:

  - `MbedTLS Library <https://github.com/Mbed-TLS/mbedtls>`_ is used as third
    party cryptographic service.
  - ECDSA NIST 256 bits keypair are used on device and host side as based key
    of the OEM Master key agreement.
  - ECDH + HKDF-SHA256 algorithm is used for the key agreement operation.

  .. note::
     The following code is not complete, failure must be handled correctly and
     resource freed. The following examples aim to give the guidelines to
     write application on host and device.


#. **On device**, generates and exports an ECDSA NIST 256 bits keypair:

   The SMW API :c:func:`smw_generate_key` is used to generate the key.
   The key is stored as a transient key.
   The public key is exported if the operation success. The public key is
   the device peer key that will be used to derive the OEM Master key on the
   host side.

   This key identifier will be identified in this example by ``ELE_base_id``.

   The public key of this key will be identified in this example by ``ELE_peer_key``.

   .. code-block:: C
      :linenos:

      int res = -1;
      enum smw_status_code status = SMW_STATUS_OK;
      struct smw_generate_key_args args = { 0 };
      struct smw_key_descriptor key = { 0 };
      struct smw_key_attributes *attributes = &key.attributes;
      struct smw_keypair_buffer buffer = { 0 };

      /* Allocate the public key buffer of the key */
      buffer.gen.public_length = 64;
      buffer.gen.public_data = malloc(buffer.gen.public_length);
      if (!buffer.gen.public_data)
        return res;

      args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
      args.key_descriptor = &key;

      key.type_name = SMW_KEY_TYPE_NAME_SECP_R1;
      key.security_size = 256;
      key.buffer = &buffer;

      attributes.permitted_algo = SMW_ATTR_ALGO_KEY_AGREEMENT(SMW_ATTR_ALGO_ECDH,
                                                              SMW_ATTR_ALGO_HKDF,
                                                              SMW_ATTR_HASH_SHA256);
      attributes.usage_flags = SMW_ATTR_USAGE_DERIVE;
      attributes.attributes = SMW_ATTR_SET_PERSISTENCE(attributes.attributes,
                                                       SMW_ATTR_PERSISTENCE_TRANSIENT);

      status = smw_generate_key(&args);
      if (status != SMW_STATUS_OK) {
          free(buffer.gen.public_data);
          return -1;
      }

      /*
       * At this stage:
       *  - ``ELE_peer_key`` is the buffer.gen.public_data
       *  - ``ELE_base_id`` is the identifier returned in key.id
       */

      ...

#. **On host**, generates and exports an ECDSA NIST 256 bits keypair:

   The public key is exported if the operation success. The public key is
   the host peer key that will be used to derive the OEM Master key on the
   device side.

   In this example, the Host peer key is named ``Host_peer_key``.

   .. code-block:: C
      :linenos:

      int res = -1;
      mbedtls_pk_context key;
      mbedtls_entropy_context entropy;
      mbedtls_ctr_drbg_context ctr_drbg;
      mbedtls_ecp_group grp;
      mbedtls_ecp_point Host_base_key;
      unsigned char Host_peer_key[MBEDTLS_ECP_MAX_PT_LEN];
      mbedtls_pk_type_t pk_alg = MBEDTLS_PK_ECKEY;
      size_t len = 0;

      mbedtls_pk_init(&key);
      mbedtls_entropy_init(&entropy);
      mbedtls_ctr_drbg_init(&ctr_drbg);


      res = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(pk_alg));
      if (res)
        /* Failure */

      res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                  &entropy,
                                  (const unsigned char *) "ecdsa",
                                  strlen(pers));
      if (res)
        /* Failure */

      res = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                mbedtls_pk_ec(key),
                                mbedtls_ctr_drbg_random,
                                &ctr_drbg);
      if (res)
        /* Failure */

      mbedtls_ecp_group_init(&grp);
      mbedtls_ecp_point_init(&pt);

      res = mbedtls_ecp_export(ecp, &grp, NULL, &Host_base_key);
      if (res)
        /* Failure */

      res = mbedtls_ecp_point_write_binary(&grp, &Host_base_key,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           &len, Host_peer_key,
                                           sizeof(Host_peer_key));
      if (res)
        /* Failure */

      /*
       * At this stage the ``Host_peer_key`` is the public key value starting with
       * the uncompress tag 0x4.
       */

      ...

#. **On device**, derive the OEM Master key:

   * ``Host_peer_key`` is the host peer public key buffer.
   * ``ELE_base_id`` is the ELE base key identifier.

   Fixed info is optional. If set, its digest must be present in the signed
   content payload.

   Signed content payload must be configured as explained in `OEM Master key`_
   and where the peer public key digest must be the result of SHA256(``Host_peer_key``).
   This signed content payload key will be identified in this example by ``OEM_Payload``.

   In this example, the OEM Master key is a persistent key with a key identifier
   named ``ELE_OEM_MK_ID``. It's assumed that the signed payload is valid with
   slat flags set to 0 (no salt used to derived OEM Master key, wrapping and
   signing keys).

   In this example, the fixed info is not set.

   .. code-block:: C
      :linenos:

      int res = -1;
      enum smw_status_code status = SMW_STATUS_OK;
      struct smw_derive_key_args args = { 0 };
      struct smw_kdf_oem_master_key_args oem_mk_args = { 0 };
      struct smw_key_descriptor key_base = { 0 };
      struct smw_derived_key_descriptor key_derived = { 0 };

      args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
      args.key_descriptor_base = &key_base;
      args.kdf_name = SMW_KDF_NAME_OEM_MASTER_KEY;
      args.kdf_arguments = &oem_mk_args;
      args.store_derived_key = true; /* Request to store the key in Secure Storage */
      args.key_descriptor_base = &key_base;
      ergs.key_descriptor_derived = &key_derived;

      oem_mk_args.op = SMW_OEM_MK_OP_NAME_DERIVE;
      oem_mk_args.peer_public_buffer = Host_peer_key;
      oem_mk_args.peer_public_buffer_length = sizeof(Host_peer_key);
      oem_mk_args.payload = OEM_Payload;
      oem_mk_args.payload_length = sizeof(OEM_Payload);

      key_base.id = ELE_base_id;

      key_derived.type_name = SMW_KEY_TYPE_NAME_DERIVE;
      key_derived.security_size = 256;
      key_derived.id = ELE_OEM_MK_ID;
      key_derived.attributes.permitted_algo = SMW_ATTR_ALGO_KEY_DERIVATION_HKDF(SHA256);
      key_derived.attributes.usage_flags = SMW_ATTR_USAGE_DERIVE;
      key_derived.attributes.attributes = SMW_ATTR_PERSISTENCE_PERSISTENT;


      status = smw_derive_key(&args);
      if (status != SMW_STATUS_OK)
          return -1;

      /*
       * At this stage, the OEM Master key is created in the EdgeLock Enclave,
       * as persistent key identifier ``ELE_OEM_MK_ID``
       */

   .. note::
      The wrapping and signing keys of the key import blob are not derived
      at this step but each time the Key Import API is executed.

#. **On host**, generates same OEM Master key:

   This operation is done in two steps: key agreement and key derivation.

   In this example, the host OEM Master key identifier will be named
   ``Host_OEM_MK_ID``.

   #. Key agreement:

      This step generates a shared secret that will be used as input of key
      derivation step.

      The algorithm used is ECDH.

      In this example, the base key is the key generated in previous step and
      named ``Host_base_key``. The peer key is the device public key generated
      in previous step and named ``ELE_peer_key``.

      Here's a sample of code that can be used to generated the shared secret:

        .. code-block:: C
           :linenos:

           int res = -1;
           uint32_t peer_key_size = (256 / 8) * 2;
           uint32_t mbed_peer_key_size = peer_key_size + 1;
           uint8_t peer_key[mbed_peer_key_size];
           mbedtls_ecp_group grp;
           mbedtls_ecp_point peer_pt;
           mbedtls_mpi ecdh;

           /* Prepare public key */
           memset(&grp, 0, sizeof(grp));
           res = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
           if (res != 0)
           	return failure;

           /* Prepare public key, a 0x04 leading byte must be added */
           peer_key[0] = 0x04;
           memcpy(peer_key_key + 1, ELE_peer_key, peer_key_size);

           /* Load public key from buffer */
           mbedtls_ecp_point_init(&peer_pt);
           res = mbedtls_ecp_point_read_binary(&grp, &peer_key, mbed_peer_key,
                                               mbed_peer_key_size);
           if (res != 0)
           	/* Failure */

           /* Compute ECDH */
           mbedtls_mpi_init(&ecdh);

           /*
            * The ``Host_base_key`` is the result of the key generated in
            * previous step.
            */
           res = mbedtls_ecdh_compute_shared(&grp, &ecdh, &peer_pt,
                                             &Host_base_key.private_d,
                                             my_mbedtls_rand, NULL);
           if (res != 0)
           	/* Failure */

           /*
            * At this point, the shared secret is the buffer located at
            * ecdh.private_p. Its size in bytes is 8 * ecdh.private_n
            * (ecdh.private_n is the size in limbs, i.e number of 64 bits blocks).
            *
            * CAUTION: Switch your environment configuration, MbedTLS may store
            * the shared secret ecdh.private_p in little endian BUT we need it
            * in big endian for the next step (key derivation).
            * Then a little endian to big endian conversion is needed.
            */

           ...

      .. note::
         ``my_mbedtls_rand`` must be a user function with the following
         definition: ``int my_mbedtls_rand(void *rng_state, unsigned char *output, size_t len)``.
         The function fills output buffer with a random value of len bytes.
         It must return 0 on success. Implementation depends on your environment.

   #. Key derivation:

      In this step, the shared secret buffer generated in previous step is
      used as input. Let's identify it as ``ecdh`` and ``ecdh_size``
      (size in bytes).

      .. note::
         ECDH buffer must be in big endian.


      Here's a sample of code that can be used to derive the host OEM Master
      key named ``Host_OEM_MK`` key:

        .. code-block:: C
           :linenos:

           int res = -1;
           const mbedtls_md_info_t *md = NULL;
           uint32_t salt_size = 0;
           uint8_t *salt = NULL;
           uint32_t info_size = 0;
           uint8_t *info = NULL;
           uint32_t Host_OEM_MK_size = 256 / 8;
           uint8_t *Host_OEM_MK[Host_OEM_MK_size];

           /* Set md info */
           md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
           if (md == NULL)
              /* Failure */

           /*
            * In this example:
            * Salt is NULL and salt_size is 0: a string of zeros of SHA256 bytes
            * length will be used.
            *
            * Info is NULL and info_size is 0: no fixed info are used in the
            * derivation process.
            *
            * Both Salt and Fixed info could be enabled/set but previous steps
            * must defined the same.
            */
           res = mbedtls_hkdf(md, salt, salt_size, ecdh, ecdh_size, info,
                              info_size, Host_OEM_MK, Host_OEM_MK_size);
           if (res != 0)
              /* Failure */

           ...

#. **On host**, derives the wrapping key:

   Use third party crypto service (MbedTLS library).

   In this step, the OEM Master key is the ``Host_OEM_MK`` key buffer generated
   in previous step is used as input.

   Here's a sample of code that can be used to derive the wrapping key identified
   by ``Host_OEM_WRAP_key`` key:

     .. code-block:: C
        :linenos:

        int res = -1;
        const mbedtls_md_info_t *md = NULL;
        uint32_t salt_size = 0;
        uint8_t *salt = NULL;
        uint32_t info_size = 24;
        uint8_t *info = "oemelefwkeyimportwrap256";
        uint32_t Host_OEM_WRAP_key_size = 256 / 8;
        uint8_t *Host_OEM_WRAP_key[Host_OEM_WRAP_key_size];

        /* Set md info */
        md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (md == NULL)
          /* Failure */

        /*
         * In this example:
         * Salt is NULL and salt_size is 0: a string of zeros of SHA256 bytes
         * length will be used.
         *
         * Salt could be enabled/set but previous steps must defined the same.
         *
         * Info is imposed by ELE FW.
         */
        res = mbedtls_hkdf(md, salt, salt_size, Host_OEM_MK, Host_OEM_MK_size,
                           info, info_size, Host_OEM_WRAP_key,
                           Host_OEM_WRAP_key_size);
        if (res != 0)
          /* Failure */

        ...

#. **On host**, derives the signing key:

   Use third party crypto service (MbedTLS library).

   In this step, the OEM Master key is the ``Host_OEM_MK`` key buffer generated
   in previous step is used as input.

   Here's a sample of code that can be used to derive the wrapping key identified
   by ``Host_OEM_CMAC_key`` key:

     .. code-block:: C
        :linenos:

        int res = -1;
        const mbedtls_md_info_t *md = NULL;
        uint32_t salt_size = 0;
        uint8_t *salt = NULL;
        uint32_t info_size = 24;
        uint8_t *info = "oemelefwkeyimportcmac256";
        uint32_t Host_OEM_CMAC_key_size = 256 / 8;
        uint8_t *Host_OEM_CMAC_key[Host_OEM_CMAC_key_size];

        /* Set md info */
        md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (md == NULL)
          /* Failure */

        /*
         * In this example:
         * Salt is NULL and salt_size is 0: a string of zeros of SHA256 bytes
         * length will be used.
         *
         * Salt could be enabled/set but previous steps must defined the same.
         *
         * Info is imposed by ELE FW.
         */
        res = mbedtls_hkdf(md, salt, salt_size, Host_OEM_MK, Host_OEM_MK_size,
                           info, info_size, Host_OEM_CMAC_key,
                           Host_OEM_CMAC_key_size);
        if (res != 0)
          /* Failure */

        ...

#. **On host**, build the EdgeLock Enclave blob to import the key:

   The blob must be builf by yourself and encoded as described
   in :numref:`ele_import_blob`.

   Third party crypto service (MbedTLS library) is used to wrap the
   imported key and signed the blob.

   Here's a sample of code that can be used to wrap the imported key
   with `RFC3394 <https://datatracker.ietf.org/doc/html/rfc3394>`_ algorithm:

     .. code-block:: C
        :linenos:

        uint32_t imported_key_size = 256 / 8;
        uint8_t imported_key[imported_key_size];
        uint32_t wrap_key_size = imported_key_size + 8; /* RFC3394 algorithm adds 8 bytes */
        uint8_t wrap_key[wrap_key_size];
        uint32_t out_len = 0;
        mbedtls_nist_kw_context kw_ctx;

        /* MbedTLS KW context init and setup */
        mbedtls_nist_kw_init(&kw_ctx);

        res = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES,
                                     Host_OEM_WRAP_key, 256, 1);
        if (res != 0)
          /* Failure */

        /* Execute key wrapping operation */
        res = mbedtls_nist_kw_wrap(&kw_ctx, MBEDTLS_KW_MODE_KW, imported_key,
                                   imported_key_size, wrap_key, &out_len,
                                   wrap_key_size);
        if (res != 0)
          /* Failure */

        ...


   Here's a sample of code that can be used to sign the blob with CMAC algorithm:

     .. code-block:: C
        :linenos:

        int res = -1;
        const mbedtls_cipher_info_t *cipher_info = NULL;
        uint32_t signature_size = 16; /* Default CMAC output size */
        uin32_t message_size = tlv_size - signature_size; /* Full TLV buffer size */
        uint8_t tlv[tlv_size]; /* The TLV buffer you built previously */
        uint8_t *signature_ptr = tlv + message_size;

        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
        if (cipher_info == NULL)
           return failure;

        res = mbedtls_cipher_cmac(cipher_info, Host_OEM_CMAC_key, 256, tlv,
                                  message_size, signature_ptr);
        if (res != 0)
          /* Failure */

        ...


   Here's an example of EdgeLock Enclave blob to import an AES 256 bits key:

    - identifier = 0x66
    - permitted algorithm is defined to permit all ciphers mode
    - usage encrypt/decrypt
    - key is persistent
    - lifecycle is current device lifecycle
    - OEM Master key identifier = 0x2

    .. code-block:: C
       :linenos:

       uint8_t aes_key_ex[] = {
          0x40, 0x15, 0x65, 0x64, 0x67, 0x65, 0x6c, 0x6f,
          0x63, 0x6b, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76,
          0x65, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x41,
          0x04, 0x00, 0x00, 0x00, 0x66, 0x42, 0x04, 0x84,
          0xc0, 0xff, 0x00, 0x43, 0x04, 0x00, 0x00, 0x03,
          0x00, 0x44, 0x02, 0x24, 0x00, 0x45, 0x04, 0x00,
          0x00, 0x01, 0x00, 0x46, 0x04, 0xc0, 0x02, 0x00,
          0x01, 0x47, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50,
          0x04, 0x00, 0x00, 0x00, 0x02, 0x51, 0x04, 0x00,
          0x00, 0x00, 0x01, 0x54, 0x04, 0x00, 0x00, 0x00,
          0x01, 0x55, 0x28, 0x23, 0xb4, 0xa9, 0xf5, 0x9a,
          0x91, 0x9c, 0xd6, 0xfc, 0x6d, 0x27, 0xa7, 0xa6,
          0x27, 0x4e, 0xed, 0xf5, 0x6e, 0x92, 0x9f, 0x04,
          0xeb, 0xed, 0xef, 0xf0, 0x31, 0xe4, 0xc9, 0x51,
          0x9d, 0x12, 0x4d, 0x42, 0x50, 0xe8, 0x98, 0x82,
          0x95, 0x42, 0x96, 0x5e, 0x10, 0x77, 0x17, 0xd2,
          0x6c, 0x47, 0x55, 0x67, 0xf4, 0x0b, 0xeb, 0x7f,
          0x39, 0x31, 0xea, 0x8b, 0x86
       };

#. **On device**, import the key:

   The SMW API :c:func:`smw_import_key` is used to import the key.

   In the following example, the key imported is the blob example of the AES
   256 bits key above.

   .. code-block:: C
      :linenos:

      int res = -1;
      enum smw_status_code status = SMW_STATUS_OK;
      struct smw_import_key_args args = { 0 };
      struct smw_key_descriptor key = { 0 };
      struct smw_key_attributes *attributes = &key.attributes;
      struct smw_keypair_buffer buffer = { 0 };

      /* Set the private key buffer to use the blob example */
      buffer.gen.public_length = sizeof(aes_key_ex);
      buffer.gen.public_data = aes_key_ex;

     	args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
     	args.key_descriptor = &key;

      key.id = 0x66:
      key.type_name = SMW_KEY_TYPE_NAME_AES;
      key.security_size = 256;
      key.buffer = &buffer;

      attributes.permitted_algo = SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(SMW_ATTR_ALGO_AES,
                                                                     SMW_ATTR_MODE_ANY);
      attributes.usage_flags = SMW_ATTR_USAGE_ENCRYPT | SMW_ATTR_USAGE_DECRYPT;
      attributes.attributes = SMW_ATTR_SET_PERSISTENCE(attributes.attributes,
                                                       SMW_ATTR_PERSISTENCE_PERSISTENT);


      status = smw_import_key(&args);

      ...

Export Public Key
^^^^^^^^^^^^^^^^^
The **export public key** operation is used to extract the public key from a key
pair stored in the secure subsystem storage.

The PKCS11 interface to use is the C_GetAttributeValue() function to retrieve
the public key attribute containing the public key plaintext value.

.. table:: Export Public Key APIs Comparison
   :name: table_export_public_key_apis_comparison
   :align: center
   :widths: 25 15 60
   :width: 100%
   :class: wrap-table

   +------------------+---------+------------------------------------------------------------+
   | **Key Type**     | **API** | **Function** / **Key Type** or **Key Attribute**           |
   +==================+=========+============================================================+
   | Secp R1          | SMW     | :c:func:`smw_export_key`                                   |
   +                  +         +                                                            +
   |                  |         | SMW_KEY_TYPE_NAME_SECP_R1                                  |
   +                  +---------+------------------------------------------------------------+
   |                  | PSA     | :c:func:`psa_export_key` / :c:func:`psa_export_public_key` |
   +                  +         +                                                            +
   |                  |         | PSA_ECC_FAMILY_SECP_R1                                     |
   +                  +---------+------------------------------------------------------------+
   |                  | PKCS11  | C_GetAttributeValue()                                      |
   +                  +         +                                                            +
   |                  |         | CKA_EC_POINT                                               |
   +------------------+---------+------------------------------------------------------------+
   | Brainpool R1     | SMW     | :c:func:`smw_export_key`                                   |
   +                  +         +                                                            +
   |                  |         | SMW_KEY_TYPE_NAME_BRAINPOOL_R1                             |
   +                  +---------+------------------------------------------------------------+
   |                  | PSA     | :c:func:`psa_export_key` / :c:func:`psa_export_public_key` |
   +                  +         +                                                            +
   |                  |         | PSA_ECC_FAMILY_BRAINPOOL_P_R1                              |
   +                  +---------+------------------------------------------------------------+
   |                  | PKCS11  | Not defined                                                |
   +------------------+---------+------------------------------------------------------------+
   | Twisted Edwards  | SMW     | :c:func:`smw_export_key`                                   |
   +                  +         +                                                            +
   | (ED25519/ED448)  |         | SMW_KEY_TYPE_NAME_ED25519                                  |
   +                  +         +                                                            +
   |                  |         | SMW_KEY_TYPE_NAME_ED448                                    |
   +                  +---------+------------------------------------------------------------+
   |                  | PSA     | :c:func:`psa_export_key` / :c:func:`psa_export_public_key` |
   +                  +         +                                                            +
   |                  |         | PSA_ECC_FAMILY_TWISTED_EDWARDS                             |
   +                  +---------+------------------------------------------------------------+
   |                  | PKCS11  | C_GetAttributeValue()                                      |
   +                  +         +                                                            +
   |                  |         | CKA_EC_POINT                                               |
   +------------------+---------+------------------------------------------------------------+
   | Montgomery       | SMW     | :c:func:`smw_export_key`                                   |
   +                  +         +                                                            +
   | (X25519/X448)    |         | SMW_KEY_TYPE_NAME_X25519                                   |
   +                  +         +                                                            +
   |                  |         | SMW_KEY_TYPE_NAME_X448                                     |
   +                  +---------+------------------------------------------------------------+
   |                  | PSA     | :c:func:`psa_export_key` / :c:func:`psa_export_public_key` |
   +                  +         +                                                            +
   |                  |         | PSA_ECC_FAMILY_MONTGOMERY                                  |
   +                  +---------+------------------------------------------------------------+
   |                  | PKCS11  | C_GetAttributeValue()                                      |
   +                  +         +                                                            +
   |                  |         | CKA_EC_POINT                                               |
   +------------------+---------+------------------------------------------------------------+
   | RSA              | SMW     | :c:func:`smw_export_key`                                   |
   +                  +         +                                                            +
   |                  |         | SMW_KEY_TYPE_NAME_RSA                                      |
   +                  +---------+------------------------------------------------------------+
   |                  | PSA     | :c:func:`psa_export_key` / :c:func:`psa_export_public_key` |
   +                  +         +                                                            +
   |                  |         | PSA_KEY_TYPE_RSA_KEY_PAIR                                  |
   +                  +---------+------------------------------------------------------------+
   |                  | PKCS11  | C_GetAttributeValue()                                      |
   +                  +         +                                                            +
   |                  |         | CKA_MODULUS and CKA_PUBLIC_EXPONENT                        |
   +------------------+---------+------------------------------------------------------------+


Key Derivation
^^^^^^^^^^^^^^
The **key derivation** operation is used to derive one or more keys from a
secret value such as a shared secret or a password.

.. table:: Key Derivation APIs Comparison
   :name: table_key_derivation_apis_comparison
   :align: center
   :widths: 22 12 66
   :width: 100%
   :class: wrap-table

   +------------------+---------+-------------------------------------------------------+
   | **KDF Type**     | **API** | **Function** / **Algorithm**                          |
   +==================+=========+=======================================================+
   | HKDF             | SMW     | :c:func:`smw_derive_key`                              |
   +                  +         +                                                       +
   |                  |         | SMW_KDF_NAME_HKDF                                     |
   +                  +         +                                                       +
   |                  |         | SMW_KDF_NAME_HKDF_EXTRACT                             |
   +                  +         +                                                       +
   |                  |         | SMW_KDF_NAME_HKDF_EXPAND                              |
   +                  +---------+-------------------------------------------------------+
   |                  | PSA     | :c:func:`psa_key_derivation_output_key` /             |
   |                  |         | :c:func:`psa_key_derivation_output_bytes`             |
   +                  +         +                                                       +
   |                  |         | PSA_ALG_HKDF(hash)                                    |
   +                  +         +                                                       +
   |                  |         | PSA_ALG_HKDF_EXTRACT(hash)                            |
   +                  +         +                                                       +
   |                  |         | PSA_ALG_HKDF_EXPAND(hash)                             |
   +                  +---------+-------------------------------------------------------+
   |                  | PKCS11  | C_DeriveKey()                                         |
   +                  +         +                                                       +
   |                  |         | CKM_HKDF_DERIVE                                       |
   +------------------+---------+-------------------------------------------------------+

Key Agreement
^^^^^^^^^^^^^
The **key agreement** operation is used to derive a shared secret from two key
pairs.
The shared secret can then be used as input to a key derivation function.

The Secure Subsystems able to do key agreement are limited to ELE and SECO
(if SECO specific FW is loaded).

The key agreement supported are ECDH and `OEM Master key`_. The OEM
Master key is used to import secure key in the ELE Secure Subsystem using
a blob where key is encrypted.


.. table:: Key Derivation & Key Agreement APIs Comparison
   :name: table_key_derivation_agreement_apis_comparison
   :align: center
   :widths: 22 12 66
   :width: 100%
   :class: wrap-table

   +------------------+---------+-------------------------------------------------------+
   | **KDF Type**     | **API** | **Function** / **Algorithm**                          |
   +==================+=========+=======================================================+
   | ECDH             | SMW     | :c:func:`smw_derive_key`                              |
   +                  +         +                                                       +
   |                  |         | SMW_KDF_NAME_ECDH                                     |
   +                  +---------+-------------------------------------------------------+
   |                  | PSA     | :c:func:`psa_key_agreement` /                         |
   |                  |         | :c:func:`psa_key_derivation_key_agreement`            |
   +                  +         +                                                       +
   |                  |         | PSA_ALG_ECDH                                          |
   +                  +---------+-------------------------------------------------------+
   |                  | PKCS11  | C_DeriveKey()                                         |
   +                  +         +                                                       +
   |                  |         | CKM_ECDH1_DERIVE                                      |
   +------------------+---------+-------------------------------------------------------+
   | OEM Master Key   | SMW     | :c:func:`smw_derive_key`                              |
   +                  +         +                                                       +
   |                  |         | SMW_KDF_NAME_OEM_MASTER_KEY                           |
   +                  +---------+-------------------------------------------------------+
   |                  | PSA     | Not supported                                         |
   +                  +---------+-------------------------------------------------------+
   |                  | PKCS11  | Not supported                                         |
   +------------------+---------+-------------------------------------------------------+

OEM Master key
""""""""""""""
The OEM Master key is a key agreement between a secure host ECDSA key and a
device ECDSA key. The resulting key is a symmetric key used to derive two keys:

  - A wrap key to wrap secure key to import
  - A sign key to sign EdgeLock Enclave blob including the wrapped key and
    its attributes.

The OEM Master key requests a EdgeLock Enclave signed message to authenticate
the key attributes and derivation parameters.

The SMW library offers the possibility to pre-fill the message payload to be
signed (see :ref:smw_kdf_oem_master_key_args).

The NXP SPSDK tool can be used to sign the message and can be installed from
`SPSDK releases <https://github.com/nxp-mcuxpresso/spsdk/releases>`_.
The documentation is available `here <https://spsdk.readthedocs.io/en/latest/index.html>`_.
The command used to sign is `nxpimage <https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html#nxpimage-signed-msg>`_.


The OEM Master key attributes are almost pre-defined, the following
:numref:`oem_mk_attributes` lists the value to set in the signed payload
and the SMW key attributes.

The signed payload defined also a ``derived key group`` field where the key
will be stored. Value must be in the range [0:99]
SMW defined 2 groups range function of the key persistency:

  - 0:49 Groups of the persistent keys
  - 50:99 Groups of the transient keys

It's impossible during runtime to predict the group number where the key could
be stored if other keys are already present in the ELE NVM Secure Storage.
If the key group can't be known in advance, it's adviced to use the SMW
operation pre-filling the payload content (see :ref:`smw_kdf_oem_master_key_args`)
that will try to find a key group number where the key could be stored. Note,
even that, it's not 100% guaranty that the key group will have enough place to
store the key at the time the key derivation operation will be requested.

It's adviced to store this key as persistent key with a known key identifier.
In case of transient key the ELE FW will assign the key identifier after key
derivation operation success.

.. table:: OEM Master key attributes
   :name: oem_mk_attributes
   :align: center
   :class: wrap-table

   +----------------------+------------+-------------------------------------------+
   | Key attributes       | ELE value  | SMW value                                 |
   +======================+============+===========================================+
   | Key type             | 0x9200     | SMW_KEY_TYPE_NAME_DERIVE                  |
   +----------------------+------------+-------------------------------------------+
   | Security size (bits) | 256        | 256                                       |
   +----------------------+------------+-------------------------------------------+
   | Usage                | 0x00004000 | SMW_ATTR_USAGE_DERIVE                     |
   +----------------------+------------+-------------------------------------------+
   | Permitted algorithm  | 0x0800109  | SMW_ATTR_ALGO_KEY_DERIVATION_HKDF(SHA256) |
   +----------------------+------------+-------------------------------------------+
   | Lifetime             | 0x00000000 | SMW_ATTR_PERSISTENCE_TRANSIENT flag       |
   +                      +------------+-------------------------------------------+
   |                      | 0x00000001 | SMW_ATTR_PERSISTENCE_PERSISTENT flag      |
   +----------------------+------------+-------------------------------------------+
   | Lifecycle flags      | 0x00       | SMW_ATTR_LIFECYCLE_CURRENT                |
   +                      +------------+-------------------------------------------+
   |                      | 0x01       | SMW_ATTR_LIFECYCLE_OPEN                   |
   +                      +------------+-------------------------------------------+
   |                      | 0x02       | SMW_ATTR_LIFECYCLE_CLOSED                 |
   +                      +------------+-------------------------------------------+
   |                      | 0x03       | SMW_ATTR_LIFECYCLE_CLOSED_LOCKED          |
   +----------------------+------------+-------------------------------------------+

.. important::
  The OEM SRKH must be fused.

.. note::
  Only supported on i.MX8ULP, i.MX91, i.MX93 and i.MX943

Usage Example
~~~~~~~~~~~~~
See the :ref:`Example (with OEM Master key derivation) <ELE_blob_example>`


TLS 1.2 (PRF)
^^^^^^^^^^^^^
The TLS 1.2 Pseudo-Random Function (PRF) is used to derive key material during
the TLS handshake process. The subsystem supports the following TLS 1.2 operations:

- Master secret generation from pre-master secret
- Key expansion to derive encryption/decryption keys and IVs
- Finished message verification data generation


.. warning::
   TLS 1.2 is considered legacy. For new implementations, consider using
   TLS 1.3 which provides improved security and performance.


Key Exchange and Ciphersuites
"""""""""""""""""""""""""""""
Only Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange is supported,
using SECP_R1 key type.

The base key size used for ECDH(E) determines which ciphersuites can be used:

- **256-bit keys**: Support SHA256-based ciphersuites
- **384-bit keys**: Support SHA384-based ciphersuites

.. note::
   ELE does not allow some operations on data with length less than the key size.
   Therefore, the key size of the base key used for ECDH(E) dictates which
   ciphersuites are available. For example, if the key size is 384 bits, you may
   only use ciphersuites that use SHA384.

Supported Ciphersuites
""""""""""""""""""""""
The following ciphersuites are supported:

.. table:: TLS 1.2 Ciphersuites
   :name: tls12_ciphersuites
   :align: center
   :widths: 60 40
   :width: 100%
   :class: wrap-table

   +-----------------------------------------------+-------------------------------+
   | **Cipher Suite**                              | **OpenSSL equivalent**        |
   +===============================================+===============================+
   | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       | ECDHE-ECDSA-AES128-SHA256     |
   +-----------------------------------------------+-------------------------------+
   | TLS_ECDHE_ECDSA_WITH_AES_128_CCM              | ECDHE-ECDSA-AES128-CCM        |
   +-----------------------------------------------+-------------------------------+
   | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | ECDHE-ECDSA-AES128-GCM-SHA256 |
   +-----------------------------------------------+-------------------------------+
   | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384       | ECDHE-ECDSA-AES256-SHA384     |
   +-----------------------------------------------+-------------------------------+
   | TLS_ECDHE_ECDSA_WITH_AES_256_CCM              | ECDHE-ECDSA-AES256-CCM        |
   +-----------------------------------------------+-------------------------------+
   | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | ECDHE-ECDSA-AES256-GCM-SHA384 |
   +-----------------------------------------------+-------------------------------+
   | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | ECDHE-ECDSA-CHACHA20-POLY1305 |
   +-----------------------------------------------+-------------------------------+

Encryption Types
""""""""""""""""
The supported cipher suites use the following encryption types:

- **AES CBC and GCM**: Defined in `RFC 5289 <https://www.rfc-editor.org/rfc/rfc5289>`_
- **AES CCM**: Defined in `RFC 7251 <https://www.rfc-editor.org/rfc/rfc7251>`_
- **CHACHA20_POLY1305**: Defined in `RFC 7905 <https://www.rfc-editor.org/rfc/rfc7905>`_

TLS 1.2 PRF Algorithm
"""""""""""""""""""""
The TLS 1.2 PRF is based on HMAC and uses the following construction:

.. code-block:: none

   PRF(secret, label, seed) = P_<hash>(secret, label + seed)

Where:

- **secret**: The pre-master secret or master secret
- **label**: An ASCII string identifying the purpose of the key derivation
- **seed**: Random data (typically client_random + server_random)
- **hash**: SHA256 or SHA384 depending on the ciphersuite

Key Derivation Process
""""""""""""""""""""""
The typical TLS 1.2 key derivation process involves:

1. **Master Secret Derivation**:

   .. code-block:: none

      master_secret = PRF(pre_master_secret, "master secret",
                          client_random + server_random)[0..47]

2. **Key Material Expansion**:

   .. code-block:: none

      key_block = PRF(master_secret, "key expansion",
                      server_random + client_random)

3. **Key Material Partitioning**:

   The key_block is partitioned into:

   - Client write MAC key
   - Server write MAC key
   - Client write encryption key
   - Server write encryption key
   - Client write IV
   - Server write IV

Subsystem Support
"""""""""""""""""

.. table:: TLS 1.2 Subsystem Support
   :name: tls12_subsystem_support
   :align: center
   :widths: 20 15 65
   :width: 100%
   :class: wrap-table

   +---------------+-------------+-----------------------------------------------+
   | **Subsystem** | **Support** | **Notes**                                     |
   +===============+=============+===============================================+
   | ELE           | Yes         | Full TLS 1.2 PRF support.                     |
   +---------------+-------------+-----------------------------------------------+
   | TEE           | No          | Not supported.                                |
   +---------------+-------------+-----------------------------------------------+
   | SECO          | Yes*        | Requires specific Firmware.                   |
   +               +             +                                               +
   |               |             | Following encryption types are not supported: |
   |               |             |                                               |
   |               |             |   - AES CCM                                   |
   |               |             |   - CHACHA20_POLY1305_SHA256                  |
   +---------------+-------------+-----------------------------------------------+

Usage Example with SMW API
""""""""""""""""""""""""""
Here's a basic example of doing TLS 1.2 key derivation with SMW API to
use a TLS_ECDHE_ECDSA_WITH_AES_128_CCM_SHA256 cipher suite.

.. code-block:: c
   :linenos:

   #include <smw_keymgr.h>
   #include <smw_crypto.h>

   static int derive_tls12_master_key(struct smw_op_context *ctx,
                                      unsigned int pre_master_secret_id,
                                      unsigned char client_random[32],
                                      unsigned char server_random[32],
                                      unsigned char *peer_key,
                                      unsigned int peer_key_size,
                                      unsigned int *master_key_id)
   {
       enum smw_status_code status;
       struct smw_op_context ctx = { 0 };
       struct smw_derive_key_args args = { 0 };
       struct smw_key_descriptor base_key = { 0 };
       struct smw_derived_key_descriptor derived_key = { 0 };
       struct smw_kdf_tls12_op_args tls12_args = { 0 };
       struct smw_kdf_tls12_random_data random_data = { 0 };

       /* Configure TLS 1.2 KDF arguments */
       args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
       args.key_descriptor_base = &base_key;
       args.key_descriptor_derived = &derived_key;
       args.kdf_name = SMW_KDF_NAME_TLS12_OP_KEY_EXCHANGE;
       args.kdf_arguments = &tls12_args;

       /* Set base key (pre-master secret) */
       base_key.id = pre_master_secret_id;

       /* Configure TLS 1.2 specific parameters */
       tls12_args.op_name = SMW_TLS12_OP_NAME_MASTER_SECRET;
       tls12_args.prf_name = SMW_HASH_ALGO_NAME_SHA256;
       tls12_args.client_random = client_random;
       tls12_args.client_random_length = sizeof(client_random);
       tls12_args.server_random = server_random;
       tls12_args.server_random_length = sizeof(server_random);
       tls12_args.context = &ctx;

       tls12_args.master_secret.key_exchange_name = SMW_TLS12_KEA_NAME_ECDH_ECDSA;
       tls12_args.master_secret.ext_master_key = false;
       tls12_args.master_secret.peer_public_buffer = peer_key
       tls12_args.master_secret.peer_public_buffer_length = peer_key_size;

       tls12_args.master_secret.random_data = &random_data;
       random_data.client_random = client_random;
       random_data.client_random_length = sizeof(client_random);
       random_data.server_random = server_random;
       random_data.server_random_length = sizeof(server_random);

       /* Derive master secret */
       status = smw_derive_key(&args);
       if (status != SMW_STATUS_OK) {
           /* Handle error */
           return -1;
       }

       /* Store derived master key ID */
       *master_key_id = derived_key.id;

       return 0;
   }

   static int derive_tls12_key_material(struct smw_op_context *ctx,
                                        unsigned int master_key_id,
                                        unsigned char client_random[32],
                                        unsigned char server_random[32]
                                        unsigned char client_iv[12],
                                        unsigned char server_iv[12],
                                        unsigned int *client_wr_enc_key_id,
                                        unsigned int *server_wr_enc_key_id,
                                        unsigned int *client_wr_mac_key_id,
                                        unsigned int *server_wr_mac_key_id)
   {
       enum smw_status_code status;
       struct smw_derive_key_args args = { 0 };
       struct smw_key_descriptor base_key = { 0 };
       struct smw_derived_key_descriptor derived_key = { 0 };
       struct smw_kdf_tls12_op_args tls12_args = { 0 };
       struct smw_kdf_tls12_random_data random_data = { 0 };

       /* Configure TLS 1.2 KDF arguments */
       args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
       args.key_descriptor_base = &base_key;
       args.key_descriptor_derived = &derived_key;
       args.kdf_name = SMW_KDF_NAME_TLS12_OP_KEY_EXCHANGE;
       args.kdf_arguments = &tls12_args;

       /* Set base key (master key derived before) */
       base_key.id = master_key_id;

       /* Configure TLS 1.2 specific parameters */
       tls12_args.op_name = SMW_TLS12_OP_NAME_KEY_EXPANSION;
       tls12_args.prf_name = SMW_HASH_ALGO_NAME_SHA256;
       tls12_args.client_random = client_random;
       tls12_args.client_random_length = sizeof(client_random);
       tls12_args.server_random = server_random;
       tls12_args.server_random_length = sizeof(server_random);
       tls12_args.context = &ctx;

       tls12_args.key_expansion.encryption_name = SMW_TLS12_ENC_NAME_AES_128_CCM;
       tls12_args.key_expansion.random_data = &random_data
       random_data.client_random = client_random;
       random_data.client_random_length = sizeof(client_random);
       random_data.server_random = server_random;
       random_data.server_random_length = sizeof(server_random);

       tls12_args.key_expansion.client_w_iv = client_iv;
       tls12_args.key_expansion.client_w_iv_length = sizeof(client_iv);
       tls12_args.key_expansion.server_w_iv = server_iv;
       tls12_args.key_expansion.server_w_iv_length = sizeof(server_iv);

       /* Derive master secret */
       status = smw_derive_key(&args);
       if (status != SMW_STATUS_OK) {
           /* Handle error */
           return -1;
       }

       /* Store derived key material IDs */
       *client_wr_enc_key_id = tls12_args.key_expansion.client_w_enc_key_id;
       *server_wr_enc_key_id = tls12_args.key_expansion.server_w_enc_key_id;
       *client_wr_mac_key_id = tls12_args.key_expansion.client_w_mac_key_id;
       *server_wr_mac_key_id = tls12_args.key_expansion.server_w_mac_key_id;

       return 0;
   }

   int derive_tls12_keys(...)
   {
       int res = 0;
       enum smw_status_code status;
       struct smw_op_context ctx = { 0 };
       unsigned int master_key_id = 0;
       unsigned int client_wr_enc_key_id = 0;
       unsigned int server_wr_enc_key_id = 0;
       unsigned int client_wr_mac_key_id = 0;
       unsigned int server_wr_mac_key_id = 0;
       unsigned char client_iv[12] = { 0 };
       unsigned char server_iv[12] = { 0 };

       status = smw_allocate_context(&ctx);
       if (status != SMW_STATUS_OK)
           return -1;

      /*
       * Pre-master key id, client_random, server_random, peer_key,
       * peer_key_size are expected to be provided when calling this function.
       */

       res = derive_tls12_master_secret(&ctx, pre_master_secret_id,
                                        client_random, server_random,
                                        peer_key, peer_key_size, &master_key_id);
       if (res != 0) {
           smw_cancel_context(&ctx);
           return res;
       }

       res = derive_tls12_key_material(&ctx, master_key_id, client_random,
                                       server_random, client_iv, server_iv,
                                       &client_wr_enc_key_id, &server_wr_enc_key_id,
                                       &client_wr_mac_key_id, &server_wr_mac_key_id);

       if (res != 0)
           return res;

       /* Now you can use keys and ivs for encryption/decryption */
       /* ... */
   }


Usage Example with PSA API
""""""""""""""""""""""""""
Here's a basic example of doing TLS 1.2 key derivation with PSA API to
use a TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <stdlib.h>
   #include "psa/crypto.h"

   /* Step 1: Derive master secret from pre-master secret */
   static int derive_master_secret(psa_key_id_t ecdh_key_id,
                                  const uint8_t *peer_public_key,
                                  size_t peer_public_key_length,
                                  const uint8_t *client_random,
                                  const uint8_t *server_random,
                                  psa_key_id_t *master_secret_id)
   {
       psa_status_t status;
       psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
       psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
       const uint8_t label[] = "master secret";
       uint8_t *seed = NULL;

       /* Prepare seed: label || client_random || server_random */
       seed = malloc(13 + 32 + 32); /* 13 bytes for label + 32 + 32 for randoms */
       if (!seed) {
           printf("Memory allocation failed\n");
           return -1;
       }

       memcpy(seed, label, 13);
       memcpy(seed + 13, client_random, 32);
       memcpy(seed + 13 + 32, server_random, 32);

       /* Setup key derivation operation for TLS 1.2 PRF */
       status = psa_key_derivation_setup(&operation,
                                         PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_setup failed: %d\n", status);
           return -1;
       }

       /* Set the input secret for the pre-master key internal generation */
       status = psa_key_derivation_key_agreement(&operation,
                                             PSA_KEY_DERIVATION_INPUT_SECRET,
                                             ecdh_key_id,
                                             peer_public_key,
                                             peer_public_key_length);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_key_agreement failed: %d\n", status);
           goto cleanup;
       }

       /* Set the seed (label + client_random + server_random) */
       status = psa_key_derivation_input_bytes(&operation,
                                               PSA_KEY_DERIVATION_INPUT_SEED,
                                               seed, sizeof(seed));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_bytes (seed) failed: %d\n", status);
           goto cleanup;
       }


       /* Output master secret key id for further derivation */
       psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
       psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);

       /* Output master secret key id */
       status = psa_key_derivation_output_key(&attributes, &operation, master_secret_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_key failed: %d\n", status);
           goto cleanup;
       }

       printf("Derived master secret with ID: %u\n", *master_secret_id);

   cleanup:
       if (seed)
           free(seed);

       psa_key_derivation_abort(&operation);
       return (status == PSA_SUCCESS) ? 0 : -1;
   }

   /* Step 2: Derive key material (encryption keys, MAC keys, IVs) */
   static int derive_key_material(psa_key_id_t master_secret_id,
                                  const uint8_t *client_random,
                                  const uint8_t *server_random,
                                  psa_key_id_t *client_mac_key_id,
                                  psa_key_id_t *server_mac_key_id,
                                  psa_key_id_t *client_enc_key_id,
                                  psa_key_id_t *server_enc_key_id,
                                  uint8_t *client_iv,
                                  uint8_t *server_iv)
   {
       psa_status_t status;
       psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
       psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
       const uint8_t label[] = "key expansion";
       uint8_t *seed = NULL;

       /* Prepare seed: label || server_random || client_random (note the order) */
       seed = malloc(13 + 32 + 32); /* 13 bytes for label + 32 + 32 for randoms */
       if (!seed) {
           printf("Memory allocation failed\n");
           return -1;
       }

       memcpy(seed, label, 13);
       memcpy(seed + 13, server_random, 32);
       memcpy(seed + 13 + 32, client_random, 32);

       /* Setup key derivation operation for TLS 1.2 PRF */
       status = psa_key_derivation_setup(&operation,
                                         PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_setup failed: %d\n", status);
           return -1;
       }

       /* Set the master secret as input */
       status = psa_key_derivation_input_key(&operation,
                                             PSA_KEY_DERIVATION_INPUT_SECRET,
                                             master_secret_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_key failed: %d\n", status);
           goto cleanup;
       }

       /* Set the seed (label + server_random + client_random) */
       status = psa_key_derivation_input_bytes(&operation,
                                               PSA_KEY_DERIVATION_INPUT_SEED,
                                               seed, sizeof(seed));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_bytes (seed) failed: %d\n", status);
           goto cleanup;
       }

       /* Output client AES encryption key (AES-128-GCM) */
       psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
       psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
       psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
       psa_set_key_bits(&attributes, 128);
       psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

       status = psa_key_derivation_output_key(&attributes, &operation, client_enc_key_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_key failed: %d\n", status);
           goto cleanup;
       }

       /* Output server AES encryption key (AES-128-GCM) */
       status = psa_key_derivation_output_key(&attributes, &operation, server_enc_key_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_key failed: %d\n", status);
           goto cleanup;
       }

       /* Output IVs (for GCM, these are the implicit parts) */
       status = psa_key_derivation_output_bytes(&operation, client_iv, 4);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_bytes (client_iv) failed: %d\n", status);
           goto cleanup;
       }

       status = psa_key_derivation_output_bytes(&operation, server_iv, 4);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_bytes (server_iv) failed: %d\n", status);
           goto cleanup;
       }

       printf("Derived all key material successfully\n");
       printf("Client encryption key handle: %lu\n", client_enc_key);
       printf("Server encryption key handle: %lu\n", server_enc_key);

   cleanup:
       if (seed)
       free(seed);

       psa_key_derivation_abort(&operation);
       return (status == PSA_SUCCESS) ? 0 : -1;
   }

   /* Complete TLS 1.2 key derivation workflow */
   int tls12_derive_keys_psa(...)
   {
       psa_status_t status;
       psa_key_id_t ecdh_key_id = 0;
       psa_key_id_t master_secret_id = 0;
       psa_key_id_t client_enc_key_id = 0;
       psa_key_id_t server_enc_key_id = 0;
       uint8_t client_iv[12] = {0}; /* Full IV for GCM */
       uint8_t server_iv[12] = {0}; /* Full IV for GCM */
       int ret = 0;

       /*
        * Pre-master key id, client_random, server_random, peer_key,
        * peer_key_size are expected to be provided whe calling this function.
        */

       printf("\n=== TLS 1.2 Key Derivation with PSA API ===\n\n");

       /* Step 3: Derive master secret */
       printf("\nStep 1: Deriving master secret...\n");
       if (derive_master_secret(ecdh_key_id, peer_public_key, 64,
                               client_random, server_random,
                               &master_secret_id) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 4: Derive key material */
       printf("\nStep 2: Deriving key material...\n");
       if (derive_key_material(master_secret_id,
                              client_random, server_random,
                              &client_enc_key_id, &server_enc_key_id,
                              client_iv, server_iv) != 0) {
           ret = -1;
           goto cleanup;
       }

       printf("\n=== TLS 1.2 key derivation completed successfully! ===\n");

       /* Now you can use keys and ivs for encryption/decryption */
       /* ... */
   }


Usage Example with PKCS11 API
"""""""""""""""""""""""""""""
Here's a basic example of using TLS 1.2 key derivation with PKCS11 API to
use a TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <stdlib.h>
   #include "pkcs11.h"

   /* Step 1: Perform ECDH to derive pre-master secret */
   static int derive_premaster_secret(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE priv_key,
                                      CK_BYTE *peer_public_key,
                                      CK_ULONG peer_key_len,
                                      CK_OBJECT_HANDLE *premaster_secret)
   {
       CK_RV rv;
       CK_ECDH1_DERIVE_PARAMS ecdh_params = {
           .kdf = CKD_NULL,
           .pSharedData = NULL,
           .ulSharedDataLen = 0,
           .pPublicData = peer_public_key,
           .ulPublicDataLen = peer_key_len
       };

       CK_MECHANISM mechanism = {
           .mechanism = CKM_ECDH1_DERIVE,
           .pParameter = &ecdh_params,
           .ulParameterLen = sizeof(ecdh_params)
       };

       /* Template for derived pre-master secret */
       CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
       CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
       CK_ULONG key_len = 32; /* 256 bits for SECP256R1 */
       CK_MECHANISM_TYPE key_allowed_mech = { CKM_TLS12_MASTER_KEY_DERIVE_DH };

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &secret_class, sizeof(secret_class) },
           { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
           { CKA_VALUE_LEN, &key_len, sizeof(key_len) },
           { CKA_ALLOWED_MECHANISMS, &key_allowed_mech, sizeof(key_allowed_mech) },
           { CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
           { CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) }
       };

       rv = p11_func->C_DeriveKey(session, &mechanism, priv_key,
                                  template, 6, premaster_secret);
       if (rv != CKR_OK) {
           printf("C_DeriveKey (ECDH) failed: 0x%lx\n", rv);
           return -1;
       }

       return 0;
   }

   /* Step 2: Derive master secret from pre-master secret */
   static int derive_master_secret(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE premaster_secret,
                                  CK_BYTE *client_random,
                                  CK_BYTE *server_random,
                                  CK_OBJECT_HANDLE *master_secret)
   {
       CK_RV rv;
       CK_SSL3_RANDOM_DATA random_data = {
           .pClientRandom = client_random,
           .ulClientRandomLen = 32,
           .pServerRandom = server_random,
           .ulServerRandomLen = 32
       };

       CK_TLS12_MASTER_KEY_DERIVE_PARAMS params = {
           .prfHashMechanism = CKM_SHA256,
           .RandomInfo = random_data,
           .pVersion = NULL  /* Use default TLS 1.2 */
       };

       CK_MECHANISM mechanism = {
           .mechanism = CKM_TLS12_MASTER_KEY_DERIVE,
           .pParameter = &params,
           .ulParameterLen = sizeof(params)
       };

       /* Template for master secret */
       CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
       CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
       CK_ULONG key_len = 48; /* TLS master secret is always 48 bytes */
       CK_MECHANISM_TYPE key_allowed_mech = { CKM_TLS12_KEY_AND_MAC_DERIVE };

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &secret_class, sizeof(secret_class) },
           { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
           { CKA_VALUE_LEN, &key_len, sizeof(key_len) },
           { CKA_ALLOWED_MECHANISMS, &key_allowed_mech, sizeof(key_allowed_mech) },
           { CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }
       };

       rv = p11_func->C_DeriveKey(session, &mechanism, premaster_secret,
                                  template, 5, master_secret);
       if (rv != CKR_OK) {
           printf("C_DeriveKey (Master Secret) failed: 0x%lx\n", rv);
           return -1;
       }

       return 0;
   }

   /* Step 3: Derive key material (encryption keys, MAC keys, IVs) */
   static int derive_key_material(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE master_secret,
                                  CK_BYTE *client_random,
                                  CK_BYTE *server_random,
                                  CK_OBJECT_HANDLE *client_mac_key,
                                  CK_OBJECT_HANDLE *server_mac_key,
                                  CK_OBJECT_HANDLE *client_enc_key,
                                  CK_OBJECT_HANDLE *server_enc_key,
                                  CK_ULONG iv_size_bits,
                                  CK_BYTE *client_iv,
                                  CK_BYTE *server_iv)
   {
       CK_RV rv;
       CK_SSL3_RANDOM_DATA random_data = {
           .pClientRandom = client_random,
           .ulClientRandomLen = 32,
           .pServerRandom = server_random,
           .ulServerRandomLen = 32
       };

       /* For AES-128-GCM-SHA256 cipher suite */
       CK_SSL3_KEY_MAT_OUT key_material = {
           .pIVClient = client_iv,
           .pIVServer = server_iv,
       };
       CK_TLS12_KEY_MAT_PARAMS params = {
           .prfHashMechanism = CKM_SHA256,
           .bIsExport = CK_FALSE,
           .RandomInfo = random_data,
           .ulIV_SizeInBits = iv_size_bits,
           .ulKeySizeInBits = 160,
           .ulMacSizeInBits = 256,
           .pReturnedKeyMaterial = &key_material,
       };

       CK_MECHANISM mechanism = {
           .mechanism = CKM_TLS12_KEY_AND_MAC_DERIVE,
           .pParameter = &params,
           .ulParameterLen = sizeof(params)
       };

       /* Template for key encryption derived key */
       CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
       CK_KEY_TYPE key_type = CKK_AES;
       CK_ULONG key_len = 32;
       CK_MECHANISM_TYPE key_allowed_mech = { CKM_AES_CBC };

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &secret_class, sizeof(secret_class) },
           { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
           { CKA_VALUE_LEN, &key_len, sizeof(key_len) },
           { CKA_ALLOWED_MECHANISMS, &key_allowed_mech, sizeof(key_allowed_mech) },
           { CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }
       };

       rv = p11_func->C_DeriveKey(session, &mechanism, master_secret,
                                 template, 5, NULL);
       if (rv != CKR_OK) {
           printf("C_DeriveKey (Key Material) failed: 0x%lx\n", rv);
           return -1;
       }

       /* Extract derived keys and IVs */
       *client_mac_key = key_material.hClientMacSecret;
       *server_mac_key = key_material.hServerMacSecret;
       *client_enc_key = key_material.hClientKey;
       *server_enc_key = key_material.hServerKey;

       return 0;
   }

   /* Complete TLS 1.2 key derivation workflow */
   int tls12_derive_keys_pkcs11(...)
   {
       int ret = 0;
       CK_RV rv;
       CK_SESSION_HANDLE session;
       CK_SLOT_ID slot_id = 0;
       CK_OBJECT_HANDLE priv_key, pub_key;
       CK_OBJECT_HANDLE premaster_secret, master_secret;
       CK_OBJECT_HANDLE client_mac_key, server_mac_key;
       CK_OBJECT_HANDLE client_enc_key, server_enc_key;
       CK_BYTE client_iv[12], server_iv[12];

       /*
        * Pre-master key id, client_random, server_random, peer_key,
        * peer_key_size are expected to be provided whe calling this function.
        */

       /* Step 1: Derive pre-master secret using ECDH */
       if (derive_premaster_secret(session, priv_key, peer_public_key,
                                   sizeof(peer_public_key),
                                   &premaster_secret) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 2: Derive master secret */
       if (derive_master_secret(session, premaster_secret,
                               client_random, server_random,
                               &master_secret) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 3: Derive key material */
       if (derive_key_material(session, master_secret,
                              client_random, server_random,
                              &client_mac_key, &server_mac_key,
                              &client_enc_key, &server_enc_key,
                              sizeof(client_iv) * 8,
                              client_iv, server_iv) != 0) {
           ret = -1;
           goto cleanup;
       }

       printf("TLS 1.2 key derivation completed successfully!\n");
       printf("Client MAC key handle: %lu\n", client_mac_key);
       printf("Server MAC key handle: %lu\n", server_mac_key);
       printf("Client encryption key handle: %lu\n", client_enc_key);
       printf("Server encryption key handle: %lu\n", server_enc_key);

       /* Now you can use keys and ivs for encryption/decryption */
       /* ... */
   }


API Comparison
""""""""""""""

.. table:: TLS 1.2 Key Derivation APIs
   :name: table_tls12_kdf_apis
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+---------------------------------------------------------------+
   | **API** | **Functions** § **Algorithm**                                 |
   +=========+===============================================================+
   | SMW     | :c:func:`smw_derive_key`                                      |
   +         +                                                               +
   |         | SMW_KDF_NAME_TLS12_PRF                                        |
   +---------+---------------------------------------------------------------+
   | PSA     | :c:func:`psa_key_derivation_output_key` /                     |
   |         | :c:func:`psa_key_derivation_output_bytes`                     |
   +         +                                                               +
   |         | PSA_ALG_TLS12_PRF(hash_alg)                                   |
   +         +                                                               +
   |         | PSA_ALG_TLS12_PSK_TO_MS(hash_alg)                             |
   +---------+---------------------------------------------------------------+
   | PKCS11  | C_DeriveKey()                                                 |
   +         +                                                               +
   |         | CKM_ECDH1_DERIVE                                              |
   +         +                                                               +
   |         | CKM_TLS12_MASTER_KEY_DERIVE                                   |
   +         +                                                               +
   |         | CKM_TLS12_KEY_AND_MAC_DERIVE                                  |
   +         +                                                               +
   |         | CKM_TLS12_KEY_SAFE_DERIVE                                     |
   +---------+---------------------------------------------------------------+


References
""""""""""

- `RFC 5246 <https://www.rfc-editor.org/rfc/rfc5246>`_ - The Transport Layer Security (TLS) Protocol Version 1.2
- `RFC 5289 <https://www.rfc-editor.org/rfc/rfc5289>`_ - TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
- `RFC 7251 <https://www.rfc-editor.org/rfc/rfc7251>`_ - AES-CCM Elliptic Curve Cryptography (ECC) Cipher Suites for TLS
- `RFC 7905 <https://www.rfc-editor.org/rfc/rfc7905>`_ - ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)


TLS 1.3 (TLS13-KDF)
^^^^^^^^^^^^^^^^^^^
TLS 1.3 introduces a redesigned key derivation function based on HKDF (HMAC-based
Key Derivation Function) as defined in `RFC 8446 <https://www.rfc-editor.org/rfc/rfc8446>`_.
The TLS 1.3 key schedule provides improved security through a more structured
key derivation process and forward secrecy.

.. note::
   Only supported on i.MX91, i.MX93, i.MX943 and i.MX95

Key Schedule Overview
"""""""""""""""""""""
The TLS 1.3 key schedule derives multiple secrets in a hierarchical manner:

.. code-block:: none

                         0
                         |
                         v
               PSK ->  HKDF-Extract = Early Secret
                         |
                         +-----> Derive-Secret(., "ext binder" | "res binder", "")
                         |                     = binder_key
                         |
                         +-----> Derive-Secret(., "c e traffic", ClientHello)
                         |                     = client_early_traffic_secret
                         |
                         +-----> Derive-Secret(., "e exp master", ClientHello)
                         |                     = early_exporter_master_secret
                         v
                   Derive-Secret(., "derived", "")
                         |
                         v
               (EC)DHE -> HKDF-Extract = Handshake Secret
                         |
                         +-----> Derive-Secret(., "c hs traffic",
                         |                     ClientHello...ServerHello)
                         |                     = client_handshake_traffic_secret
                         |
                         +-----> Derive-Secret(., "s hs traffic",
                         |                     ClientHello...ServerHello)
                         |                     = server_handshake_traffic_secret
                         v
                   Derive-Secret(., "derived", "")
                         |
                         v
                  0 -> HKDF-Extract = Master Secret
                         |
                         +-----> Derive-Secret(., "c ap traffic",
                         |                     ClientHello...server Finished)
                         |                     = client_application_traffic_secret_0
                         |
                         +-----> Derive-Secret(., "s ap traffic",
                         |                     ClientHello...server Finished)
                         |                     = server_application_traffic_secret_0
                         |
                         +-----> Derive-Secret(., "exp master",
                         |                     ClientHello...server Finished)
                         |                     = exporter_master_secret
                         |
                         +-----> Derive-Secret(., "res master",
                                               ClientHello...client Finished)
                                               = resumption_master_secret

Internal Secret Management
""""""""""""""""""""""""""
The following secrets are computed internally by the subsystem and are
**not exported**:

- Early secret
- ECDH shared secret
- Handshake secret
- Master secret

This design ensures that sensitive key material never leaves the secure
subsystem, providing enhanced security.

Supported Key Types
"""""""""""""""""""
The subsystem supports the following elliptic curve key types for TLS 1.3:

.. table:: TLS 1.3 Supported Key Types
   :name: tls13_key_types
   :align: center
   :widths: 20 30 50
   :width: 100%
   :class: wrap-table

   +------------------+---------------------------+----------------------------------+
   | **Key Type**     | **Security size (bits)**  | **Notes**                        |
   +==================+===========================+==================================+
   | SECP_R1          | 256 / 384 / 521           | NIST P-256, P-384, P-521 curves  |
   +------------------+---------------------------+----------------------------------+
   | X25519           | 255                       | Curve25519 for ECDH              |
   +------------------+---------------------------+----------------------------------+
   | X448             | 448                       | Curve448 for ECDH                |
   +------------------+---------------------------+----------------------------------+

Derivable Secrets
"""""""""""""""""
The subsystem supports derivation of the following TLS 1.3 secrets:

.. table:: TLS 1.3 Secrets
   :name: tls13_secrets
   :align: center
   :widths: 35 30 35
   :width: 100%
   :class: wrap-table

   +-------------------------------------+------------------------------------+----------------------------------+
   | **TLS 1.3 Secret Name**             | **Label (without null term)**      | **Usage**                        |
   +=====================================+====================================+==================================+
   | Binder key                          | "ext binder" or "res binder"       | PSK binder computation           |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Client early traffic secret         | "c e traffic"                      | 0-RTT data encryption (client)   |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Early exporter master secret        | "e exp master"                     | Early data exporters             |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Client handshake traffic secret     | "c hs traffic"                     | Handshake encryption (client)    |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Server handshake traffic secret     | "s hs traffic"                     | Handshake encryption (server)    |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Client application traffic secret 0 | "c ap traffic"                     | Application data (client)        |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Server application traffic secret 0 | "s ap traffic"                     | Application data (server)        |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Exporter master secret              | "exp master"                       | Exporters for external protocols |
   +-------------------------------------+------------------------------------+----------------------------------+
   | Resumption master secret            | "res master"                       | Session resumption PSK           |
   +-------------------------------------+------------------------------------+----------------------------------+

Key and IV Derivation
"""""""""""""""""""""
After deriving the required traffic secret, the TLS 1.3 API can be used to
further derive encryption keys and IVs as specified in
`RFC 8446 <https://www.rfc-editor.org/rfc/rfc8446>`_:


.. code-block:: none

   [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
   [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)

Where:

- **Secret**: The traffic secret (e.g., client_handshake_traffic_secret)
- **key_length**: Length of the encryption key (depends on cipher suite)
- **iv_length**: Length of the IV (typically 12 bytes for AEAD ciphers)

Key Attributes for Derived Keys
"""""""""""""""""""""""""""""""
When deriving keys from traffic secrets, the derived keys must have appropriate
attributes set based on their intended use:

**Example 1: Deriving AES-128-GCM key from server handshake traffic secret**

- **Key type**: AES
- **Security size**: 128 bits
- **Algorithm**: AES-GCM
- **Usage**: Encrypt and/or Decrypt

**Example 2: Deriving HMAC-256 key for Finished message**

- **Key type**: HMAC
- **Security size**: 256 bits
- **Algorithm**: HMAC-SHA256
- **Usage**: Sign and/or Verify

.. important::
   All derived keys need to have the proper attributes (type, size, algorithm,
   and usage) set before performing the derivation operation.

Supported Cipher Suites
"""""""""""""""""""""""
TLS 1.3 supports the following cipher suites:

.. table:: TLS 1.3 Cipher Suites
   :name: tls13_ciphersuites
   :align: center
   :widths: 40 30 30
   :width: 100%
   :class: wrap-table

   +-------------------------------+------------------+------------------+
   | **Cipher Suite**              | **AEAD**         | **Hash**         |
   +===============================+==================+==================+
   | TLS_AES_128_GCM_SHA256        | AES-128-GCM      | SHA-256          |
   +-------------------------------+------------------+------------------+
   | TLS_AES_256_GCM_SHA384        | AES-256-GCM      | SHA-384          |
   +-------------------------------+------------------+------------------+
   | TLS_CHACHA20_POLY1305_SHA256  | ChaCha20-Poly1305| SHA-256          |
   +-------------------------------+------------------+------------------+
   | TLS_AES_128_CCM_SHA256        | AES-128-CCM      | SHA-256          |
   +-------------------------------+------------------+------------------+

Subsystem Support
"""""""""""""""""

.. table:: TLS 1.3 Subsystem Support
   :name: tls13_subsystem_support
   :align: center
   :width: 100%
   :class: wrap-table

   +---------------+-------------+------------------------------------------+
   | **Subsystem** | **Support** | **Notes**                                |
   +===============+=============+==========================================+
   | ELE           | Yes         | i.MX91, i.MX93, i.MX943, i.MX95 only     |
   +---------------+-------------+------------------------------------------+
   | TEE           | No          | Not supported                            |
   +---------------+-------------+------------------------------------------+
   | SECO          | No          | Not supported                            |
   +---------------+-------------+------------------------------------------+

Usage Example with SMW API
""""""""""""""""""""""""""
Here's a basic example of using TLS 1.3 key derivation with SMW API to
use a TLS_AES_128_GCM_SHA256 cipher suite.

.. code-block:: c
   :linenos:

   #include <smw_keymgr.h>
   #include <smw_crypto.h>
   #include <string.h>

   /* Step 1: Derive handshake traffic secret */
   int derive_handshake_secret(unsigned int ecdh_key_id,
                               unsigned char *label,
                               unsigned char transcript_hash[32],
                               unsigned char *peer_key,
                               unsigned int peer_key_len,
                               unsigned int *secret_id)
   {
       int res = 0;
       enum smw_status_code status;
       struct smw_derive_key_args args = { 0 };
       struct smw_key_descriptor base_key = { 0 };
       struct smw_derived_key_descriptor derived_key = { 0 };
       struct smw_tls13_kdf_args tls13_args = { 0 };
       struct smw_tls13_expand_label_args exp_args = { 0 };

       /* Configure TLS 1.3 KDF arguments */
       args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
       args.key_descriptor_base = &base_key;
       args.key_descriptor_derived = &derived_key;
       args.kdf_name = SMW_KDF_NAME_TLS13_KEY_EXCHANGE;
       args.kdf_arguments = &tls13_args;
       args.store_derived_key = false;

       /* Base key is the ECDH shared secret (managed internally) */
       base_key.id = ecdh_key_id;

       exp_args.length = 32; /* SHA-256 output length */
       exp_args.label = label;
       exp_args.label_length = strlen(label);
       exp_args.context = transcript_hash;
       exp_args.context_length = sizeof(transcript_hash);

       tls13_args->expanded_label_length = SMW_TLS13_EXPANDED_LABEL_LENGTH(&exp_args);
       tls13_args->expanded_label = malloc(tls_args->expanded_label_length);
       if (!tls13_args->expanded_label)
           return -1;

       exp_args.expanded_label_length = tls13_args->expanded_label_length;
       exp_args.expanded_label = tls13_args->expanded_label;

       res = smw_tls13_expand_label(&exp_args);
       if (res != SMW_STATUS_OK) {
           res = -1;
           goto end;
       }

       /* Configure TLS 1.3 specific parameters */
       tls13_args.prf_name = SMW_HASH_ALGO_NAME_SHA256;
       tls13_args.peer_public_buffer = peer_key;
       tls13_args.peer_public_buffer_length = peer_key_length;

       /* Derive server handshake traffic secret */
       status = smw_derive_key(&args);
       if (status != SMW_STATUS_OK)
           res = -1;
       else
           *secret_id = derived_key.id;

   end:
       free(tls13_args->expanded_label);

       return res;
   }

   /* Step 2: Derive AES-128-GCM key from traffic secret */
   int derive_aes_key_from_traffic_secret(unsigned int traffic_secret_id,
                                          unsigned int *aes_key_id)
   {
       int res = 0;
       enum smw_status_code status;
       struct smw_derive_key_args args = { 0 };
       struct smw_key_descriptor base_key = { 0 };
       struct smw_derived_key_descriptor derived_key = { 0 };
       struct smw_tls13_kdf_args tls13_args = { 0 };
       struct smw_tls13_expand_label_args exp_args = { 0 };

       /* Configure derivation arguments */
       args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
       args.key_descriptor_base = &base_key;
       args.key_descriptor_derived = &derived_key;
       args.kdf_name = SMW_KDF_NAME_TLS13_EXPAND_LABEL;
       args.kdf_arguments = &tls13_args;
       args.store_derived_key = false;

       /* Base key is the traffic secret */
       base_key.id = traffic_secret_id;

       /* Configure HKDF-Expand-Label parameters */
       exp_args.label = "key";
       exp_args.label_length = strlen(exp_args.label);
       exp_args.context = NULL;
       exp_args.context_length = 0;

       tls13_args->expanded_label_length = SMW_TLS13_EXPANDED_LABEL_LENGTH(&exp_args);
       tls13_args->expanded_label = malloc(tls_args->expanded_label_length);
       if (!tls13_args->expanded_label)
           return -1;

       exp_args.expanded_label_length = tls13_args->expanded_label_length;
       exp_args.expanded_label = tls13_args->expanded_label;

       res = smw_tls13_expand_label(&exp_args);
       if (res != SMW_STATUS_OK) {
           res = -1;
           goto end;
       }

       /* Configure derived AES key attributes */
       derived_key.type_name = SMW_KEY_TYPE_NAME_AES;
       derived_key.security_size = 128;
       derived_key.attributes.permitted_algo =
           SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(SMW_ATTR_ALGO_AES,
                                             SMW_ATTR_MODE_GCM);
       derived_key.attributes.usage_flags =
           SMW_ATTR_USAGE_ENCRYPT | SMW_ATTR_USAGE_DECRYPT;
       derived_key.attributes.attributes =
           SMW_ATTR_SET_PERSISTENCE(derived_key.attributes.attributes,
                                   SMW_ATTR_PERSISTENCE_TRANSIENT);

       /* Configure TLS 1.3 specific parameters */
       tls13_args.prf_name = SMW_HASH_ALGO_NAME_SHA256;

       /* Derive AES key */
       status = smw_derive_key(&args);
       if (status != SMW_STATUS_OK)
           res = -1;
       else
           *aes_key_id = derived_key.id;

   end:
       free(tls13_args->expanded_label);

       return res;
   }

   /* Step 3: Derive IV from traffic secret */
   int derive_iv_from_traffic_secret(unsigned int traffic_secret_id,
                                     unsigned char *iv, size_t iv_len)
   {
       int res = 0;
       enum smw_status_code status;
       struct smw_derive_key_args args = { 0 };
       struct smw_key_descriptor base_key = { 0 };
       struct smw_derived_key_descriptor derived_key = { 0 };
       struct smw_tls13_kdf_args tls13_args = { 0 };
       struct smw_tls13_expand_label_args exp_args = { 0 };

       /* Configure derivation arguments */
       args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
       args.key_descriptor_base = &base_key;
       args.key_descriptor_derived = &derived_key;
       args.kdf_name = SMW_KDF_NAME_TLS13_EXPAND_LABEL;
       args.kdf_arguments = &tls13_args;
       args.store_derived_key = false; /* Output to buffer */

       /* Base key is the traffic secret */
       base_key.id = traffic_secret_id;

       /* Configure HKDF-Expand-Label parameters */
       exp_args.label = "iv";
       exp_args.label_length = strlen(exp_args.label);
       exp_args.context = NULL;
       exp_args.context_length = 0;

       tls13_args->expanded_label_length = SMW_TLS13_EXPANDED_LABEL_LENGTH(&exp_args);
       tls13_args->expanded_label = malloc(tls_args->expanded_label_length);
       if (!tls13_args->expanded_label)
           return -1;

       exp_args.expanded_label_length = tls13_args->expanded_label_length;
       exp_args.expanded_label = tls13_args->expanded_label;

       res = smw_tls13_expand_label(&exp_args);
       if (res != SMW_STATUS_OK) {
           res = -1;
           goto end;
       }

       /* Configure derived key result as shared buffer */
       derived_key.shared_secret = iv;
       derived_key.shared_secret_len = iv_len;

       /* Configure TLS 1.3 specific parameters */
       tls13_args.prf_name = SMW_HASH_ALGO_NAME_SHA256;

       /* Derive IV */
       status = smw_derive_key(&args);
       if (status != SMW_STATUS_OK)
           res = -1;

   end:
       free(tls13_args->expanded_label);
       return res;
   }

   /* Complete workflow example */
   int tls13_derive_encryption_keys(...)
   {
       int ret;
       unsigned int hs_secret_id;
       unsigned int aes_key_id;
       unsigned char iv[12]; /* Standard IV length for AEAD */
       unsigned char transcript_hash[32]; /* SHA-256 hash */

       /* Compute transcript hash: Hash(ClientHello...ServerHello) */
       /* ... */

       /* Peer key and ecdh_key_id obtained from key exchange */

       /* Step 1: Derive client handshake traffic secret */
       ret = derive_handshake_secret(ecdh_key_id, "c hs traffic",
                                     peer_key, peer_key_len,
                                     transcript_hash, &hs_secret_id);
       if (ret != 0)
           return -1;

       /* Step 2: Derive AES-128-GCM encryption key */
       ret = derive_aes_key_from_traffic_secret(hs_secret_id, &aes_key_id);
       if (ret != 0)
           return -1;

       /* Step 3: Derive IV */
       ret = derive_iv_from_traffic_secret(hs_secret_id, iv, sizeof(iv));
       if (ret != 0)
           return -1;

       /* Now you can use keys and ivs for encryption/decryption */
       /* ... */
   }

Usage Example with PSA API
""""""""""""""""""""""""""
Here's a basic example of doing TLS 1.3 key derivation with PSA API to
use a TLS_AES_128_GCM_SHA256 cipher suite.

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <stdlib.h>
   #include "psa/crypto.h"


   /* Step 1: Derive client handshake traffic secret */
   static int derive_handshake_traffic_secret(psa_key_id_t ecdh_key_id,
                                              const char *label,
                                              const uint8_t *peer_public_key,
                                              size_t peer_public_key_length,
                                              const uint8_t *transcript_hash,
                                              psa_key_id_t *hs_traffic_id)
   {
       psa_status_t status;
       psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
       psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
       uint8_t info[256] = {0};
       size_t info_len;
       uint16_t length_be;
       size_t label_len = strlen(label);

       /* Build HKDF-Expand-Label info structure:
        * struct {
        *     uint16 length = 32 (SHA-256 output length);
        *     opaque label<7..255> = "tls13 " + Label;
        *     opaque context<0..255> = transcript_hash;
        * } HkdfLabel;
        */
       size_t pos = 0;

       /* Length (2 bytes, big-endian) */
       length_be = 32; /* SHA-256 output length */
       info[pos++] = (length_be >> 8) & 0xFF;
       info[pos++] = length_be & 0xFF;

       /* Label length (1 byte) */
       info[pos++] = 6 + label_len; /* "tls13 " + label */

       /* Label ("tls13 " + label) */
       memcpy(&info[pos], "tls13 ", 6);
       pos += 6;
       memcpy(&info[pos], label, label_len);
       pos += label_len;

       /* Context length (1 byte) */
       info[pos++] = 32; /* SHA-256 hash length */

       /* Context (transcript hash) */
       memcpy(&info[pos], transcript_hash, 32);
       pos += 32;

       info_len = pos;

       /* Setup key derivation operation for TLS 1.3 PRF */
       status = psa_key_derivation_setup(&operation,
                                         PSA_ALG_VENDOR_TLS13(PSA_ALG_SHA_256));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_setup failed: %d\n", status);
           return -1;
       }

       /* Set the input secret for the pre-master key internal generation */
       status = psa_key_derivation_key_agreement(&operation,
                                             PSA_KEY_DERIVATION_INPUT_SECRET,
                                             ecdh_key_id,
                                             peer_public_key,
                                             peer_public_key_length);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_key_agreement failed: %d\n", status);
           goto cleanup;
       }

       /* Set the seed (label + client_random + server_random) */
       status = psa_key_derivation_input_bytes(&operation,
                                               PSA_KEY_DERIVATION_INPUT_INFO,
                                               info, sizeof(info));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_bytes (info) failed: %d\n", status);
           goto cleanup;
       }


       /* Output master secret key id for further derivation */
       psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
       psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);

       /* Output handshake traffic key id */
       status = psa_key_derivation_output_key(&attributes, &operation, hs_traffic_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_key failed: %d\n", status);
           goto cleanup;
       }

       printf("Derived HS traffic with ID: %u\n", *hs_traffic_id);

   cleanup:
       if (seed)
           free(seed);

       psa_key_derivation_abort(&operation);
       return (status == PSA_SUCCESS) ? 0 : -1;
   }

   /* Step 2: Derive AES-128-GCM encryption key */
   static int derive_aes_key_from_traffic_secret(psa_key_id_t traffic_secret_id,
                                                 psa_key_id_t *aes_key_id)
   {
       psa_status_t status;
       psa_key_derivation_operation_t operation =
           PSA_KEY_DERIVATION_OPERATION_INIT;
       psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
       uint8_t info[256] = {0};
       size_t info_len;
       uint16_t length_be;
       const char *label = "key";
       size_t label_len = strlen(label);

       /* Build HKDF-Expand-Label info for "key" derivation */
       size_t pos = 0;

       /* Length (2 bytes, big-endian) - 16 bytes for AES-128 */
       length_be = 16;
       info[pos++] = (length_be >> 8) & 0xFF;
       info[pos++] = length_be & 0xFF;

       /* Label length */
       info[pos++] = 6 + label_len;

       /* Label */
       memcpy(&info[pos], "tls13 ", 6);
       pos += 6;
       memcpy(&info[pos], label, label_len);
       pos += label_len;

       /* Context length (empty context) */
       info[pos++] = 0;

       info_len = pos;

       /* Setup HKDF derivation */
       status = psa_key_derivation_setup(&operation,
                                         PSA_ALG_VENDOR_TLS13(PSA_ALG_SHA_256));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_setup failed: %d\n", status);
           return -1;
       }

       /* Input the traffic secret */
       status = psa_key_derivation_input_key(&operation,
                                             PSA_KEY_DERIVATION_INPUT_SECRET,
                                             traffic_secret_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_key failed: %d\n", status);
           goto cleanup;
       }

       /* Input the info */
       status = psa_key_derivation_input_bytes(&operation,
                                               PSA_KEY_DERIVATION_INPUT_INFO,
                                               info, info_len);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_bytes failed: %d\n", status);
           goto cleanup;
       }

       /* Configure AES-128-GCM key attributes */
       psa_set_key_usage_flags(&attributes,
                              PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
       psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
       psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
       psa_set_key_bits(&attributes, 128);
       psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

       /* Derive the AES key */
       status = psa_key_derivation_output_key(&attributes, &operation, aes_key_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_key (AES) failed: %d\n", status);
           goto cleanup;
       }

       printf("Derived AES-128-GCM encryption key with ID: %u\n", *aes_key_id);

   cleanup:
       psa_reset_key_attributes(&attributes);
       psa_key_derivation_abort(&operation);
       return (status == PSA_SUCCESS) ? 0 : -1;
   }

   /* Step 3: Derive IV from traffic secret */
   static int derive_iv_from_traffic_secret(psa_key_id_t traffic_secret_id,
                                            uint8_t *iv, size_t iv_len)
   {
       psa_status_t status;
       psa_key_derivation_operation_t operation =
           PSA_KEY_DERIVATION_OPERATION_INIT;
       uint8_t info[256] = {0};
       size_t info_len;
       uint16_t length_be;
       const char *label = "iv";
       size_t label_len = strlen(label);

       /* Build HKDF-Expand-Label info for "iv" derivation */
       size_t pos = 0;

       /* Length (2 bytes, big-endian) - 12 bytes for GCM IV */
       length_be = iv_len;
       info[pos++] = (length_be >> 8) & 0xFF;
       info[pos++] = length_be & 0xFF;

       /* Label length */
       info[pos++] = 6 + label_len;

       /* Label */
       memcpy(&info[pos], "tls13 ", 6);
       pos += 6;
       memcpy(&info[pos], label, label_len);
       pos += label_len;

       /* Context length (empty context) */
       info[pos++] = 0;

       info_len = pos;

       /* Setup HKDF derivation */
       status = psa_key_derivation_setup(&operation,
                                         PSA_ALG_VENDOR_TLS13(PSA_ALG_SHA_256));
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_setup failed: %d\n", status);
           return -1;
       }

       /* Input the traffic secret */
       status = psa_key_derivation_input_key(&operation,
                                             PSA_KEY_DERIVATION_INPUT_SECRET,
                                             traffic_secret_id);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_key failed: %d\n", status);
           goto cleanup;
       }

       /* Input the info */
       status = psa_key_derivation_input_bytes(&operation,
                                               PSA_KEY_DERIVATION_INPUT_INFO,
                                               info, info_len);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_input_bytes failed: %d\n", status);
           goto cleanup;
       }

       /* Derive the IV bytes */
       status = psa_key_derivation_output_bytes(&operation, iv, iv_len);
       if (status != PSA_SUCCESS) {
           printf("psa_key_derivation_output_bytes (IV) failed: %d\n", status);
           goto cleanup;
       }

       print_hex("Derived IV", iv, iv_len);

   cleanup:
       psa_key_derivation_abort(&operation);
       return (status == PSA_SUCCESS) ? 0 : -1;
   }

   /* Complete TLS 1.3 key derivation workflow */
   int tls13_derive_keys_psa(...)
   {
       psa_key_id_t hs_traffic_id = 0;
       psa_key_id_t aes_key_id = 0;
       uint8_t client_iv[12] = {0}; /* Full IV for GCM */
       unsigned char transcript_hash[32]; /* SHA-256 hash */
       int ret = 0;

       /* Compute transcript hash: Hash(ClientHello...ServerHello) */
       /* ... */

       /* Peer key and ecdh_key_id obtained from key exchange */

       printf("\n=== TLS 1.3 Key Derivation with PSA API ===\n\n");

       /* Step 1: Derive client handshake traffic secret */
       ret = derive_handshake_secret(ecdh_key_id, "c hs traffic",
                                     peer_key, peer_key_len,
                                     transcript_hash, &hs_secret_id);
       if (ret != 0)
           return -1;

       /* Step 2: Derive AES-128-GCM encryption key */
       ret = derive_aes_key_from_traffic_secret(hs_secret_id, &aes_key_id);
       if (ret != 0)
           return -1;

       /* Step 3: Derive IV */
       ret = derive_iv_from_traffic_secret(hs_secret_id, iv, sizeof(iv));
       if (ret != 0)
           return -1;

       printf("\n=== TLS 1.3 key derivation completed successfully! ===\n");

       /* Now you can use keys and ivs for encryption/decryption */
       /* ... */

   }

Usage Example with PKCS11 API
"""""""""""""""""""""""""""""
Here's a basic example of using TLS 1.3 key derivation with PKCS11 API to
use a TLS_AES_128_GCM_SHA256 cipher suite.

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <stdlib.h>
   #include "pkcs11.h"

   /* Helper: Build HKDF-Expand-Label info structure for TLS 1.3 */
   static CK_ULONG build_hkdf_label(CK_BYTE *output,
                                    CK_ULONG length,
                                    const char *label,
                                    const CK_BYTE *context,
                                    CK_ULONG context_len)
   {
       CK_ULONG pos = 0;
       CK_ULONG label_len = strlen(label);

       /* Length (2 bytes, big-endian) */
       output[pos++] = (length >> 8) & 0xFF;
       output[pos++] = length & 0xFF;

       /* Label length (1 byte) - "tls13 " + label */
       output[pos++] = 6 + label_len;

       /* Label - "tls13 " prefix */
       memcpy(&output[pos], "tls13 ", 6);
       pos += 6;

       /* Label - actual label */
       memcpy(&output[pos], label, label_len);
       pos += label_len;

       /* Context length (1 byte) */
       output[pos++] = context_len;

       /* Context data */
       if (context_len > 0) {
           memcpy(&output[pos], context, context_len);
           pos += context_len;
       }

       return pos;
   }


   /* Step 1: Perform ECDH to derive pre-master secret */
   static int derive_ecdh_secret(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE priv_key,
                                 CK_BYTE *peer_public_key,
                                 CK_ULONG peer_key_len,
                                 CK_OBJECT_HANDLE *shared_secret)
   {
       CK_RV rv;
       CK_ECDH1_DERIVE_PARAMS ecdh_params = {
           .kdf = CKD_NULL,
           .pSharedData = NULL,
           .ulSharedDataLen = 0,
           .pPublicData = peer_public_key,
           .ulPublicDataLen = peer_key_len
       };

       CK_MECHANISM mechanism = {
           .mechanism = CKM_ECDH1_DERIVE,
           .pParameter = &ecdh_params,
           .ulParameterLen = sizeof(ecdh_params)
       };

       /* Template for derived pre-master secret */
       CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
       CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
       CK_ULONG key_len = 32; /* 256 bits for SECP256R1 */
       CK_MECHANISM_TYPE key_allowed_mech = { CKM_HKDF_DERIVE };
       CK_BBOOL true_val = CK_TRUE;
       CK_BBOOL false_val = CK_TRUE;

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &secret_class, sizeof(secret_class) },
           { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
           { CKA_VALUE_LEN, &key_len, sizeof(key_len) },
           { CKA_ALLOWED_MECHANISMS, &key_allowed_mech, sizeof(key_allowed_mech) },
           { CKA_DERIVE, &true_val, sizeof(CK_BBOOL) },
           { CKA_EXTRACTABLE, &false_val, sizeof(CK_BBOOL) }
       };

       rv = p11_func->C_DeriveKey(session, &mechanism, priv_key,
                                  template, 6, shared_secret);
       if (rv != CKR_OK) {
           printf("C_DeriveKey (ECDH) failed: 0x%lx\n", rv);
           return -1;
       }

       return 0;
   }

   /* Step 2: Derive handshake traffic secret */
   static int derive_handshake_traffic_secret(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE shared_secret,
                                  const CK_BYTE *transcript_hash,
                                  const char *labal,
                                  CK_OBJECT_HANDLE *traffic_secret)
   {
       CK_RV rv;
       CK_BYTE info[256];
       CK_ULONG info_len;

       /* HKDF parameters for TLS 1.3 */
       CK_HKDF_PARAMS hkdf_params = {
           .bExtract = CK_FALSE,  /* We're doing expand only */
           .bExpand = CK_TRUE,
           .prfHashMechanism = CKM_SHA256,
           .ulSaltType = CKF_HKDF_SALT_NULL,
           .pSalt = NULL,
           .ulSaltLen = 0,
           .pInfo = info,
           .ulInfoLen = info_len
       };

       CK_MECHANISM mechanism = {
           .mechanism = CKM_HKDF_DERIVE,
           .pParameter = &hkdf_params,
           .ulParameterLen = sizeof(hkdf_params)
       };

       CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
       CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
       CK_ULONG key_len = 32; /* SHA-256 output length */
       CK_MECHANISM_TYPE key_allowed_mech = { CKM_HKDF_DERIVE };
       CK_BBOOL true_val = CK_TRUE;

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &secret_class, sizeof(secret_class) },
           { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
           { CKA_VALUE_LEN, &key_len, sizeof(key_len) },
           { CKA_DERIVE, &true_val, sizeof(CK_BBOOL) },
           { CKA_ALLOWED_MECHANISMS, &key_allowed_mech, sizeof(CK_MECHANISM_TYPE) },
       };

       /* Build HKDF-Expand-Label info structure */
       info_len = build_hkdf_label(info, 32, label, transcript_hash, 32);

       rv = p11_func->C_DeriveKey(session, &mechanism, shared_secret,
                                  template, 5, traffic_secret);
       if (rv != CKR_OK) {
           printf("C_DeriveKey (HKDF - %s) failed: 0x%lx\n", label, rv);
           return -1;
       }

       printf("Derived %s (handle: %lu)\n", label, *traffic_secret);
       return 0;

   }

   /* Step 3: Derive key encryption */
   static int derive_encryption_key(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE traffic_secret,
                                    CK_OBJECT_HANDLE *aes_key)
   {
       CK_RV rv;
       CK_BYTE info[256];
       CK_ULONG info_len;

       CK_HKDF_PARAMS hkdf_params = {
           .bExtract = CK_FALSE,
           .bExpand = CK_TRUE,
           .prfHashMechanism = CKM_SHA256,
           .ulSaltType = CKF_HKDF_SALT_NULL,
           .pSalt = NULL,
           .ulSaltLen = 0,
           .pInfo = info,
           .ulInfoLen = info_len
       };

       CK_MECHANISM mechanism = {
           .mechanism = CKM_HKDF_DERIVE,
           .pParameter = &hkdf_params,
           .ulParameterLen = sizeof(hkdf_params)
       };

       CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
       CK_KEY_TYPE key_type = CKK_AES;
       CK_ULONG key_len = 16; /* AES-128 */
       CK_BBOOL true_val = CK_TRUE;
       CK_MECHANISM_TYPE key_allowed_mech = { CKM_AES_GCM };

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &secret_class, sizeof(secret_class) },
           { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
           { CKA_VALUE_LEN, &key_len, sizeof(key_len) },
           { CKA_ENCRYPT, &true_val, sizeof(CK_BBOOL) },
           { CKA_DECRYPT, &true_val, sizeof(CK_BBOOL) },
           { CKA_ALLOWED_MECHANISMS, &key_allowed_mech, sizeof(CK_MECHANISM_TYPE) },
       };

       /* Build HKDF-Expand-Label info for "key" derivation */
       info_len = build_hkdf_label(info, 16, "key", NULL, 0);

       rv = p11_func->C_DeriveKey(session, &mechanism, traffic_secret,
                                  template, 6, aes_key);
       if (rv != CKR_OK) {
           printf("C_DeriveKey (AES key) failed: 0x%lx\n", rv);
           return -1;
       }

       printf("Derived AES-128-GCM encryption key (handle: %lu)\n", *aes_key);
       return 0;
   }

   /* Step 4: Derive IV from traffic secret */
   static int derive_iv(CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE traffic_secret,
                       CK_BYTE *iv,
                       CK_ULONG iv_len)
   {
       CK_RV rv;
       CK_BYTE info[256];
       CK_ULONG info_len;
       CK_OBJECT_HANDLE temp_key;

       CK_HKDF_PARAMS hkdf_params = {
           .bExtract = CK_FALSE,
           .bExpand = CK_TRUE,
           .prfHashMechanism = CKM_SHA256,
           .ulSaltType = CKF_HKDF_SALT_NULL,
           .pSalt = NULL,
           .ulSaltLen = 0,
           .pInfo = info,
           .ulInfoLen = info_len
       };

       CK_MECHANISM mechanism = {
           .mechanism = CKM_HKDF_DERIVE,
           .pParameter = &hkdf_params,
           .ulParameterLen = sizeof(hkdf_params)
       };

       CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
       CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
       CK_BBOOL true_val = CK_TRUE;
       CK_BBOOL false_val = CK_FALSE;

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &secret_class, sizeof(secret_class) },
           { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
           { CKA_VALUE_LEN, &iv_len, sizeof(iv_len) },
           { CKA_EXTRACTABLE, &true_val, sizeof(CK_BBOOL) },
           { CKA_TOKEN, &false_val, sizeof(CK_BBOOL) }
       };

       /* Build HKDF-Expand-Label info for "iv" derivation */
       info_len = build_hkdf_label(info, iv_len, "iv", NULL, 0);

       /* Derive IV as extractable generic secret */
       rv = p11_func->C_DeriveKey(session, &mechanism, traffic_secret,
                                  template, 5, &temp_key);
       if (rv != CKR_OK) {
           printf("C_DeriveKey (IV) failed: 0x%lx\n", rv);
           return -1;
       }

       /* Extract the IV value */
       CK_ATTRIBUTE extract_template[] = {
           { CKA_VALUE, iv, iv_len }
       };

       rv = p11_func->C_GetAttributeValue(session, temp_key,
                                          extract_template, 1);
       if (rv != CKR_OK) {
           printf("C_GetAttributeValue (IV) failed: 0x%lx\n", rv);
           p11_func->C_DestroyObject(session, temp_key);
           return -1;
       }

       /* Clean up temporary key */
       p11_func->C_DestroyObject(session, temp_key);

       return 0;
   }

   /* Complete TLS 1.3 key derivation workflow */
   int tls13_derive_keys_pkcs11(...)
   {
       CK_OBJECT_HANDLE ecdhe_key = CK_INVALID_HANDLE;
       CK_OBJECT_HANDLE client_hs_secret = CK_INVALID_HANDLE;
       CK_OBJECT_HANDLE server_hs_secret = CK_INVALID_HANDLE;
       CK_OBJECT_HANDLE client_aes_key = CK_INVALID_HANDLE;
       CK_OBJECT_HANDLE server_aes_key = CK_INVALID_HANDLE;
       CK_BYTE client_iv[12];
       CK_BYTE server_iv[12];
       int ret = 0;
       CK_RV rv;

       /* Compute transcript hash: Hash(ClientHello...ServerHello) */
       /* ... */

       /* Peer key and ecdsa_key_id obtained from key exchange */

       printf("\n=== TLS 1.3 Key Derivation for TLS_AES_128_GCM_SHA256 ===\n");

       /* Step 1: Derive ECDH shared secret */
       if (derive_ecdh_shared_secret(session, ecdsa_key_id, peer_public_key,
                                     sizeof(peer_public_key),
                                     &ecdhe_key) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 2: Derive client handshake traffic secret */
       if (derive_handshake_traffic_secret(session, ecdhe_key,
                                          transcript_hash,
                                          "c hs traffic",
                                          &client_hs_secret) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 3: Derive server handshake traffic secret */
       if (derive_handshake_traffic_secret(session, ecdhe_key,
                                          transcript_hash,
                                          "s hs traffic",
                                          &server_hs_secret) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 4: Derive client AES-128-GCM key */
       if (derive_encryption_key(session, client_hs_secret,
                                &client_aes_key) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 5: Derive server AES-128-GCM key */
       if (derive_encryption_key(session, server_hs_secret,
                                &server_aes_key) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 6: Derive client IV */
       if (derive_iv(session, client_hs_secret, client_iv,
                    sizeof(client_iv)) != 0) {
           ret = -1;
           goto cleanup;
       }

       /* Step 7: Derive server IV */
       if (derive_iv(session, server_hs_secret, server_iv,
                    sizeof(server_iv)) != 0) {
           ret = -1;
           goto cleanup;
       }

       printf("\n=== TLS 1.3 key derivation completed successfully! ===\n");
       printf("\nDerived keys summary:\n");
       printf("- ECDH shared secret handle: %lu\n", ecdhe_key);
       printf("- Client handshake traffic secret handle: %lu\n",
              client_hs_secret);
       printf("- Server handshake traffic secret handle: %lu\n",
              server_hs_secret);
       printf("- Client AES-128-GCM key handle: %lu\n", client_aes_key);
       printf("- Server AES-128-GCM key handle: %lu\n", server_aes_key);
       printf("\nThese keys can now be used for TLS 1.3 handshake encryption.\n");

       /* Now you can use keys and ivs for encryption/decryption */
       /* ... */

      }


Security Considerations
"""""""""""""""""""""""
TLS 1.3 provides several security improvements over TLS 1.2:

1. **Forward Secrecy**: All handshakes use ephemeral key exchange (ECDHE)
2. **Simplified Key Schedule**: Clearer separation of key derivation stages
3. **AEAD-only Ciphers**: All cipher suites use authenticated encryption
4. **Reduced Attack Surface**: Removed legacy features and weak algorithms
5. **0-RTT Support**: Optional early data with replay protection considerations

.. warning::
   When using 0-RTT (early data), be aware of replay attack risks. Only use
   0-RTT for idempotent operations or implement additional replay protection.

API Comparison
""""""""""""""

.. table:: TLS 1.3 Key Derivation APIs
   :name: table_tls13_kdf_apis
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+---------------------------------------------------------------+
   | **API** | **Functions** / **Algorithm**                                 |
   +=========+===============================================================+
   | SMW     | :c:func:`smw_derive_key`                                      |
   +         +                                                               +
   |         | SMW_KDF_NAME_TLS13                                            |
   +         +                                                               +
   |         | SMW_KDF_NAME_TLS13_EXPAND_LABEL                               |
   +---------+---------------------------------------------------------------+
   | PSA     | :c:func:`psa_key_derivation_output_key` /                     |
   |         | :c:func:`psa_key_derivation_output_bytes`                     |
   +         +                                                               +
   |         | PSA_ALG_VENDOR_TLS13(hash_alg)                                |
   +---------+---------------------------------------------------------------+
   | PKCS11  | C_DeriveKey()                                                 |
   +         +                                                               +
   |         | CKM_ECDH1_DERIVE                                              |
   +         +                                                               +
   |         | CKM_HKDF_DERIVE                                               |
   +---------+---------------------------------------------------------------+

References
""""""""""

- `RFC 8446 <https://www.rfc-editor.org/rfc/rfc8446>`_ - The Transport Layer Security (TLS) Protocol Version 1.3
- `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`_ - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- `RFC 7748 <https://www.rfc-editor.org/rfc/rfc7748>`_ - Elliptic Curves for Security (X25519 and X448)
- `RFC 8439 <https://www.rfc-editor.org/rfc/rfc8439>`_ - ChaCha20 and Poly1305 for IETF Protocols


Get key attributes
^^^^^^^^^^^^^^^^^^
The **get key attributes** operation is used to retrieve metadata about stored
key from the secure subsystem without retrieving the actual key material.

.. table:: Get key attributes APIs Comparison
   :name: table_get_key_attributes_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+-----------------------------------+
   | **API** | **Function**                      |
   +=========+===================================+
   | SMW     | :c:func:`smw_get_key_attributes`  |
   +---------+-----------------------------------+
   | PSA     | :c:func:`psa_get_key_attributes`  |
   +---------+-----------------------------------+
   | PKCS11  | C_GetAttributeValue()             |
   +---------+-----------------------------------+

The metadata available for the key are described in the
:ref:`objects_attributes_definition` chapter and are:

  - **Type**: Type of the key (e.g. RSA, ECC, AES, HMAC, etc.).
  - **Security size**: The security size of the data in bits.
  - **Permitted algorithm**: Algorithms that are allowed to be used with
    this key.
  - **Key usage**: Indicates the operations permitted on the key (e.g., sign,
    verify, encrypt, decrypt, derive, etc.).
  - **Persistence**: Indicates whether the key is persistent or volatile.
  - **Lifecycle**: Indicates the device lifecycle stage where the key is valid.
  - **Storage location**: Key storage location.

.. note::
   The key attributes are not all managed by the different secure subsystem
   like SECO, TEE. In this case, the SMW library will provide the key
   attributes stored in its database when data was created by SMW and if the
   key object is still referenced.

.. note::
   If the key is not referenced in the SMW database, each secure subsystem
   enabled in the SMW configuration is queried to retrieve the missing key
   attributes in the limit of information managed by the secure subsystem,
   some may not be retrieval.

Public Key Attestation
^^^^^^^^^^^^^^^^^^^^^^
The **public key attestation** operation provides cryptographic proof that a
asymmetric public key is owned by a secure subsystem. This operation produces a
signed attestation certificate that can be verified by a third party
to establish trust in the key's provenance and security properties.

.. table:: Key Attestation Subsystem Support
   :name: table_key_attestation_subsystem_support
   :align: center
   :widths: 20 15 65
   :width: 100%
   :class: wrap-table

   +---------------+-------------+-------------------------------------+
   | **Subsystem** | **Support** | **Attestation Certificate**         |
   +===============+=============+=====================================+
   | ELE           | Yes         | `Custom TLV certificate structure`_ |
   +---------------+-------------+-------------------------------------+
   | TEE           | No          | Not supported                       |
   +---------------+-------------+-------------------------------------+
   | SECO          | No          | Not supported                       |
   +---------------+-------------+-------------------------------------+


.. table:: Key Attestation APIs Comparison
   :name: table_key_attestation_apis_comparison
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +---------+-------------------------------+
   | **API** | **Function**                  |
   +=========+===============================+
   | SMW     | :c:func:`smw_key_attestation` |
   +---------+-------------------------------+
   | PSA     | :c:func:`psa_attest_key`      |
   +---------+-------------------------------+
   | PKCS11  | Not supported                 |
   +---------+-------------------------------+

Custom TLV Certificate Structure
""""""""""""""""""""""""""""""""
The following table describes the custom TLV (Tag-Length-Value) certificate
structure used for key attestation in the ELE subsystem:

.. table:: Custom TLV Key attestation certificate
   :name: key_attest_cert_custom_tlv
   :align: center
   :widths: 13 13 9 11 54
   :width: 100%
   :class: wrap-table

   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | **Field**                  | **Tag**  | **Length**  | **Description / Value**                                          |
   +                            +          +             +                                                                  +
   |                            |          | **(bytes)** |                                                                  |
   +============================+==========+=============+==================================================================+
   | Key ID                     | 0x41     | 4           | Identifier, in the subsystem, of the key attest.                 |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Key properties | Algorithm |   0x42   | 4           | ELE key permitted algorithm.                                     |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   |                | Usage     |   0x43   | 4           | ELE key usage flags.                                             |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   |                | Type      |   0x44   | 2           | ELE Type of key.                                                 |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   |                | Bits      |   0x45   | 4           | Key security size in bits.                                       |
   +                +-----------+----------+-------------+------------------------------------------------------------------+
   |                | Lifetime  |   0x46   | 4           | ELE Lifetime:\                                                   |
   |                |           |          |             |                                                                  |
   |                |           |          |             |  - Key generated by the device:\                                 |
   |                |           |          |             |                                                                  |
   |                |           |          |             |    - 0x00000000: Transient key                                   |
   |                |           |          |             |    - 0x00000001: Persistent key                                  |
   |                |           |          |             |    - 0x000000FF: Permanent key                                   |
   |                |           |          |             |                                                                  |
   |                |           |          |             |  - Key imported with EdgeLock Enclave import:\                   |
   |                |           |          |             |                                                                  |
   |                |           |          |             |    - 0xC0020000: Transient key                                   |
   |                |           |          |             |    - 0xC0020001: Persistent key                                  |
   |                |           |          |             |    - 0xC00200FF: Permanent key                                   |
   |                |           |          |             |                                                                  |
   |                |           |          |             |  - Key imported with EdgeLock 2GO import:\                       |
   |                |           |          |             |                                                                  |
   |                |           |          |             |    - 0xE0000200: Transient key                                   |
   |                |           |          |             |    - 0xE0000201: Persistent key                                  |
   |                |           |          |             |    - 0xE00002FF: Permanent key                                   |
   |                |           |          |             |                                                                  |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Key lifecycle              | 0x47     | 4           | Key lifecycle usage flags:\                                      |
   |                            |          |             |                                                                  |
   |                            |          |             | - OEM OPEN: 0x01.                                                |
   |                            |          |             | - OEM CLOSED: 0x02.                                              |
   |                            |          |             | - OEM CLOSED_LOCKED: 0x04.                                       |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Attestation challenge      | 0x50     | Variable    | Input value chosen by the user, could be a random or the         |
   |                            |          |             | current data/time.                                               |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Key attestion ID           | 0x51     | 4           | Key identifier in the subsystem of the key used to attest the    |
   |                            |          |             | public key by signing this TLV.                                  |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Public key buffer          | 0x52     | Variable    | Public key buffer (big-endian).                                  |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Key origin                 | 0x53     | 1           | Information about the key origin:\                               |
   |                            |          |             |                                                                  |
   |                            |          |             | - 0x01: Key has been generated by the device.                    |
   |                            |          |             | - 0x02: Key has been imported into the device.                   |
   |                            |          |             | - 0x03: Key has been injected into the device.                   |
   |                            |          |             | - 0x04: Key has been imported with EdgeLock 2GO provisioning.    |
   |                            |          |             | - 0x05: Key has been derived.                                    |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Device UUID                | 0x54     | 16          | Device UUID (big-endian).                                        |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Signing algorithm          | 0x56     | 4           | Algorithm used to sign the blob itself. Field Signature of this  |
   |                            |          |             | blob:\                                                           |
   |                            |          |             |                                                                  |
   |                            |          |             | Possible values are:\                                            |
   |                            |          |             |                                                                  |
   |                            |          |             | - 0x01: CMAC.                                                    |
   |                            |          |             | - 0x02: ECDSA-NIST.                                              |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+
   | Signature                  |   0x5E   | 16          | Signature of all previous fields of this blob including the      |
   |                            |          |             | signature tag (0x5E) and signature length fields.                |
   +----------------+-----------+----------+-------------+------------------------------------------------------------------+


.. _psa_key_type_encoding:

Key type encoding
^^^^^^^^^^^^^^^^^

The key types are 16-bit encoded values. This chapter describes how this
bit field encoded value is structured and which key types are supported.

Typedef
"""""""
.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_key_type_t

The key type is a 16-bit encoded value that specifies the cryptographic key
type.

 - PSA_KEY_TYPE_NONE == 0
     Reserved as an invalid key type.

 - 0x0001 - 0x7fff
     Specification-defined key types. Key types defined by this standard
     always have bit 15 clear. Unallocated key type values in this range
     are reserved for future use.

 - 0x8000 - 0xffff
	No additional key type is defined.

.. table:: Key type bit field
   :name: table_psa_key_type_encoding
   :align: center
   :widths: 28 10 60
   :class: wrap-table

   +-------------------+-----------+-----------------------------------------------------+
   | **Field**         | **Bits**  | **Description**                                     |
   +===================+===========+=====================================================+
   | V                 | [15]      | Flag to indicate an vendor defined key type (V=1).  |
   +-------------------+-----------+-----------------------------------------------------+
   | A                 | [14]      | Flag to indicate an asymmmetric key type (A=1).     |
   +-------------------+-----------+-----------------------------------------------------+
   | CAT               | [13:12]   | Key type category. See `Key type categories`_.      |
   +-------------------+-----------+-----------------------------------------------------+
   | category-specific | [11:1]    | The meaning of this field is specific to each       |
   | type              |           | key type category.                                  |
   +-------------------+-----------+-----------------------------------------------------+
   | P                 | [0]       | Parity bit. Valid key type values have even parity. |
   +-------------------+-----------+-----------------------------------------------------+

Key type categories
"""""""""""""""""""
The key type is further categorized into the following categories:

.. table:: Key type categories
   :name: table_psa_key_type_categories
   :align: center
   :widths: 28 8 8 56
   :class: wrap-table

   +-----------------------+-------+---------+---------------------------------------------------------+
   | **Category**          | **A** | **CAT** | **Description**                                         |
   +=======================+=======+=========+=========================================================+
   | None                  | 0     | 0       | No key type. See PSA_KEY_TYPE_NONE (0x0000).            |
   +-----------------------+-------+---------+---------------------------------------------------------+
   | Raw data              | 0     | 1       | Unstructured raw data. See `Raw key encoding`_.         |
   +-----------------------+-------+---------+---------------------------------------------------------+
   | Symmetric             | 0     | 2       | Symmetric keys. See `Symmetric key encoding`_.          |
   +-----------------------+-------+---------+---------------------------------------------------------+
   | Asymmetric public key | 1     | 0       | Asymmetric public keys. See `Asymmetric key encoding`_. |
   +-----------------------+-------+---------+---------------------------------------------------------+
   | Asymmetric keypair    | 1     | 3       | Asymmetric keypairs.  See `Asymmetric key encoding`_.   |
   +-----------------------+-------+---------+---------------------------------------------------------+

Raw key encoding
~~~~~~~~~~~~~~~~
The raw key encoding category (CAT=1, A=0) is used for unstructured raw data
keys.
All PSA raw key type are not supported in this implementation.

.. table:: Raw key encoding
   :name: table_psa_raw_key_encoding
   :align: center
   :widths: 15 10 20
   :class: wrap-table

   +-------------------+----------+------------------------------------------+
   | **Field**         | **Bits** | **Details**                              |
   +===================+==========+==========================================+
   | V                 | [15]     | =0                                       |
   +-------------------+----------+------------------------------------------+
   | A                 | [14]     | =0                                       |
   +-------------------+----------+------------------------------------------+
   | CAT               | [13:12]  | =1                                       |
   +-------------------+----------+------------------------------------------+
   | RAW-TYPE          | [11:8]   | See the :numref:`table_psa_raw_key_types`|
   +-------------------+----------+                                          +
   | SUB-TYPE          | [7:1]    |                                          |
   +-------------------+----------+                                          +
   | P                 | [0]      |                                          |
   +-------------------+----------+------------------------------------------+

.. table:: Raw key types
   :name: table_psa_raw_key_types
   :widths: 16 12 11 5 32 10
   :width: 100%
   :class: wrap-table

   +-------------------+--------------+--------------+-------+----------------------------+-----------+
   | **Raw Key Type**  | **RAW-TYPE** | **SUB-TYPE** | **P** | **Name**                   | **Value** |
   +===================+==============+==============+=======+============================+===========+
   | Raw data          | 0            | 0            | 1     | PSA_KEY_TYPE_RAW_DATA      | 0x1001    |
   +-------------------+--------------+--------------+-------+----------------------------+-----------+
   | HMAC              | 1            | 0            | 0     | PSA_KEY_TYPE_HMAC          | 0x1100    |
   +-------------------+--------------+--------------+-------+----------------------------+-----------+
   | Derive secret     | 2            | 0            | 0     | PSA_KEY_TYPE_DERIVE        | 0x1200    |
   +-------------------+--------------+--------------+-------+----------------------------+-----------+
   | Password          | 2            | 1            | 1     | PSA_KEY_TYPE_PASSWORD      | 0x1203    |
   +-------------------+--------------+--------------+-------+----------------------------+-----------+
   | Password hash     | 2            | 2            | 1     | PSA_KEY_TYPE_PASSWORD_HASH | 0x1205    |
   +-------------------+--------------+--------------+-------+----------------------------+-----------+
   | Derivation Pepper | 2            | 3            | 0     | PSA_KEY_TYPE_PEPPER        | 0x1206    |
   +-------------------+--------------+--------------+-------+----------------------------+-----------+

Symmetric key encoding
~~~~~~~~~~~~~~~~~~~~~~
The symmetric key encoding category (CAT=2, A=0) is used for symmetric keys.
All PSA symmetric key type are not supported in this implementation.

.. table:: Symmetric key encoding
   :name: table_psa_sym_key_encoding
   :align: center
   :widths: 15 10 20
   :class: wrap-table

   +-------------------+----------+---------------------------------------------+
   | **Field**         | **Bits** | **Details**                                 |
   +===================+==========+=============================================+
   | V                 | [15]     | =0                                          |
   +-------------------+----------+---------------------------------------------+
   | A                 | [14]     | =0                                          |
   +-------------------+----------+---------------------------------------------+
   | CAT               | [13:12]  | =2                                          |
   +-------------------+----------+---------------------------------------------+
   | Not used          | [11]     | =0                                          |
   +-------------------+----------+---------------------------------------------+
   | BLK               | [10:8]   | Block size for the cipher algorithm (2^BLK).|
   +-------------------+----------+---------------------------------------------+
   | SYM-TYPE          | [7:1]    | See the :numref:`table_psa_sym_key_types`.  |
   +-------------------+----------+                                             +
   | P                 | [0]      |                                             |
   +-------------------+----------+---------------------------------------------+

.. table:: Symmetric key types
   :name: table_psa_sym_key_types
   :widths: 15 5 10 5 25 10
   :class: wrap-table

   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | **Symmetric Key Type**  | **BLK** | **SYM-TYPE** | **P** | **Name**                   | **Value** |
   +=========================+=========+==============+=======+============================+===========+
   | ARC4                    | 0       | 1            | 0     | PSA_KEY_TYPE_ARC4          | 0x2002    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | ChaCha20                | 0       | 2            | 0     | PSA_KEY_TYPE_CHACHA20      | 0x2004    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | XChaCha20               | 0       | 3            | 1     | PSA_KEY_TYPE_XCHACHA20     | 0x2007    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | DES                     | 3       | 0            | 1     | PSA_KEY_TYPE_DES           | 0x2301    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | AES                     | 4       | 0            | 0     | PSA_KEY_TYPE_AES           | 0x2400    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | Camellia                | 4       | 1            | 1     | PSA_KEY_TYPE_CAMELLIA      | 0x2403    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | SM4                     | 4       | 2            | 1     | PSA_KEY_TYPE_SM4           | 0x2405    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+
   | ARIA                    | 4       | 3            | 0     | PSA_KEY_TYPE_ARIA          | 0x2406    |
   +-------------------------+---------+--------------+-------+----------------------------+-----------+

Asymmetric key encoding
~~~~~~~~~~~~~~~~~~~~~~~
The asymmetric key encoding category (CAT=0 or CAT=3, A=1) is used for
asymmetric keys and keypairs.
All PSA asymmetric key types are not supported in this implementation.

.. table:: Asymmetric key encoding
   :name: table_psa_asym_key_encoding
   :align: center
   :widths: 15 10 20
   :class: wrap-table

   +-------------------+----------+-----------------------------------------------+
   | **Field**         | **Bits** | **Details**                                   |
   +===================+==========+===============================================+
   | V                 | [15]     | =0                                            |
   +-------------------+----------+-----------------------------------------------+
   | A                 | [14]     | =1                                            |
   +-------------------+----------+-----------------------------------------------+
   | PAIR              | [13:12]  | =0 for public, =3 for a keypair.              |
   +-------------------+----------+-----------------------------------------------+
   | ASYM-TYPE         | [11:7]   | See the :numref:`table_psa_asym_key_subtype`. |
   +-------------------+----------+-----------------------------------------------+
   | FAMILY            | [6:1]    | Depends on the ASYM-TYPE value. More details  |
   +-------------------+----------+                                               +
   | P                 | [0]      | for each asymmetric key sub-type.             |
   +-------------------+----------+-----------------------------------------------+

.. table:: Asymmetric key sub-type
   :name: table_psa_asym_key_subtype
   :align: center
   :widths: 25 15 40
   :class: wrap-table

   +--------------------------+---------------+---------------------------------------------------------------+
   | **Asymmetric Key Type**  | **ASYM-TYPE** | **Details**                                                   |
   +==========================+===============+===============================================================+
   | RSA                      | 0             | See the :ref:`RSA key family <psa_rsa_key_family>`.           |
   +--------------------------+---------------+---------------------------------------------------------------+
   | ECC                      | 2             | See the :ref:`ECC key family <psa_ecc_key_family>`.           |
   +--------------------------+---------------+---------------------------------------------------------------+
   | Diffie-Hellman           | 4             | See the :ref:`Diffie-Hellman key family <psa_dh_key_family>`. |
   +--------------------------+---------------+---------------------------------------------------------------+
   | SPAKE2+                  | 8             | See the :ref:`SPAKE2+ key family <psa_spake_key_family>`.     |
   +--------------------------+---------------+---------------------------------------------------------------+

.. _psa_rsa_key_family:

**RSA key family**

The RSA key type encoding uses ASYM-TYPE=0. The FAMILY and P fields are used
as follows:

.. table:: Asymmetric RSA key family
   :name: table_psa_rsa_key_family
   :align: center
   :widths: 20 10 10 5 25 10
   :class: wrap-table

   +----------------+----------+------------+-------+-----------------------------+-----------+
   | **Key family** | **PAIR** | **FAMILY** | **P** | **Name**                    | **Value** |
   +================+==========+============+=======+=============================+===========+
   | RSA Public key | 0        | 0          | 1     | PSA_KEY_TYPE_RSA_PUBLIC_KEY | 0x4001    |
   +----------------+----------+------------+-------+-----------------------------+-----------+
   | RSA Keypair    | 3        | 0          | 1     | PSA_KEY_TYPE_RSA_KEY_PAIR   | 0x7001    |
   +----------------+----------+------------+-------+-----------------------------+-----------+

.. _psa_ecc_key_family:

**Elliptic Curve key family**

The Elliptic Curve (ECC) key type encoding uses ASYM-TYPE=2. The FAMILY and P
fields are used as follows:

.. table:: Asymmetric Elliptic curve key family
   :name: table_psa_ecc_key_family
   :align: center
   :width: 100%
   :widths: 15 10 5 35 9 9
   :class: wrap-table

   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | **Key family**  | **FAMILY** | **P** | **Name**                       | **Value / Key**          |
   +                 +            +       +                                +------------+-------------+
   |                 |            |       |                                | **Public** | **Keypair** |
   +=================+============+=======+================================+============+=============+
   | SECP K1         | 0x0B       | 1     | PSA_ECC_FAMILY_SECP_K1         | 0x4117     | 0x7117      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | SECP R1         | 0x09       | 0     | PSA_ECC_FAMILY_SECP_R1         | 0x4112     | 0x7112      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | SECP R2         | 0x0D       | 1     | PSA_ECC_FAMILY_SECP_R2         | 0x411B     | 0x711B      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | SECT K1         | 0x13       | 1     | PSA_ECC_FAMILY_SECT_K1         | 0x4127     | 0x7127      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | SECT R1         | 0x11       | 0     | PSA_ECC_FAMILY_SECT_R1         | 0x4122     | 0x7122      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | SECT R2         | 0x15       | 1     | PSA_ECC_FAMILY_SECT_R2         | 0x412B     | 0x712B      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | BRAINPOOL-P R1  | 0x18       | 0     | PSA_ECC_FAMILY_BRAINPOOL_P_R1  | 0x4130     | 0x7130      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | FRP             | 0x19       | 1     | PSA_ECC_FAMILY_FRP             | 0x4133     | 0x7133      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | Montgomery      | 0x20       | 1     | PSA_ECC_FAMILY_MONTGOMERY      | 0x4141     | 0x7141      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | Twisted Edwards | 0x21       | 0     | PSA_ECC_FAMILY_TWISTED_EDWARDS | 0x4142     | 0x7142      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+

The asymmetric elliptic curve key type value is constructed from the
elliptic curve family using either PSA_KEY_TYPE_ECC_PUBLIC_KEY(family) or
PSA_KEY_TYPE_ECC_KEY_PAIR(family).

.. _psa_dh_key_family:

**Diffie-Hellman key family**

The Diffie-Hellman key type encoding uses ASYM-TYPE=4. The FAMILY and P fields
are used as follows:

.. table:: Asymmetric Diffie-Hellman key family
   :name: table_psa_dh_key_family
   :align: center
   :width: 100%
   :widths: 15 10 5 35 9 9
   :class: wrap-table

   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | **Key family**  | **FAMILY** | **P** | **Name**                       | **Value / Key**          |
   +                 +            +       +                                +------------+-------------+
   |                 |            |       |                                | **Public** | **Keypair** |
   +=================+============+=======+================================+============+=============+
   | RFC7919         | 0x01       | 1     | PSA_DH_FAMILY_RFC7919          | 0x4203     | 0x7203      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+

The asymmetric Diffie-Hellman key type value is constructed from the
Diffie-Hellman family using either PSA_KEY_TYPE_DH_PUBLIC_KEY(family) or
PSA_KEY_TYPE_DH_KEY_PAIR(family).

.. _psa_spake_key_family:

**SPAKE2+ key family**

The SPAKE2+ key type encoding uses ASYM-TYPE=8. The FAMILY and P fields are
used as follows:

.. table:: Asymmetric SPAKE2+ key family
   :name: table_psa_spake_key_family
   :align: center
   :width: 100%
   :widths: 15 10 5 35 9 9
   :class: wrap-table

   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | **Key family**  | **FAMILY** | **P** | **Name**                       | **Value / Key**          |
   +                 +            +       +                                +------------+-------------+
   |                 |            |       |                                | **Public** | **Keypair** |
   +=================+============+=======+================================+============+=============+
   | SECP R1         | 0x09       | 0     | PSA_ECC_FAMILY_SECP_R1         | 0x4412     | 0x7412      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+
   | Twisted Edwards | 0x21       | 0     | PSA_ECC_FAMILY_TWISTED_EDWARDS | 0x4442     | 0x7442      |
   +-----------------+------------+-------+--------------------------------+------------+-------------+

The asymmetric SPAKE2+ key type value is constructed from the elliptic curve
family using either PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(family) or
PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(family).

Functions and Macros
""""""""""""""""""""
Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_set_key_type psa_get_key_type

Key categories
~~~~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_IS_UNSTRUCTURED PSA_KEY_TYPE_IS_ASYMMETRIC
            PSA_KEY_TYPE_IS_PUBLIC_KEY PSA_KEY_TYPE_IS_KEY_PAIR

Symmetric Keys
~~~~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_RAW_DATA PSA_KEY_TYPE_HMAC PSA_KEY_TYPE_DERIVE
            PSA_KEY_TYPE_AES PSA_KEY_TYPE_DES PSA_KEY_TYPE_SM4

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_PASSWORD PSA_KEY_TYPE_PASSWORD_HASH
            PSA_KEY_TYPE_PEPPER PSA_KEY_TYPE_ARIA PSA_KEY_TYPE_CAMELLIA
            PSA_KEY_TYPE_CHACHA20 PSA_KEY_TYPE_XCHACHA20 PSA_KEY_TYPE_ARC4

None keys
~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_NONE


Asymmetric Keys
~~~~~~~~~~~~~~~
RSA Keys
########
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_IS_RSA

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_RSA_KEY_PAIR PSA_KEY_TYPE_RSA_PUBLIC_KEY

Elliptic Curve Keys
###################
.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_ecc_family_t

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_ECC_KEY_PAIR PSA_KEY_TYPE_ECC_PUBLIC_KEY
            PSA_KEY_TYPE_IS_ECC PSA_KEY_TYPE_IS_ECC_KEY_PAIR
            PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY PSA_KEY_TYPE_ECC_GET_FAMILY

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_ECC_FAMILY_SECP_K1 PSA_ECC_FAMILY_SECP_R1
            PSA_ECC_FAMILY_SECP_R2 PSA_ECC_FAMILY_SECT_K1
            PSA_ECC_FAMILY_SECT_R1 PSA_ECC_FAMILY_SECT_R2
            PSA_ECC_FAMILY_BRAINPOOL_P_R1 PSA_ECC_FAMILY_MONTGOMERY
            PSA_ECC_FAMILY_FRP PSA_ECC_FAMILY_TWISTED_EDWARDS

Diffie-Hellman Keys
###################
.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_dh_family_t

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_DH_KEY_PAIR PSA_KEY_TYPE_DH_PUBLIC_KEY
            PSA_KEY_TYPE_IS_DH
            PSA_KEY_TYPE_IS_DH_KEY_PAIR PSA_KEY_TYPE_IS_DH_PUBLIC_KEY
            PSA_KEY_TYPE_DH_GET_FAMILY

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_DH_FAMILY_RFC7919

SPAKE2+ Keys
############
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_SPAKE2P_KEY_PAIR PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY
            PSA_KEY_TYPE_IS_SPAKE2P PSA_KEY_TYPE_IS_SPAKE2P_KEY_PAIR
            PSA_KEY_TYPE_IS_SPAKE2P_PUBLIC_KEY PSA_KEY_TYPE_SPAKE2P_GET_FAMILY

Additional macros
#################
.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY
            PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR

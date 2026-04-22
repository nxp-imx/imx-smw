.. _subsystems-configuration:

Subsystems Configuration
------------------------

The SMW Library allows user to configure the Secure Subsystems and
their supported operations through a subsystem configuration file.
The configuration is a structured text format buffer that defines the mapping
between subsystems and their supported operations. This configuration is loaded
by the :c:func:`smw_config_load` function. This configuration part is detailed
in the following sections.

.. note::
  In the context of the SMW Library running on the Linux OS, the configuration
  is a text file loaded by the OSAL module and passed to the
  :c:func:`smw_config_load` function (see :ref:`OSAL <osal>` chapter).

The subsystem configuration definition must respect
`Syntactic rules`_ and writing structure to properly
define the capabilities and constraints of each operation across different
Secure Subsystems.

The subsystem configuration definition is divided in sections:

- `Global configuration`_: Defines the parser
  version and other settings.
- `Secure Subsystems definition`_: Defines
  each Secure Subsystem name and their loading/unloading method.
- `Security Operations definition`_: Defines
  for each Secure Subsystem the supported operations and their capabilities
  and constraints.

Syntactic rules
^^^^^^^^^^^^^^^

  - Characters must be encoded in ASCII.
  - Semicolon '**;**' specifies end of line.
  - Colon '**:**' is a separator of multiples entries.
  - Spaces and line separators are ignored.
  - Decimal numbers are written using the US/UK format (i.e. separator
    is '**.**').
  - Negative numbers are preceded by '**-**'.
  - Range value is defined using the format '**min:max**'.
  - Range value defined using the format '**min:**', means a range from min
    to maximum unsigned integer value.
  - Range value defined using the format '**val:val**', means a single value
    (min equals max).
  - String must not be quoted.
  - Commented sections start with '**/\***' and finish with '***/**'. Comments
    are ignored during parsing.


Global configuration
^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   VERSION=<integer: parser version must be 1>;
   PSA_DEFAULT=<string: subsystem name>[:ALT];
   [SECURE_SUBSYSTEM]
       …

The following rules apply to the global configuration:

  - The first tag to define is the **VERSION** tag specifying the parser
    version compatibility. Supported version is **1**.
  - The tag **PSA_DEFAULT**, if present, must be after the tag **VERSION**.
    This tag defines which Secure Subsystem is targetted to execute the PSA
    operation.
    If present after the first occurrence of **[SECURE_SUBSYSTEM]**, it is
    ignored. The possible values are the Secure Subsystems names listed in
    :numref:`secure_subsystems`. Adding option **ALT** (":ALT") after the Secure
    Subsystem name allows the selection of another Secure Subsystem if the
    default one doesn't support the requested Security Operation.


Secure Subsystems definition
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   [SECURE_SUBSYSTEM] /* First part of the 1st Subsystem */
       <string: name of subsystem>;
       <string: load/unload method>;
       [SECURITY_OPERATION]
       …
       [SECURITY_OPERATION]
       …
   [SECURE_SUBSYSTEM] /* 2nd Subsystem definition */
       <string: name of subsystem>;
       <string: load/unload method>;
       [SECURITY_OPERATION]
       …
       [SECURITY_OPERATION]
       …
   [SECURE_SUBSYSTEM] /* Second and last part of the 1st Subsystem */
       <string: name of subsystem>;
       [SECURITY_OPERATION]
       …


The following rules apply to the Secure Subsystem definition:

  - The tag **[SECURE_SUBSYSTEM]** defines a Secure Subsystem configuration
    block.
  - Each **[SECURE_SUBSYSTEM]** block must start with the subsystem name
    identifier matching the names defined in the Secure Subsystems
    name :numref:`secure_subsystems`.
  - An optional load/unload method can be specified within the block after the
    subsystem name using the format **<string: load/unload method>**. The
    supported methods are listed in :numref:`subsystem_load_methods`. This method
    must be defined only once per **[SECURE_SUBSYSTEM]** block.
  - A **[SECURE_SUBSYSTEM]** configuration can be split into multiple parts.
    Each part must start with the same subsystem name identifier.
  - A **[SECURE_SUBSYSTEM]** block can contain one or more secure operation
    definition block **[SECURITY_OPERATION]**.


.. note::

   - The configuration definition order is important. It defines the priority
     of the Secure Subsystems versus Security Operation when the library must
     select by itself which Secure Subsystems to be used to execute the Security
     Operation (when Subsystem Name is not specified in the API argument).
     The first **[SECURE_SUBSYSTEM]** block has the highest priority and the last
     one has the lowest priority.
   - Secure Subsystem is implicit when an operation uses a key identifier as
     key is owned by the Secure Subsystem.


Security Operations definition
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   [SECURITY_OPERATION]
       <string: name of operation>;
       /* A combination of the lines below describes */
       /* the Secure Subsystem capabilities for this Security Operation. */
       <param1>_VALUES=<value1>:<value2>:<value3>;
       <param2>_SIZE_RANGE=<integer: min>:<integer: max>;
       <param3>_SIZE_RANGE=:<integer: max>; /* threshold lower than */
       <param4>_SIZE_RANGE=<integer: min>:; /* threshold greater than */

The following rules apply to the Security Operation definition:

  - The tag **[SECURITY_OPERATION]** defines a Security Operation configuration
    block within a **[SECURE_SUBSYSTEM]** block.
  - Each **[SECURITY_OPERATION]** block must start with the operation name as
    matching the names defined in the `Security Operations`.
  - Each **[SECURITY_OPERATION]** block must contain one operation name
    identifier.
  - A Security Operation name must not be duplicated within the same Secure
    Subsystem configuration, even if Subsystem configuration is split across
    multiple **[SECURE_SUBSYSTEM]** blocks.
  - The Security Operation can define its capabilities values (e.g. key types,
    hash algorithms...) using tags **<param#>_VALUES** (as describes in
    `Capabilities tags`_). Each value is a non-quoted string
    separated by a colon '**:**'.
  - The Security Operation can define its capabilities range using tags
    **<param#>_SIZE_RANGE**. Range values are integer defining minimum and/or
    maximum capability value.


Naming Convention
^^^^^^^^^^^^^^^^^

Secure Subsystems
"""""""""""""""""

The :numref:`secure_subsystems` below lists all Secure Subsystems supported by
the Security Middleware library.

.. table:: Secure Subsystems
   :name: secure_subsystems
   :align: center
   :widths: 15 85
   :width: 100%
   :class: wrap-table

   +------------+------------------------------------------------------+
   | **Name**   | **Description**                                      |
   +============+======================================================+
   | SECO       | Use the SECO Secure Enclave on device type i.MX8qxp. |
   +------------+------------------------------------------------------+
   | TEE        | Use the Secure OS called OPTEE and running in ARM    |
   |            | Trustzone Secure world.                              |
   +------------+------------------------------------------------------+
   | ELE        | Use the ELE Secure Enclave (EdgeLock Enclave) on     |
   |            | devices type:                                        |
   |            |                                                      |
   |            |  - i.MX8ULP                                          |
   |            |  - i.MX9x                                            |
   +------------+------------------------------------------------------+

Subsystem load/unload methods
"""""""""""""""""""""""""""""

The following :numref:`subsystem_load_methods` defines the
possible string value of the load/unload method.

.. table:: Secure Subsystem - load/unload methods
   :name: subsystem_load_methods
   :align: center
   :widths: 50 50
   :width: 100%
   :class: wrap-table

   +---------------------------------+-----------------------------------------+
   | **Name**                        | **Description**                         |
   +=================================+=========================================+
   | AT_FIRST_CALL_LOAD              | At first Secure Subsystem call, the     |
   |                                 | Secure Subsystem is loaded.             |
   |                                 |                                         |
   |                                 | The Secure Subsystem is unloaded when   |
   |                                 | the configuration is unloaded.          |
   |                                 |                                         |
   |                                 | It's the **default** method if no       |
   |                                 | specified.                              |
   +---------------------------------+-----------------------------------------+
   | AT_CONTEXT_CREATION_DESTRUCTION | At Secure Subsystem context creation,   |
   |                                 | the Secure Subsystem is loaded.         |
   |                                 |                                         |
   |                                 | It is unloaded when the Secure          |
   |                                 | Subsystem operation is finish. In case  |
   |                                 | multi-part operation, when the final    |
   |                                 | step is performed or when the cancel    |
   |                                 | context operation is called.            |
   +---------------------------------+-----------------------------------------+


Security Operations
"""""""""""""""""""

This section defines the Security Operations organized by functional category:

  - Key Management Operations, `Key management`_.
  - Cryptographic Operations, `Cryptographic operations`_
  - Data Management Operations, `Data management`_.
  - Device Management Operations, `Device management`_.
  - Operation's capabilities tags, `Capabilities tags`_.


Key management
~~~~~~~~~~~~~~

Following :numref:`security_op_key_mgt` below lists all key management security
operations.

.. table:: Security Operations - key management
   :name: security_op_key_mgt
   :align: center
   :widths: 25 50 25
   :width: 100%
   :class: wrap-table

   +------------------------+--------------------------------------------------+----------------------+
   | **Name**               | **Description**                                  | **Capabilities Tags**|
   +========================+==================================================+======================+
   | GENERATE_KEY           | Generate a cryptographic key (private, keypair). | `KEY_TYPE_VALUES`_   |
   |                        | Public key can be exported.                      |                      |
   +------------------------+--------------------------------------------------+----------------------+
   | DERIVE_KEY             | Derive a key from an existing cryptographic key. | `KEY_TYPE_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `OP_TYPE_VALUES`_    |
   +------------------------+--------------------------------------------------+----------------------+
   | IMPORT_KEY             | Import cryptographic key (public, private,       | `KEY_TYPE_VALUES`_   |
   |                        | keypair).                                        |                      |
   +------------------------+--------------------------------------------------+----------------------+
   | EXPORT_KEY             | Export cryptographic key. Private key            | `KEY_TYPE_VALUES`_   |
   |                        | exportation is function of the Secure Subsystem  |                      |
   |                        | capabilities. Public key are always exportable.  |                      |
   +------------------------+--------------------------------------------------+----------------------+
   | DELETE_KEY             | Delete a key.                                    | `KEY_TYPE_VALUES`_   |
   +------------------------+--------------------------------------------------+----------------------+


Cryptographic operations
~~~~~~~~~~~~~~~~~~~~~~~~

Following :numref:`security_op_crypto` below lists all cryptographic security
operations.

.. table:: Security Operations - Cryptographic operations
   :name: security_op_crypto
   :align: center
   :widths: 26 48 26
   :width: 100%
   :class: wrap-table

   +------------------------+--------------------------------------------------+----------------------+
   | **Name**               | **Description**                                  | **Capabilities Tags**|
   +========================+==================================================+======================+
   | HASH                   | Oneshot message digest.                          | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | HASH_MULTI_PART        | Multipart message digest.                        | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | MAC                    | Message Authentication Code.                     | `KEY_TYPE_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MAC_ALGO_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | SIGN                   | Oneshot asymmetric signature generation.         | `SIGN_ALGO_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `SIGN_TYPE_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | VERIFY                 | Oneshot asymmetric signature verification.       | `SIGN_ALGO_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `SIGN_TYPE_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | SIGN_MULTI_PART        | Multipart asymmetric signature generation.       | `SIGN_ALGO_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `SIGN_TYPE_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | VERIFY_MULTI_PART      | Multipart asymmetric signature verification.     | `SIGN_ALGO_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `SIGN_TYPE_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | CIPHER                 | Oneshot cipher encryption and decryption.        | `KEY_TYPE_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MODE_VALUES`_       |
   +                        +                                                  +                      +
   |                        |                                                  | `OP_TYPE_VALUES`_    |
   +------------------------+--------------------------------------------------+----------------------+
   | CIPHER_MULTI_PART      | Multipart cipher encryption and decryption.      | `KEY_TYPE_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MODE_VALUES`_       |
   +                        +                                                  +                      +
   |                        |                                                  | `OP_TYPE_VALUES`_    |
   +------------------------+--------------------------------------------------+----------------------+
   | AEAD                   | Oneshot authentication encryption.               | `KEY_TYPE_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MODE_VALUES`_       |
   +                        +                                                  +                      +
   |                        |                                                  | `OP_TYPE_VALUES`_    |
   +------------------------+--------------------------------------------------+----------------------+
   | AEAD_MULTI_PART        | Multipart authentication encryption.             | `KEY_TYPE_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MODE_VALUES`_       |
   +                        +                                                  +                      +
   |                        |                                                  | `OP_TYPE_VALUES`_    |
   +------------------------+--------------------------------------------------+----------------------+
   | ASYMM_ENCRYPT          | Oneshot asymmetric encryption.                   | `ENC_ALGO_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MODE_VALUES`_       |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | ASYMM_DECRYPT          | Oneshot asymmetric decryption.                   | `ENC_ALGO_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MODE_VALUES`_       |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +------------------------+--------------------------------------------------+----------------------+
   | RNG                    | Generate a Random data number.                   | RNG_SIZE_RANGE       |
   +------------------------+--------------------------------------------------+----------------------+


Data management
~~~~~~~~~~~~~~~

Following :numref:`security_op_data_mgt` below lists all data management
security operations.

.. table:: Security Operations - Data management
   :name: security_op_data_mgt
   :align: center
   :widths: 26 48 26
   :width: 100%
   :class: wrap-table

   +------------------------+--------------------------------------------------+----------------------+
   | **Name**               | **Description**                                  | **Capabilities Tags**|
   +========================+==================================================+======================+
   | STORAGE_STORE          | Store data in secure storage.                    | `KEY_TYPE_VALUES`_   |
   +                        +                                                  +                      +
   |                        |                                                  | `MODE_VALUES`_       |
   +                        +                                                  +                      +
   |                        |                                                  | `HASH_ALGO_VALUES`_  |
   +                        +                                                  +                      +
   |                        |                                                  | `MAC_ALGO_VALUES`_   |
   +------------------------+--------------------------------------------------+----------------------+
   | STORAGE_RETRIEVE       | Retrieve data from secure storage.               | N/A                  |
   +------------------------+--------------------------------------------------+----------------------+
   | STORAGE_DELETE         | Delete data from secure storage.                 | N/A                  |
   +------------------------+--------------------------------------------------+----------------------+


Device management
~~~~~~~~~~~~~~~~~

Following :numref:`security_op_device_mgt` below lists all device management
security operations.

.. table:: Security Operations - Device management
   :name: security_op_device_mgt
   :align: center
   :widths: 28 46 26
   :width: 100%
   :class: wrap-table

   +------------------------+--------------------------------------------------+----------------------+
   | **Name**               | **Description**                                  | **Capabilities Tags**|
   +========================+==================================================+======================+
   | DEVICE_ATTESTATION     | Device attestation certificate.                  | N/A                  |
   +------------------------+--------------------------------------------------+----------------------+
   | DEVICE_LIFECYCLE       | Set and Get device lifecycle.                    | N/A                  |
   +------------------------+--------------------------------------------------+----------------------+
   | DEVICE_REPROVISION     | Device reprovisioning                            | N/A                  |
   +------------------------+--------------------------------------------------+----------------------+


Capabilities tags
~~~~~~~~~~~~~~~~~

KEY_TYPE_VALUES
***************

Following :numref:`security_op_key_type_values` below lists all supported key
type values.

To each key type value, a range tag is associated as shown in the table below.
The key range tag is used to define the minimum and/or maximum key security
size in bits. The key range tag is optional and when not specified, the key
size is not restricted.

The key range definition must respect the range format explained in the
`Syntactic rules`_ section above.


.. table:: Security Operation - Key type values
   :name: security_op_key_type_values
   :align: center
   :widths: 20 45 35
   :width: 100%
   :class: wrap-table


   +---------------+--------------------------------------------------+-------------------------+
   | **Name**      | **Description**                                  | **Range Tag**           |
   +===============+==================================================+=========================+
   | SECP_R1       | SECP R1 Elliptic Curve key.                      | SECP_R1_SIZE_RANGE      |
   +---------------+--------------------------------------------------+-------------------------+
   | BRAINPOOL_R1  | Brainpool R1 Elliptic Curve key.                 | BRAINPOOL_R1_SIZE_RANGE |
   +---------------+--------------------------------------------------+-------------------------+
   | BRAINPOOL_T1  | Brainpool T1 Elliptic Curve key.                 | BRAINPOOL_T1_SIZE_RANGE |
   +---------------+--------------------------------------------------+-------------------------+
   | ED25519       | Edwards Curve25519 key.                          | N/A                     |
   +---------------+--------------------------------------------------+-------------------------+
   | X25519        | ECDH key exchange based on Montgomery Curve25519.| N/A                     |
   +---------------+--------------------------------------------------+-------------------------+
   | ED448         | Edwards Curve448 key.                            | N/A                     |
   +---------------+--------------------------------------------------+-------------------------+
   | X448          | ECDH key exchange based on Montgomery Curve448.  | N/A                     |
   +---------------+--------------------------------------------------+-------------------------+
   | AES           | AES symmetric encryption                         | AES_SIZE_RANGE          |
   +---------------+--------------------------------------------------+-------------------------+
   | DES           | DES symmetric encryption                         | DES_SIZE_RANGE          |
   +---------------+--------------------------------------------------+-------------------------+
   | DES3          | Triple-DES symmetric encryption                  | DES3_SIZE_RANGE         |
   +---------------+--------------------------------------------------+-------------------------+
   | SM4           | SM4 symmetric encryption                         | N/A                     |
   +---------------+--------------------------------------------------+-------------------------+
   | HMAC          | HMAC message authentication                      | HMAC_SIZE_RANGE         |
   +---------------+--------------------------------------------------+-------------------------+
   | RSA           | RSA asymmetric encryption                        | RSA_SIZE_RANGE          |
   +---------------+--------------------------------------------------+-------------------------+
   | DH            | Diffie-Hellman key exchange                      | DH_SIZE_RANGE           |
   +---------------+--------------------------------------------------+-------------------------+
   | TLS_MASTER    | TLS Master secret derivation                     | N/A                     |
   +---------------+--------------------------------------------------+-------------------------+
   | RAW           | Raw public key format                            | N/A                     |
   +---------------+--------------------------------------------------+-------------------------+
   | DERIVE        | Derive key material                              | N/A                     |
   +---------------+--------------------------------------------------+-------------------------+


OP_TYPE_VALUES
**************

The capabilities definition apply to key derivation and some cryptographic
operations. The following section lists all supported operation type values
for key derivation and cryptographic operations.


**Key derivation operation type**

Following :numref:`security_op_derive_op_type_values` below lists all key
derivation operation type values.

.. table:: Security Operation - Key derivation operation type values
   :name: security_op_derive_op_type_values
   :align: center
   :widths: 34 66
   :width: 100%
   :class: wrap-table

   +-----------------------+-------------------------------------------------------------------+
   | **OP_TYPE_VALUES**    | **Description**                                                   |
   +=======================+===================================================================+
   | HKDF                  | HMAC-based Key Derivation Function.                               |
   +-----------------------+-------------------------------------------------------------------+
   | HKDF_EXTRACT          | HMAC-based Key Derivation Function Extract step.                  |
   +-----------------------+-------------------------------------------------------------------+
   | HKDF_EXPAND           | HMAC-based Key Derivation Function Expand step.                   |
   +-----------------------+-------------------------------------------------------------------+
   | ECDH                  | Elliptic Curve Diffie-Hellman key derivation.                     |
   +-----------------------+-------------------------------------------------------------------+
   | TLS12_KEY_EXCHANGE    | SECO subsystem TLS 1.2 Key Exchange.                              |
   |                       |                                                                   |
   |                       | **Deprecated** prefer to use the operation TLS12_OP_KEY_EXCHANGE. |
   |                       |                                                                   |
   |                       | Refer to :ref:`SMW API - Key Derivation <smw_key_derivation>`.    |
   +-----------------------+-------------------------------------------------------------------+
   | TLS12_OP_KEY_EXCHANGE | TLS 1.2 "Operation-based" Key Exchange.                           |
   +-----------------------+-------------------------------------------------------------------+
   | TLS13_KEY_EXCHANGE    | TLS 1.3 Key Exchange.                                             |
   +-----------------------+-------------------------------------------------------------------+
   | OEM_MASTER_KEY        | OEM Master key derivation.                                        |
   +-----------------------+-------------------------------------------------------------------+


**Cryptographic operation type**

Following :numref:`security_op_crypto_op_type_values` below lists all
cryptographic operation type values.

.. table:: Security Operation - Cryptographic operation type values
   :name: security_op_crypto_op_type_values
   :align: center
   :widths: 28 72
   :width: 100%
   :class: wrap-table

   +--------------------+--------------------------------------------------+
   | **OP_TYPE_VALUES** | **Description**                                  |
   +====================+==================================================+
   | ENCRYPT            | Encryption operation.                            |
   +--------------------+--------------------------------------------------+
   | DECRYPT            | Decryption operation.                            |
   +--------------------+--------------------------------------------------+


HASH_ALGO_VALUES
****************

Following :numref:`security_op_hash_algo_values` below lists all hash
algorithm values.

.. table:: Security Operation - Hash algorithm values
   :name: security_op_hash_algo_values
   :align: center
   :widths: 28 72
   :width: 100%
   :class: wrap-table

   +-----------------------+----------------------------------------+
   | **HASH_ALGO_VALUES**  | **Description**                        |
   +=======================+========================================+
   | MD5                   | Message Digest 5.                      |
   +-----------------------+----------------------------------------+
   | SHA1                  | Secure Hash Algorithm 1.               |
   +-----------------------+----------------------------------------+
   | SHA224                | Secure Hash Algorithm 2, 224 bits      |
   +-----------------------+----------------------------------------+
   | SHA256                | Secure Hash Algorithm 2, 256 bits      |
   +-----------------------+----------------------------------------+
   | SHA384                | Secure Hash Algorithm 2, 384 bits      |
   +-----------------------+----------------------------------------+
   | SHA512                | Secure Hash Algorithm 2, 512 bits      |
   +-----------------------+----------------------------------------+
   | SHA3_224              | Secure Hash Algorithm 3, 224 bits      |
   +-----------------------+----------------------------------------+
   | SHA3_256              | Secure Hash Algorithm 3, 256 bits      |
   +-----------------------+----------------------------------------+
   | SHA3_384              | Secure Hash Algorithm 3, 384 bits      |
   +-----------------------+----------------------------------------+
   | SHA3_512              | Secure Hash Algorithm 3, 512 bits      |
   +-----------------------+----------------------------------------+
   | SM3                   | ShangMi 3                              |
   +-----------------------+----------------------------------------+
   | SHAKE256              | Secure Hash Algorithm KECCAK, 256 bits |
   +-----------------------+----------------------------------------+


MAC_ALGO_VALUES
***************

Following :numref:`security_op_mac_algo_values` below lists all MAC
algorithm values.

.. table:: Security Operation - MAC algorithm values
   :name: security_op_mac_algo_values
   :align: center
   :widths: 28 72
   :width: 100%
   :class: wrap-table

   +---------------------+-----------------------------------------------------+
   | **MAC_ALGO_VALUES** | **Description**                                     |
   +=====================+=====================================================+
   | CMAC                | Cipher-based Message Authentication Code.           |
   +---------------------+-----------------------------------------------------+
   | CMAC_TRUNCATED      | Cipher-based Message Authentication Code truncated. |
   +---------------------+-----------------------------------------------------+
   | HMAC                | Hash-Based Message Authentication Code.             |
   +---------------------+-----------------------------------------------------+
   | HMAC_TRUNCATED      | Hash-Based Message Authentication Code truncated.   |
   +---------------------+-----------------------------------------------------+


.. _sign_type_values:

SIGN_ALGO_VALUES
****************

Following :numref:`security_op_sign_algo_values` below lists all asymmetric
signature algorithm values.

The column **SIGN_TYPE_VALUES** in the following table
:numref:`security_op_sign_algo_values` defines the possible signature type
value that could be defined if the signature algorithm is used. If the type
of signature is not defined, all signature type values are supported.


.. table:: Security Operation - Asymmetric signature algorithm values
   :name: security_op_sign_algo_values
   :align: center
   :widths: 28 26 46
   :width: 100%
   :class: wrap-table

   +----------------------+----------------------+-----------------------------------------+
   | **SIGN_ALGO_VALUES** | **SIGN_TYPE_VALUES** | **Description**                         |
   +======================+======================+=========================================+
   | ECDSA                | N/A                  | Elliptic Curve Digital Signature.       |
   +----------------------+----------------------+-----------------------------------------+
   | EDDSA                |                      | Edwards Curve Digital Signature.        |
   +                      +----------------------+-----------------------------------------+
   |                      | PURE_EDDSA           | Pure EdDSA signature type. The message  |
   |                      |                      | input is full message.                  |
   +                      +----------------------+-----------------------------------------+
   |                      | EDDSA_PH             | Pre-hashed EdDSA signature type. The    |
   |                      |                      | message input is pre-hashed.            |
   +                      +----------------------+-----------------------------------------+
   |                      | EDDSA_CTX            | EdDSA signature additional context.     |
   +----------------------+----------------------+-----------------------------------------+
   | RSA                  |                      | Rivest-Shamir-Adleman signature.        |
   +                      +----------------------+-----------------------------------------+
   |                      | PKCS1_1_5            | PKCS#1 v1.5 signature type.             |
   +                      +----------------------+-----------------------------------------+
   |                      | PSS                  | Probabilistic Signature Scheme type.    |
   +----------------------+----------------------+-----------------------------------------+
   | DSA                  |                      | Digital Signature Algorithm.            |
   +----------------------+----------------------+-----------------------------------------+
   | TLS_1_2              |                      | Transport Layer Security 1.2 signature. |
   +                      +----------------------+-----------------------------------------+
   |                      | CLIENT               | TLS 1.2 client signature type.          |
   +                      +----------------------+-----------------------------------------+
   |                      | SERVER               | TLS 1.2 server signature type.          |
   +----------------------+----------------------+-----------------------------------------+


ENC_ALGO_VALUES
***************

The following :numref:`security_op_asym_enc_values` below lists all asymmetric
encryption algorithm values for the asymmetric encryption algorithm operations.

.. table:: Security Operation - Asymmetric encryption algorithm values
   :name: security_op_asym_enc_values
   :align: center
   :widths: 28 72
   :width: 100%
   :class: wrap-table

   +----------------------+-----------------------------------------+
   | **ENC_ALGO_VALUES**  | **Description**                         |
   +======================+=========================================+
   | RSA                  | Rivest-Shamir-Adleman asymmetric.       |
   +----------------------+-----------------------------------------+


MODE_VALUES
***********

The capabilities definition apply to the symmetric encryption, authentication
encryption and asymmetric encryption cryptographic operations.
The following section lists all support mode values per cryptographic operation
type.


**Symmetric encryption algorithm mode values**

Following :numref:`security_op_sym_mode_values` below lists all mode
values for the symmetric algorithm operations.

.. table:: Security Operation - Symmetric encryption algorithm mode values
   :name: security_op_sym_mode_values
   :align: center
   :widths: 28 72
   :width: 100%
   :class: wrap-table

   +----------------------+-----------------------------------------+
   | **MODE_VALUES**      | **Description**                         |
   +======================+=========================================+
   | ECB                  | Electronic Codebook mode.               |
   +----------------------+-----------------------------------------+
   | CBC                  | Cipher Block Chaining mode.             |
   +----------------------+-----------------------------------------+
   | CTR                  | Counter mode.                           |
   +----------------------+-----------------------------------------+
   | CFB                  | Cipher Feedback mode.                   |
   +----------------------+-----------------------------------------+
   | OFB                  | Output Feedback mode.                   |
   +----------------------+-----------------------------------------+
   | CTS                  | Cipher Text Stealing mode.              |
   +----------------------+-----------------------------------------+
   | XTS                  | XTS mode.                               |
   +----------------------+-----------------------------------------+


**Authentication Encryption algorithm mode values**

Following :numref:`security_op_aead_mode_values` below lists all mode values
for the authentication encryption algorithm operations.

.. table:: Security Operation - AEAD algorithm mode values
   :name: security_op_aead_mode_values
   :align: center
   :widths: 28 72
   :width: 100%
   :class: wrap-table

   +----------------------+-----------------------------------------+
   | **MODE_VALUES**      | **Description**                         |
   +======================+=========================================+
   | GCM                  | Galois/Counter Mode.                    |
   +----------------------+-----------------------------------------+
   | CCM                  | Counter with CBC-MAC mode.              |
   +----------------------+-----------------------------------------+
   | CHACHA20_POLY1305    | ChaCha20-Poly1305 AEAD mode.            |
   +----------------------+-----------------------------------------+


**Asymmetric Encryption algorithm mode values**

Following :numref:`security_op_asym_mode_values` below lists all mode values
for the asymmetric encryption algorithm operations.


.. table:: Security Operation - Asymmetric algorithm mode values
   :name: security_op_asym_mode_values
   :align: center
   :widths: 28 72
   :width: 100%
   :class: wrap-table

   +----------------------+-----------------------------------------+
   | **MODE_VALUES**      | **Description**                         |
   +======================+=========================================+
   | OAEP                 | Optimal Asymmetric Encryption Padding.  |
   +----------------------+-----------------------------------------+
   | PKCS1_1_5            | PKCS#1 v1.5 encryption mode.            |
   +----------------------+-----------------------------------------+
   | NO_PAD               | No padding mode.                        |
   +----------------------+-----------------------------------------+


Example
^^^^^^^

Here is a possible Secure Subsystems configuration example. It's define
ELE (like i.MX93) and TEE secure subsystems operation and capabilities.

The configuration is written to give the priority on the ELE subsystem for
the secure operations if the secure operation argument does not specify a
particular secure subsystem.


.. literalinclude:: ele_config.txt
   :caption: Secure Subsystem(s) configuration example
   :language: ini

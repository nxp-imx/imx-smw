How to write a configuration file
=================================

This section describes how to write a configuration file.
It gives the syntactic rules, the list of valid inputs and some examples.

Syntactic rules
---------------

The configuration format must respect following rules:

- Characters must be encoded in ASCII.

- Semicolon specifies end of line.

- Colon is a separator of multiples entries.

- Spaces and line separators are ignored.

- Decimal numbers are written using the US/UK format (i.e. separator is ‘.’).

- Negative numbers are preceded by ‘-‘.

- String must not be quoted.

- Commented sections start with ‘/\*’ and finish with ‘\*/’. Comments are ignored.

- The first tag to define is the **VERSION** tag specifying the parser version compatibility.

- The tag **PSA_DEFAULT**, if present, must be after the tag **VERSION**. If present after the first occurrence of **[SECURE_SUBSYSTEM]**, it is ignored. The possible values are the Secure Subsystems names listed in `List of Secure Subsystems`_. Adding option **ALT** (":ALT") after the Secure Subsystem name allows the selection of another Secure Subsystem if the default one doesn't support the requested Security Operation.

- There must be at least one occurrence of **[SECURE_SUBSYSTEM]**. This tag is the starter of a Secure Subsystem configuration.

- There must be only one block defining a Secure Subsystem.

- There must be only one **<string: name of subsystem>** per **[SECURE_SUBSYSTEM]**.

- The load/unload method **<string: load/unload method>** is optional. Only one occurrence is allowed if present.

- There must be at least one occurrence of **[SECURITY_OPERATION]** per **[SECURE_SUBSYSTEM]**.

- There must be one **<string: name of operation>** set in **[SECURITY_OPERATION]**. The possible values of string correspond to the external interfaces of each module as listed in `List of Security Operations`_.

- There must be only one block defining a Security Operation for a given Secure Subsystem.

- The Security Operation can define its capabilities values (e.g. key types, hash algorithms...) using tags **<param#>_VALUES** (as listed in `List of Security Operation values tag`_). Each value is a non-quoted string separated by a colon.

- The Security Operation can define its capabilities range using tags **<param#>_RANGE** (as listed in `List of Security Operation range tag`_). Range values are integer defining minimum and/or maximum capability value.

Configuration file subsystem/operation definition pair represents the subsystem selection order when Secure Subsystem is not specified in the operation arguments. Note: Secure Subsystem is implicit when an operation uses a key identifier of a key already present in the Secure Subsystem key storage.

Secure Subsystem definition
---------------------------

.. code-block:: text

   [SECURE_SUBSYSTEM]
       <string: name of subsystem>;
       <string: load/unload method>;
       [SECURITY_OPERATION]
       …
       [SECURITY_OPERATION]
       …

The Secure Subsystems definition starts with the tag [SECURE_SUBSYSTEM] and is followed by its string name. The table below lists all Secure Subsystems supported by the Security Middleware library.

.. _`List of Secure Subsystems`:

List of Secure Subsystems:

.. tabularcolumns:: |\Y{0.4}|\Y{0.6}|

.. table::
   :align: left
   :class: wrap-table

   +----------------------------------+-----------------------------------------------------------------+
   | **Secure Subsystem string name** | **Description**                                                 |
   +==================================+=================================================================+
   | HSM                              | Use the HSM/SECO protected secure mode on certain i.MX8 device. |
   +----------------------------------+-----------------------------------------------------------------+
   | TEE                              | Use the Secure OS called OPTEE and running                      |
   |                                  | in ARM Trustzone Secure world.                                  |
   +----------------------------------+-----------------------------------------------------------------+
   | ELE                              | Use the ELE (EdgeLock Enclave) protected secure mode on:        |
   |                                  |  - i.MX8ULP                                                     |
   |                                  |  - i.MX9x                                                       |
   +----------------------------------+-----------------------------------------------------------------+

A different load and unload method can be specified for each Secure Subsystem thru the <string: load/unload method> string following the subsystem’s string name. The following table defines the possible string value of the load/unload method.

List of Secure Subsystem load/unload methods:

.. tabularcolumns:: |\Y{0.5}|\Y{0.5}|

.. table::
   :align: left
   :class: wrap-table

   +---------------------------------+-----------------------------------------------------------------------+
   | **Load/Unload string method**   | **Description**                                                       |
   +=================================+=======================================================================+
   | AT_FIRST_CALL_LOAD              | At first Secure Subsystem call, the Secure Subsystem is loaded.       |
   |                                 | The Secure Subsystem is unloaded when the configuration is unloaded.  |
   +---------------------------------+-----------------------------------------------------------------------+
   | AT_CONTEXT_CREATION_DESTRUCTION | At Secure Subsystem context creation, the Secure Subsystem is loaded. |
   |                                 | It is unloaded when the Secure Subsystem context is destroyed.        |
   +---------------------------------+-----------------------------------------------------------------------+

Following the Secure Subsystem capabilities, the configuration contains one or more operations associated to the Secure Subsystem as defined Security Operation definition.

Security Operation definition
-----------------------------

.. code-block:: text

   [SECURITY_OPERATION]
       <string: name of operation>;
       /* A combination of the lines below describes */
       /* the Secure Subsystem capabilities for this Security Operation. */
       <param1>_VALUES=<value1>:<value2>:<value3>;
       <param2>_RANGE=<integer: min>:<integer: max>;
       <param3>_RANGE=:<integer: max>; /* threshold lower than */
       <param4>_RANGE=<integer: min>:; /* threshold greater than */

The Security Operation starts with the tag [SECURITY_OPERATION] and is followed by its string name. The table below lists all Security Operations supported by the Security Middleware library.

.. _`List of Security Operations`:

List of Security Operations:

.. tabularcolumns:: |\Y{0.4}|\Y{0.6}|

.. table::
   :align: left
   :class: wrap-table

   +------------------------------------+------------------------------------------------------------------+
   | **Security Operation string name** | **Description**                                                  |
   +====================================+==================================================================+
   | GENERATE_KEY                       | Generate a cryptographic key (private, keypair).                 |
   |                                    | Public key can be exported.                                      |
   +------------------------------------+------------------------------------------------------------------+
   | DERIVE_KEY                         | Derive a key from an existing cryptographic key.                 |
   +------------------------------------+------------------------------------------------------------------+
   | UPDATE_KEY                         | Update imported or generated key attributes.                     |
   +------------------------------------+------------------------------------------------------------------+
   | IMPORT_KEY                         | Import cryptographic key (public, private, keypair).             |
   +------------------------------------+------------------------------------------------------------------+
   | EXPORT_KEY                         | Export cryptographic key. Private key exportation is function of |
   |                                    | the Secure Subsystem capabilities.                               |
   +------------------------------------+------------------------------------------------------------------+
   | DELETE_KEY                         | Delete an imported or generated cryptographic key.               |
   +------------------------------------+------------------------------------------------------------------+
   | CANCEL_OPERATION                   | Cancel an active operation context.                              |
   +------------------------------------+------------------------------------------------------------------+
   | COPY_CONTEXT                       | Copy an active operation context.                                |
   +------------------------------------+------------------------------------------------------------------+
   | HASH                               | Hash a message.                                                  |
   +------------------------------------+------------------------------------------------------------------+
   | HMAC                               | Keyed-hash authentication of a message. **Deprecated use MAC**   |
   +------------------------------------+------------------------------------------------------------------+
   | MAC                                | Message Authentication Code.                                     |
   +------------------------------------+------------------------------------------------------------------+
   | SIGN                               | Sign a message.                                                  |
   +------------------------------------+------------------------------------------------------------------+
   | VERIFY                             | Verify the signature of a message.                               |
   +------------------------------------+------------------------------------------------------------------+
   | CIPHER                             | Cipher encryption and decryption.                                |
   +------------------------------------+------------------------------------------------------------------+
   | CIPHER_MULTI_PART                  | Cipher multi-part encryption and decryption.                     |
   +------------------------------------+------------------------------------------------------------------+
   | AUTHENTICATE_ENCRYPT               | Encrypt and sign a message.                                      |
   +------------------------------------+------------------------------------------------------------------+
   | AUTHENTICATE_DECRYPT               | Decrypt and verify a message.                                    |
   +------------------------------------+------------------------------------------------------------------+
   | RNG                                | Generate a Random data number.                                   |
   +------------------------------------+------------------------------------------------------------------+
   | DEVICE_LIFECYCLE                   | Get and Set device lifecycle.                                    |
   +------------------------------------+------------------------------------------------------------------+
   | STORAGE_STORE                      | Store data in secure storage.                                    |
   +------------------------------------+------------------------------------------------------------------+
   | STORAGE_RETRIEVE                   | Retrieve data from secure storage.                               |
   +------------------------------------+------------------------------------------------------------------+
   | STORAGE_DELETE                     | Delete data from secure storage.                                 |
   +------------------------------------+------------------------------------------------------------------+

Each Security Operations definition can specify capabilities using Values and Range tags definition as listed in the following tables.

.. _`List of Security Operation values tag`:

List of Security Operation values tag:

.. tabularcolumns:: |\Y{0.3}|\Y{0.7}|

.. table::
   :align: left
   :class: wrap-table

   +------------------+----------------------------------------------------------------------------------+
   | **Tag Values**   | **Description**                                                                  |
   +==================+==================================================================================+
   | ALGO_VALUES      | Define the operation algorithms supported.                                       |
   +------------------+----------------------------------------------------------------------------------+
   | MODE_VALUES      | Define the modes supported for the operation algorithms.                         |
   +------------------+----------------------------------------------------------------------------------+
   | HASH_ALGO_VALUES | Define the Hash operation algorithms supported for the operation.                |
   +------------------+----------------------------------------------------------------------------------+
   | MAC_ALGO_VALUES  | Define the MAC operation algorithms supported for the operation.                 |
   +------------------+----------------------------------------------------------------------------------+
   | KEY_TYPE_VALUES  | Define the Key types supported for the operation.                                |
   +------------------+----------------------------------------------------------------------------------+
   | SIGN_TYPE_VALUES | Define the signature types supported for signature operations (sign and verify). |
   +------------------+----------------------------------------------------------------------------------+
   | OP_TYPE_VALUES   | Define the type of operation when it has multiple possibilities                  |
   |                  | (ex: encryption vs decryption for cipher operation).                             |
   +------------------+----------------------------------------------------------------------------------+

.. _`List of Security Operation range tag`:

List of Security Operation range tag:

.. tabularcolumns:: |\Y{0.4}|\Y{0.6}|

.. table::
   :align: left
   :class: wrap-table

   +------------------------------+---------------------------------------------------+
   | **Tag Range**                | **Description**                                   |
   +==============================+===================================================+
   | <KEY_TYPE>_SIZE_RANGE        | Define the minimum and maximum key size bits of   |
   |                              | a key type listed by the **KEY_TYPE_VALUES** tag. |
   +------------------------------+---------------------------------------------------+
   | RNG_LENGTH_RANGE             | Define the length range of a random number        |
   |                              | generated with the RNG operation.                 |
   +------------------------------+---------------------------------------------------+

Notice that all Values or Range are not useful for each operation. Refer to each operation to get the tags that could be defined and the corresponding value.

Example
-------

On Linux the plaintext configuration may be a text file. This example defines the configuration supporting 2 Secure Subsystems: OPTEE and HSM.

PSA default Secure Subsystem is OPTEE.
Secure Subsystem selection is enabled if OPTEE does not support the requested Security Operation.

OPTEE configuration:

- Subsystem is loaded/unloaded when configuration is loaded and unloaded, refer to Secure Subsystems definition.
- Cipher AES (ECB and CBC) and DES (ECB and CBC) operation. OPTEE is the default subsystem for this operation for the defined keys and modes.
- All keys defined by the Security Middleware can be generated using OPTEE Secure Subsystem.

HSM configuration:

- Subsystem is loaded/unloaded with the default method as defined in Secure Subsystems definition.
- Digest SHA256 operation.
- Generate 128 bits to 256 bits AES keys.
- Generate 56 bits DES keys.
- HSM is the default subsystem for this operation for the defined key capabilities.

.. code-block:: text

   /* Configuration file */
   VERSION=1;
   PSA_DEFAULT=TEE:ALT;
   [SECURE_SUBSYSTEM]
       TEE;
       /* Load/unload method */
       AT_FIRST_CALL_LOAD;
       [SECURITY_OPERATION]
           CIPHER;
           /* Only AES and DES keys are supported */
           KEY_TYPE_VALUES=AES:DES;
           /* Only ECB and CBC modes are supported */
           MODE_VALUES=ECB:CBC;
       [SECURITY_OPERATION]
           GENERATE_KEY;
           /* No specific capabilities - all parameters are accepted */
   [SECURE_SUBSYSTEM]
       HSM;
       /* No Load/unload method specified. Default is 1. */
       [SECURITY_OPERATION]
           HASH;
           HASH_ALGO_VALUES=SHA256;
       [SECURITY_OPERATION]
           GENERATE_KEY;
           /* Only AES and DES algorithms are supported */
           KEY_TYPE_VALUES=AES:DES;
           /* AES key size allowed is between 128 bits and 256 bits */
           AES_SIZE_RANGE=128:256;
           /* DES key size allowed is 56 bits */
           DES_SIZE_RANGE=56:56;

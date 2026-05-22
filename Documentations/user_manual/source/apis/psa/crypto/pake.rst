Password-Authenticated Key Exchange (PAKE)
""""""""""""""""""""""""""""""""""""""""""

PAKE primitives
~~~~~~~~~~~~~~~
A PAKE algorithm specifies a sequence of interactions between the participants.
Many PAKE algorithms are designed to allow different cryptographic primitives to
be used for the key establishment operation, so long as all the participants are
using the same underlying cryptography.

The cryptographic primitive for a PAKE operation is specified using a
:c:type:`psa_pake_primitive_t` value, which can be constructed using the
:c:macro:`PSA_PAKE_PRIMITIVE` macro, or can be provided as a numerical constant
value.

A PAKE primitive is required when constructing a PAKE cipher-suite object,
:c:type:`psa_pake_cipher_suite_t`, which fully specifies the PAKE operation to
be carried out.

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_pake_primitive_t

PAKE primitive values are constructed using :c:macro:`PSA_PAKE_PRIMITIVE`.

.. table:: PAKE primitive encoding
   :name: table_psa_pake_primitive_encoding
   :align: center
   :widths: 15 10
   :class: wrap-table

   +-------------+----------+
   | **Field**   | **Bits** |
   +=============+==========+
   | PAKE-TYPE   | [31:24]  |
   +-------------+----------+
   | PAKE-FAMILY | [23:16]  |
   +-------------+----------+
   | PAKE-BITS   | [15:0]   |
   +-------------+----------+

The components of a PAKE primitive value can be extracted using the
:c:macro:`PSA_PAKE_PRIMITIVE_GET_TYPE`,
:c:macro:`PSA_PAKE_PRIMITIVE_GET_FAMILY`, and
:c:macro:`PSA_PAKE_PRIMITIVE_GET_BITS`. These can be used to set key attributes
for keys used in PAKE algorithms. SPAKE2+ registration provides an example of
this usage.

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_pake_primitive_type_t psa_pake_family_t

The following :numref:`table_psa_pake_primitive_type_family` lists all PAKE
primitive type and associated family.

.. table:: PAKE primitive type and family
   :name: table_psa_pake_primitive_type_family
   :widths: 25 10 15 20
   :width: 100%
   :class: wrap-table

   +-----------------------------+-----------+----------------------------+--------------------------+
   | **PAKE-TYPE**                           | **PAKE-FAMILY**            | **Description**          |
   +-----------------------------+-----------+                            +                          +
   | **Name**                    | **Value** |                            |                          |
   +=============================+===========+============================+==========================+
   | PSA_PAKE_PRIMITIVE_TYPE_ECC | 0x01      | :c:type:`psa_ecc_family_t` | Elliptic curve primitive |
   +-----------------------------+-----------+----------------------------+--------------------------+
   | PSA_PAKE_PRIMITIVE_TYPE_DH  | 0x02      | :c:type:`psa_dh_family_t`  | Diffie-Hellman primitive |
   +-----------------------------+-----------+----------------------------+--------------------------+

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_PAKE_PRIMITIVE_TYPE_ECC PSA_PAKE_PRIMITIVE_TYPE_DH

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_PAKE_PRIMITIVE PSA_PAKE_PRIMITIVE_GET_TYPE
            PSA_PAKE_PRIMITIVE_GET_FAMILY PSA_PAKE_PRIMITIVE_GET_BITS

PAKE Cipher suites
~~~~~~~~~~~~~~~~~~
Most PAKE algorithms have parameters that must be specified by the application.
These parameters include the following:

  - The cryptographic primitive used for key establishment, specified using a
    `PAKE primitives`_.
  - A cryptographic hash algorithm.
  - Whether the application requires the shared secret before, or after, it is
    confirmed.

The hash algorithm is encoded into the PAKE algorithm identifier. The
:c:type:`psa_pake_cipher_suite_t` object is used to fully specify a PAKE
operation, combining the PAKE protocol with all of the above parameters.

A PAKE cipher suite is required when setting up a PAKE operation in
:c:func:`psa_pake_setup`.

.. kdoc-extension:: /public/psa/crypto/pake.h
   :typedefs: psa_pake_cipher_suite_t

Following initialization, the cipher-suite object contains the following
values\:

.. table:: PAKE cipher-suite object initialization
   :name: table_psa_pake_cipher_suite_object_init
   :align: center
   :widths: 20 60
   :class: wrap-table

   +------------------+-----------------------------------------------------+
   | **Attribute**    | **Value**                                           |
   +==================+=====================================================+
   | algorithm        | PSA_ALG_NONE — an invalid algorithm identifier.     |
   +------------------+-----------------------------------------------------+
   | primitive        | 0 — an invalid PAKE primitive.                      |
   +------------------+-----------------------------------------------------+
   | key confirmation | PSA_PAKE_CONFIRMED_KEY — requesting that the secret |
   |                  | key is confirmed before it can be returned.         |
   +------------------+-----------------------------------------------------+

Valid algorithm, primitive, and key confirmation values must be set when using
a PAKE cipher suite.

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_PAKE_CIPHER_SUITE_INIT

.. kdoc-extension:: /public/psa/crypto/pake.h
   :functions: psa_pake_cipher_suite_init

.. kdoc-extension:: /public/psa/crypto/pake.h
   :functions: psa_pake_cs_get_algorithm psa_pake_cs_set_algorithm
               psa_pake_cs_get_primitive psa_pake_cs_set_primitive
               psa_pake_cs_get_key_confirmation psa_pake_cs_set_key_confirmation


.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_PAKE_CONFIRMED_KEY PSA_PAKE_UNCONFIRMED_KEY

PAKE roles
~~~~~~~~~~
Some PAKE algorithms need to know which role each participant is taking in the
algorithm. For example:

  - Augmented PAKE algorithms typically have a client and a server participant.
  - Some symmetric PAKE algorithms assign an order to the two participants.

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_pake_role_t

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_PAKE_ROLE_NONE PSA_PAKE_ROLE_FIRST PSA_PAKE_ROLE_SECOND
            PSA_PAKE_ROLE_CLIENT PSA_PAKE_ROLE_SERVER

PAKE step types
~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_pake_step_t

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_PAKE_STEP_KEY_SHARE PSA_PAKE_STEP_ZK_PUBLIC
            PSA_PAKE_STEP_ZK_PROOF PSA_PAKE_STEP_CONFIRM

Multiple Part
~~~~~~~~~~~~~

.. warning::
   The PAKE multiple part sequence is not supported in the current
   implementation.

The sequence of operations to set up a password-authenticated key exchange
operation is as follows\:

 #. Allocate a PAKE operation object which will be passed to all the
    functions listed here.
 #. Initialize the operation object with one of the methods described in the
    documentation for &typedef psa_pake_operation_t. For example, using
    :c:macro:`PSA_PAKE_OPERATION_INIT`.
 #. Call :c:func:`psa_pake_setup` to specify the cipher suite.
 #. Call psa_pake_set_xxx() functions on the operation to complete the setup.
    The exact sequence of psa_pake_set_xxx() functions that needs to be
    called depends on the algorithm in use.

A typical sequence of calls to perform a password-authenticated key
exchange\:

 #. Call :c:func:`psa_pake_output` with `step = PSA_PAKE_STEP_KEY_SHARE` to get
    the key share that needs to be sent to the peer.
 #. Call :c:func:`psa_pake_input` with `step = PSA_PAKE_STEP_KEY_SHARE` to
    provide the key share that was received from the peer.
 #. Depending on the algorithm additional calls to :c:func:`psa_pake_output` and
    :c:func:`psa_pake_input` might be necessary.
 #. Call :c:func:`psa_pake_get_shared_key` to access the shared secret.

.. kdoc-extension:: /public/psa/crypto/pake.h
   :typedefs: psa_pake_operation_t

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_PAKE_OPERATION_INIT

.. kdoc-extension:: /public/psa/crypto/pake.h
   :functions: psa_pake_operation_init

.. kdoc-extension:: /public/psa/crypto/pake.h
   :functions: psa_pake_setup psa_pake_set_role psa_pake_set_user
               psa_pake_set_peer psa_pake_set_context
               psa_pake_output psa_pake_input psa_pake_get_shared_key
               psa_pake_abort

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_PAKE_OUTPUT_SIZE PSA_PAKE_OUTPUT_MAX_SIZE
            PSA_PAKE_INPUT_SIZE PSA_PAKE_INPUT_MAX_SIZE
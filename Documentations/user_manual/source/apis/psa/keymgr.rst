Key Manager APIs
^^^^^^^^^^^^^^^^

The Key Manager APIs allow users of the library to manage cryptographic keys.
such as generation, derivation, import, export, and deletion.

Key Creation
""""""""""""
Key Generate
~~~~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_generate_key psa_generate_key_custom psa_copy_key

Key Import
~~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_import_key

Key Derivation
""""""""""""""
Multiple Part
~~~~~~~~~~~~~
The sequence of operations to derive a key is as follows\:

 #. Allocate a key-derivation operation object
    :c:type:`psa_key_derivation_operation_t` which will be passed to all
    the functions listed here.
 #. Initialize the operation object with one of the methods described in the
    documentation for :c:type:`psa_key_derivation_operation_t`, e.g.
    :c:macro:`PSA_KEY_DERIVATION_OPERATION_INIT`.
 #. Call :c:func:`psa_key_derivation_setup` to select the algorithm.
 #. Provide the inputs for the key derivation by calling
    :c:func:`psa_key_derivation_input_bytes` or
    :c:func:`psa_key_derivation_input_key` as
    appropriate. Which inputs are needed, in what order, whether
    keys are permitted, and what type of keys depends on the algorithm.
 #. Optionally set the operation’s maximum capacity with
    :c:func:`psa_key_derivation_set_capacity`. This can be done before, in the
    middle of, or after providing inputs. For some algorithms, this step is
    mandatory because the output depends on the maximum capacity.
 #. To derive a key, call :c:func:`psa_key_derivation_output_key`. To derive a
    byte string for a different purpose, call
    :c:func:`psa_key_derivation_output_bytes`. Successive calls to these
    functions use successive output bytes calculated by the key derivation
    algorithm.
 #. Clean up the key derivation operation object with
    :c:func:`psa_key_derivation_abort`.

.. kdoc-extension:: /public/psa/keymgr.h
   :typedefs: psa_key_derivation_operation_t

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_KEY_DERIVATION_OPERATION_INIT

.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_key_derivation_operation_init

.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_key_derivation_setup psa_key_derivation_get_capacity
               psa_key_derivation_set_capacity psa_key_derivation_input_bytes
               psa_key_derivation_input_integer psa_key_derivation_input_key
               psa_key_derivation_output_bytes psa_key_derivation_output_key
               psa_key_derivation_output_key_custom
               psa_key_derivation_verify_bytes psa_key_derivation_verify_key
               psa_key_derivation_abort

.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_key_derivation_step_t

Standalone key agreement
""""""""""""""""""""""""
Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_key_agreement psa_raw_key_agreement

Combining key agreement and key derivation
""""""""""""""""""""""""""""""""""""""""""
Function
~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_key_derivation_key_agreement

Key Exportation
"""""""""""""""
Function
~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_export_key psa_export_public_key

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_EXPORT_KEY_OUTPUT_SIZE PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE

.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_EXPORT_KEY_PAIR_MAX_SIZE PSA_EXPORT_PUBLIC_KEY_MAX_SIZE
            PSA_EXPORT_ASYMMETRIC_KEY_MAX_SIZE

Key Deletion
""""""""""""
Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_destroy_key psa_purge_key

Key Encapsulate
"""""""""""""""
Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_encapsulate psa_decapsulate

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_ENCAPSULATE_CIPHERTEXT_SIZE PSA_ENCAPSULATE_CIPHERTEXT_MAX_SIZE

Key Attributes
""""""""""""""
Attributes
~~~~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :typedefs: psa_key_attributes_t

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_KEY_ATTRIBUTES_INIT

.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_reset_key_attributes psa_key_attributes_init

.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_get_key_attributes

.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_set_key_id psa_get_key_id
               psa_set_key_bits psa_set_key_algorithm

.. kdoc-extension:: /public/psa/keymgr.h
   :functions: psa_get_key_bits psa_get_key_algorithm

Key identifier
~~~~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto_types.h
   :typedefs: psa_key_id_t

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_KEY_ID_USER_MIN PSA_KEY_ID_USER_MAX
            PSA_KEY_ID_VENDOR_MIN PSA_KEY_ID_VENDOR_MAX

Key custom parameters
"""""""""""""""""""""
Typedef
~~~~~~~
.. kdoc-extension:: /public/psa/keymgr.h
   :typedefs: psa_custom_key_parameters_t

The :numref:`table_custom_key_parameters` shows the custom production parameters
for each type of key. See the key type definitions for details of the valid
parameter values.

.. table:: Custom key parameters
   :name: table_custom_key_parameters
   :widths: 30 70
   :width: 100%
   :class: wrap-table

   +-----------------+----------------------------------------------------------+
   | **Key type**    | **Custom key parameters**                                |
   +=================+==========================================================+
   | RSA             | Use the production parameters to select an exponent      |
   |                 | value that is different from the default value of 65537. |
   |                 | See PSA_KEY_TYPE_RSA_KEY_PAIR.                           |
   +-----------------+----------------------------------------------------------+
   | Other key types | Reserved for future use.                                 |
   +-----------------+----------------------------------------------------------+

.. note::
   Future versions of the PSA Certified Crypto API, and implementations, may
   add other fields in this structure.

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_CUSTOM_KEY_PARAMETERS_INIT

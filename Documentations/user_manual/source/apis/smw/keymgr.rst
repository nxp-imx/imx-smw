Key Manager APIs
^^^^^^^^^^^^^^^^
The Key Manager APIs allow users of the library to manage cryptographic keys.
such as generation, derivation, import, export, and deletion.


Key Creation
""""""""""""
Key Generate
~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_generate_key
    :structs: smw_generate_key_args

Key import
~~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_import_key
    :structs: smw_import_key_args

Key Derivation
""""""""""""""
.. _smw_key_derivation:

Function
~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_derive_key
    :structs: smw_derive_key_args

TLS 1.2 derivation
~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :structs: smw_kdf_tls12_op_args smw_kdf_tls12_master_secret_args
              smw_kdf_tls12_key_expansion_args smw_kdf_tls12_random_data
              smw_kdf_tls12_session_hash

.. kdoc-extension:: /public/smw_keymgr.h
    :structs: smw_kdf_tls12_args

TLS 1.3 derivation
~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :structs: smw_kdf_tls13_args

The TLS 1.3 expand label buffer could be created using the following helper
function, structure and macro:

.. kdoc-extension:: /public/smw/kdf/tls.h
    :functions: smw_tls13_expand_label
    :structs: smw_tls13_expand_label_args
    :macros: SMW_TLS13_EXPANDED_LABEL_LENGTH SMW_TLS13_PREFIX
             SMW_TLS13_PREFIX_LENGTH

HKDF derivation
~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :structs: smw_kdf_hkdf_args smw_hkdf_args smw_hkdf_extract_args smw_hkdf_expand_args

ECDH derivation
~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :structs: smw_kdf_ecdh_args

OEM Master Key derivation
~~~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/smw/kdf/oem_master_key.h
    :structs: smw_kdf_oem_master_key_args


Key Exportation
"""""""""""""""
Function
~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_export_key
    :structs: smw_export_key_args


Key Deletion
""""""""""""
Function
~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_delete_key
    :structs: smw_delete_key_args


Key Attributes
""""""""""""""
Functions
~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_get_key_attributes
    :structs: smw_get_key_attributes_args

.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_get_key_buffers_lengths smw_get_key_type_name
                smw_get_security_size


Key Storage Protection
""""""""""""""""""""""
Function
~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_commit_key_storage
    :structs: smw_commit_key_storage_args


Key Attestation
"""""""""""""""
Function
~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :functions: smw_key_attestation
    :structs: smw_key_attestation_args


Key Descriptors
"""""""""""""""
Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw_keymgr.h
    :structs: smw_key_descriptor smw_derived_key_descriptor smw_key_attributes
              smw_keypair_buffer smw_keypair_gen smw_keypair_rsa

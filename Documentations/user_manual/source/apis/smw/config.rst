Configuration APIs
^^^^^^^^^^^^^^^^^^

The configuration APIs allow user of the library to:

  - Get information about the state of the Secure Subsystems.
  - Get the capabilities of the library operations.
  - Load/Unload library configuration.

Subsystems Information
""""""""""""""""""""""
Functions
~~~~~~~~~
.. kernel-doc:: /public/smw_config.h
    :functions: smw_config_subsystem_present smw_config_subsystem_loaded

Key capabilities
""""""""""""""""
Functions
~~~~~~~~~
.. kernel-doc:: /public/smw_config.h
    :functions: smw_config_check_generate_key smw_config_check_derive_key

Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw_config.h
    :structs: smw_key_info

Cryptography capabilities
"""""""""""""""""""""""""
Functions
~~~~~~~~~
.. kernel-doc:: /public/smw_config.h
    :functions: smw_config_check_digest smw_config_check_sign
                smw_config_check_verify smw_config_check_cipher
                smw_config_check_aead smw_config_check_mac
                smw_config_check_asymmetric_encrypt
                smw_config_check_asymmetric_decrypt

Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw_config.h
    :structs: smw_signature_info smw_cipher_info smw_aead_info smw_mac_info
              smw_asymmetric_encrypt_info


Library configuration
"""""""""""""""""""""
Functions
~~~~~~~~~
.. kernel-doc:: /public/smw_config.h
    :functions: smw_config_load smw_config_unload

Storage APIs
^^^^^^^^^^^^
General definitions
"""""""""""""""""""
Structure and Typedefs
~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/psa/storage_common.h
   :structs: psa_storage_info_t

.. kdoc-extension:: /public/psa/storage_common.h
   :typedefs: psa_storage_create_flags_t

The following :numref:`table_psa_data_creation_flags` lists all data creation
flags supported.

.. table:: PSA data creation flags
   :name: table_psa_data_creation_flags
   :align: center
   :class: wrap-table

   +---------------------------------------+-----------+
   | **Flags**                             | **Value** |
   +=======================================+===========+
   | PSA_STORAGE_FLAG_NONE                 | 0x00      |
   +---------------------------------------+-----------+
   | PSA_STORAGE_FLAG_WRITE_ONCE           | 0x01      |
   +---------------------------------------+-----------+
   | PSA_STORAGE_FLAG_NO_CONFIDENTIALITY   | 0x02      |
   +---------------------------------------+-----------+
   | PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION | 0x04      |
   +---------------------------------------+-----------+

.. kdoc-extension:: /public/psa/storage_common.h
   :typedefs: psa_storage_uid_t

.. warning::
   The implementation does not support :type:`psa_storage_uid_t` value
   greater than 0xFFFFFFFF

Internal Trusted Storage
""""""""""""""""""""""""
Internal Trusted Storage is designed to store the most sensitive device data
inside the Platform Root of Trust (PRoT).

  - It lives in trusted, isolated memory (e.g., secure flash, OTP, secure RAM)
  - Accessible only by trusted firmware / secure partitions

Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/internal_trusted_storage.h
   :functions: psa_its_set psa_its_get psa_its_get_info psa_its_remove

Protected Storage
"""""""""""""""""
The Protected Storage is a general-purpose secure storage layer for larger or
external data.

  - Typically stored in:

     - External flash
     - Non-secure memory

  - Security is provided via crypto mechanisms.

.. warning::
   The current implementation does not support such of storage.

Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/protected_storage.h
   :functions: psa_ps_set psa_ps_get psa_ps_get_info psa_ps_remove
               psa_ps_create psa_ps_set_extended psa_ps_get_support
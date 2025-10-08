.. _core-osal-interface:

Core library interface
----------------------

The SMW-OSAL interface defines the contract between the SMW core library and
the OSAL module. It specifies the structures and functions that the OSAL
implementation must provide to enable proper communication and integration
with the SMW core library.

This interface ensures that any OSAL implementation can be seamlessly integrated
without modifying the core library itself, allowing for OS-specific customizations
while maintaining a consistent contract.

.. note::
   This implementation can be customized by the integrator.

Object database
^^^^^^^^^^^^^^^

The OSAL module is in charge of creating/maintaining a database for the object
(key/data) present in the Secure Subsystem(s) storage(s).

This database objectives are:
  - Storing object metadata like identifier, attributes, subsystem owner,
    user label.
  - Generating unique user object identifier if no provided by the user.
  - Providing search operation by object attributes, user label, ...
  - Identifying Secure Subsystem owning the object.
  - Classifying object per persistency. Knowing that transient objects are
    not resisting to a system reset, the OSAL can destroy the transient object
    after system reset.

.. note::
   The database can't be used to store asymmetric private key or symmetric key.

.. note::
   The database is not mandatory but integrator must be aware that some features
   will not be supported like database search operation, user metadata like
   label and identifier.


OSAL APIs
^^^^^^^^^

Initialization
""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :functions: smw_init

Deinitialization
""""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :functions: smw_deinit

OSAL operations
^^^^^^^^^^^^^^^

Interface
"""""""""
Following structure describes the OSAL operations interface optional and
mandatory function pointers.

.. kdoc-extension:: /inc/osal.h
  :structs: smw_ops

Critical section
""""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_critical_section_start_t smw_osal_critical_section_stop_t

Mutex protection
""""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_mutex_init_t smw_osal_mutex_lock_t smw_osal_mutex_unlock_t
             smw_osal_mutex_destroy_t

Thread management
"""""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_thread_create_t smw_osal_thread_cancel_t

Debug trace
"""""""""""
.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_vprint_t smw_osal_hex_dump_t

Active subsystem
""""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_register_active_subsystem_t

Get the subsystem information
"""""""""""""""""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_get_subsystem_info_t

Library initialization
""""""""""""""""""""""
.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_is_lib_initialized_t

Object database management
""""""""""""""""""""""""""

.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_db_add_obj_t smw_osal_db_get_obj_t
             smw_osal_db_update_obj_t smw_osal_db_delete_obj_t

.. kdoc-extension:: /inc/osal.h
  :typedefs: smw_osal_db_find_init_t smw_osal_db_find_next_t
             smw_osal_db_find_final_t

.. kdoc-extension:: /inc/osal.h
  :structs: smw_osal_object
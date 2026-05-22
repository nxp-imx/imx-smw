Data Storage APIs
^^^^^^^^^^^^^^^^^

The Storage APIs allow users of the library to manage secure storage
operations such as creation, deletion, and data access.

Storing the data can be done either in plain text or encrypted and/or signed.
If the data is encrypted data will be returned as an encrypted blob.
If the data is signed, data will be returned as a signed blob.
Refer to the subsystem capabilities for more details of the supported
features and blob format.
Signature is limited to MAC signature.

Data Management
"""""""""""""""
Data Store
~~~~~~~~~~
.. kdoc-extension:: /public/smw_storage.h
    :functions: smw_store_data
    :structs: smw_store_data_args smw_encryption_args smw_sign_args

Data Retrieve
~~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_storage.h
    :functions: smw_retrieve_data
    :structs: smw_retrieve_data_args

Data Delete
~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_storage.h
    :functions: smw_delete_data
    :structs: smw_delete_data_args

Data Information
~~~~~~~~~~~~~~~~
.. kdoc-extension:: /public/smw_storage.h
    :functions: smw_get_data_info
    :structs: smw_data_info_args

Data Descriptor
"""""""""""""""
Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw_storage.h
    :structs: smw_data_descriptor smw_data_attributes
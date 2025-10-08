Object Database APIs
^^^^^^^^^^^^^^^^^^^^

The object database APIs allows users to find object(s) and update some
properties of an object in the SMW database.

Finding object(s)
"""""""""""""""""
Two methods are available to find object(s):
 - By its identifier
 - By its attribute(s)

.. kdoc-extension:: /public/smw/object.h
    :functions: smw_find_object_db

.. kdoc-extension:: /public/smw/object.h
    :functions: smw_find_object_db_init smw_find_object_db_next
                smw_find_object_db_final

.. kdoc-extension:: /public/smw/object.h
    :structs: smw_find_object_db_args


Updating object properties
""""""""""""""""""""""""""
.. kdoc-extension:: /public/smw/object.h
    :functions: smw_update_object_db


Object Descriptor
"""""""""""""""""
.. kdoc-extension:: /public/smw/object.h
    :structs: smw_object_descriptor

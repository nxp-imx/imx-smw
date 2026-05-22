Operation context
"""""""""""""""""
The operation context is used in the operation sequence split in multipart
calls. The following functions are generic functions regardless the type
of cryptographic sequence.

Functions
~~~~~~~~~
.. kernel-doc:: /public/smw/crypto/op_context.h
   :functions: smw_allocate_context smw_cancel_operation smw_copy_context

Structures
~~~~~~~~~~
.. kdoc-extension:: /public/smw/crypto/op_context.h
   :structs:

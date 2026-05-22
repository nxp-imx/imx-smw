Message digests (Hashes)
""""""""""""""""""""""""

Single Part
~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto/hash.h
   :functions: psa_hash_compute psa_hash_compare

.. _psa_hash_multipart:

Multiple Part
~~~~~~~~~~~~~
The sequence of operations to calculate a hash (message digest) is as
follows\:

 #. Allocate an operation object :c:type:`psa_hash_operation_t` which will be
    passed to all the functions listed here.
 #. Initialize the operation object with one of the methods described in the
    documentation for :c:type:`psa_hash_operation_t`, e.g.
    :c:macro:`PSA_HASH_OPERATION_INIT`.
 #. Call :c:func:`psa_hash_setup` to specify the algorithm.
 #. Call :c:func:`psa_hash_update` zero, one or more times, passing a fragment
    of the message each time. The hash that is calculated is the hash of the
    concatenation of these messages in order.
 #. To calculate the hash, call :c:func:`psa_hash_finish`. To compare the hash
    with an expected value, call :c:func:`psa_hash_verify`. To suspend the hash
    operation and extract the current state, call :c:func:`psa_hash_suspend`.

.. kdoc-extension:: /public/psa/crypto/hash.h
   :typedefs: psa_hash_operation_t

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_HASH_OPERATION_INIT

.. kdoc-extension:: /public/psa/crypto/hash.h
   :functions: psa_hash_operation_init

.. kdoc-extension:: /public/psa/crypto/hash.h
   :functions: psa_hash_setup psa_hash_update psa_hash_finish
               psa_hash_verify psa_hash_abort psa_hash_clone

Suspend and Resume operation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
   The HASH multiple part suspend and resume operations are
   not supported in the current implementation.

The sequence of operations to suspend and resume a hash operation is as
follows\:

  #. Compute the first part of the hash.

     a. Allocate an operation object and initialize it as described in the
        documentation for :c:type:`psa_hash_operation_t`.
     b. Call :c:func:`psa_hash_setup` to specify the algorithm.
     c. Call :c:func:`psa_hash_update` zero, one or more times, passing a
        fragment of the message each time.
     d. Call :c:func:`psa_hash_suspend` to extract the hash suspend state into
        a buffer.

  #. Pass the hash state buffer to the application which will resume the
     operation.
  #. Compute the rest of the hash.

     a. Allocate an operation object and initialize it as described in the
        documentation for :c:type:`psa_hash_operation_t`.
     b. Call :c:func:`psa_hash_resume` with the extracted hash state.
     c. Call :c:func:`psa_hash_update` zero, one or more times, passing a
        fragment of the message each time.
     d. To calculate the hash, call :c:func:`psa_hash_finish`. To compare the
        hash with an expected value, call :c:func:`psa_hash_verify`.

If an error occurs at any step after a call to :c:func:`psa_hash_setup` or
:c:func:`psa_hash_resume`, the operation will need to be reset by a call to
:c:func:`psa_hash_abort`. The application can call :c:func:`psa_hash_abort` at
any time after the operation has been initialized.

.. kdoc-extension:: /public/psa/crypto/hash.h
   :functions: psa_hash_suspend psa_hash_resume

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_HASH_LENGTH PSA_HASH_MAX_SIZE PSA_HASH_BLOCK_LENGTH
            PSA_HASH_SUSPEND_OUTPUT_SIZE PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE
Message Authentication Code (MAC)
"""""""""""""""""""""""""""""""""

Single Part
~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto/mac.h
   :functions: psa_mac_compute psa_mac_verify

Multiple Part
~~~~~~~~~~~~~

.. warning::
   The MAC signature generation and verification multiple part sequences are
   not supported in the current implementation.

**MAC signature generation sequence**

 The sequence of operations to calculate a MAC is as follows\:

  #. Allocate an operation object :c:type:`psa_mac_operation_t` which will be
     passed to all the functions listed here.
  #. Initialize the operation object with one of the methods described in the
     documentation for :c:type:`psa_mac_operation_t`, e.g.
     :c:macro:`PSA_MAC_OPERATION_INIT`.
  #. Call :c:func:`psa_mac_sign_setup` to specify the algorithm and key.
  #. Call :c:func:`psa_mac_update` zero, one or more times, passing a fragment
     of the message each time. The MAC that is calculated is the MAC of the
     concatenation of these messages in order.
  #. At the end of the message, call :c:func:`psa_mac_sign_finish` to finish
     calculating the MAC value and retrieve it.


**MAC signature verification sequence**

 The sequence of operations to verify a MAC is as follows\:

  #. Allocate an operation object :c:type:`psa_mac_operation_t` which will be
     passed to all the functions listed here.
  #. Initialize the operation object with one of the methods described in the
     documentation for :c:type:`psa_mac_operation_t`, e.g.
     :c:macro:`PSA_MAC_OPERATION_INIT`.
  #. Call :c:func:`psa_mac_verify_setup` to specify the algorithm and key.
  #. Call :c:func:`psa_mac_update` zero, one or more times, passing a fragment
     of the message each time. The MAC that is calculated is the MAC of the
     concatenation of these messages in order.
  #. At the end of the message, call :c:func:`psa_mac_verify_finish` to finish
     calculating the actual MAC of the message and verify it against the
     expected value.


.. kdoc-extension:: /public/psa/crypto/mac.h
   :typedefs: psa_mac_operation_t

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_MAC_OPERATION_INIT

.. kdoc-extension:: /public/psa/crypto/mac.h
   :functions: psa_mac_operation_init

.. kdoc-extension:: /public/psa/crypto/mac.h
   :functions: psa_mac_sign_setup psa_mac_verify_setup
               psa_mac_update psa_mac_sign_finish psa_mac_verify_finish
               psa_mac_abort

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_MAC_LENGTH PSA_MAC_MAX_SIZE

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_ALG_FULL_LENGTH_MAC PSA_ALG_AT_LEAST_THIS_LENGTH_MAC
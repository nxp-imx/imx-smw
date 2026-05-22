Authenticated Encryption with Associated Data (AEAD)
""""""""""""""""""""""""""""""""""""""""""""""""""""

Single Part
~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto/aead.h
   :functions: psa_aead_encrypt psa_aead_decrypt

Multiple Part
~~~~~~~~~~~~~

**AEAD encryption**

 The sequence of operations to encrypt a message with authentication is as
 follows\:

  #. Allocate an operation object :c:type:`psa_aead_operation_t` which will be
     passed to all the functions listed here.
  #. Initialize the operation object with one of the methods described in the
     documentation for :c:type:`psa_aead_operation_t`, e.g.
     :c:macro:`PSA_AEAD_OPERATION_INIT`.
  #. Call :c:func:`psa_aead_encrypt_setup` to specify the algorithm and key.
  #. If needed, call :c:func:`psa_aead_set_lengths` to specify the length of the
     inputs to the subsequent calls to :c:func:`psa_aead_update_ad` and
     :c:func:`psa_aead_update`. See the documentation of
     :c:func:`psa_aead_set_lengths` for details.
  #. Call either :c:func:`psa_aead_generate_nonce` or
     :c:func:`psa_aead_set_nonce` to generate or set the nonce. It is
     recommended to use :c:func:`psa_aead_generate_nonce`
     unless the protocol being implemented requires a specific nonce value.
  #. Call :c:func:`psa_aead_update_ad` zero, one or more times, passing a
     fragment of the non-encrypted additional authenticated data each time.
  #. Call :c:func:`psa_aead_update` zero, one or more times, passing a fragment
     of the message to encrypt each time.
  #. Call :c:func:`psa_aead_finish`.

**AEAD decryption**

 The sequence of operations to decrypt a message with authentication is as
 follows\:

  #. Allocate an operation object :c:type:`psa_aead_operation_t` which will be
     passed to all the functions listed here.
  #. Initialize the operation object with one of the methods described in the
     documentation for :c:type:`psa_aead_operation_t`, e.g.
     :c:macro:`PSA_AEAD_OPERATION_INIT`.
  #. Call :c:func:`psa_aead_decrypt_setup` to specify the algorithm and key.
  #. If needed, call :c:func:`psa_aead_set_lengths` to specify the length of the
     inputs to the subsequent calls to :c:func:`psa_aead_update_ad` and
     :c:func:`psa_aead_update`. See the documentation of
     :c:func:`psa_aead_set_lengths` for details.
  #. Call :c:func:`psa_aead_set_nonce` with the nonce for the decryption.
  #. Call :c:func:`psa_aead_update_ad` zero, one or more times, passing a
     fragment of the non-encrypted additional authenticated data each time.
  #. Call :c:func:`psa_aead_update` zero, one or more times, passing a fragment
     of the ciphertext to decrypt each time.
  #. Call :c:func:`psa_aead_verify`.


.. kdoc-extension:: /public/psa/crypto/aead.h
   :typedefs: psa_aead_operation_t

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_AEAD_OPERATION_INIT

.. kdoc-extension:: /public/psa/crypto/aead.h
   :functions: psa_aead_operation_init

.. kdoc-extension:: /public/psa/crypto/aead.h
   :functions: psa_aead_encrypt_setup psa_aead_decrypt_setup
               psa_aead_set_lengths psa_aead_generate_nonce psa_aead_set_nonce
               psa_aead_update_ad psa_aead_update psa_aead_finish
               psa_aead_verify psa_aead_abort

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_AEAD_ENCRYPT_OUTPUT_SIZE PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE
            PSA_AEAD_DECRYPT_OUTPUT_SIZE PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE
            PSA_AEAD_NONCE_LENGTH PSA_AEAD_NONCE_MAX_SIZE
            PSA_AEAD_UPDATE_OUTPUT_SIZE PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE
            PSA_AEAD_FINISH_OUTPUT_SIZE PSA_AEAD_FINISH_OUTPUT_MAX_SIZE
            PSA_AEAD_TAG_LENGTH PSA_AEAD_TAG_MAX_SIZE
            PSA_AEAD_VERIFY_OUTPUT_SIZE PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_ALG_AEAD_WITH_SHORTENED_TAG PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG
            PSA_ALG_AEAD_TAG_LENGTH PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG

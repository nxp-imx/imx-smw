Symmetric Encryption
""""""""""""""""""""

Single Part
~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto/cipher.h
   :functions: psa_cipher_encrypt psa_cipher_decrypt

Multiple Part
~~~~~~~~~~~~~

**Symmetric encryption**

 The sequence of operations to encrypt a message with a symmetric cipher is
 as follows\:

  #. Allocate an operation object :c:type:`psa_cipher_operation_t` which will be
     passed to all the functions listed here.
  #. Initialize the operation object with one of the methods described in the
     documentation for :c:type:`psa_cipher_operation_t`, e.g.
     :c:macro:`PSA_CIPHER_OPERATION_INIT`.
  #. Call :c:func:`psa_cipher_encrypt_setup` to specify the algorithm and key.
  #. Call either :c:func:`psa_cipher_generate_iv` or :c:func:`psa_cipher_set_iv`
     to generate or set the initialization vector (IV), if the algorithm
     requires one. It is recommended to use :c:func:`psa_cipher_generate_iv`
     unless the protocol being implemented requires a specific IV value.
  #. Call :c:func:`psa_cipher_update` zero, one or more times, passing a
     fragment of the message each time.
  #. Call :c:func:`psa_cipher_finish`.

**Symmetric decryption**

 The sequence of operations to decrypt a message with a symmetric cipher is
 as follows\:

  #. Allocate an operation object :c:type:`psa_cipher_operation_t` which
     will be passed to all the functions listed here.
  #. Initialize the operation object with one of the methods described in the
     documentation for :c:type:`psa_cipher_operation_t`, e.g.
     :c:macro:`PSA_CIPHER_OPERATION_INIT`.
  #. Call :c:func:`psa_cipher_decrypt_setup` to specify the algorithm and key.
  #. Call :c:func:`psa_cipher_set_iv` with the initialization vector (IV) for
     the decryption, if the algorithm requires one. This must match the IV used
     for the encryption.
  #. Call :c:func:`psa_cipher_update` zero, one or more times, passing a
     fragment of the message each time.
  #. Call :c:func:`psa_cipher_finish`.

.. kdoc-extension:: /public/psa/crypto/cipher.h
   :typedefs: psa_cipher_operation_t

.. kdoc-extension:: /public/psa/crypto_struct.h
   :macros: PSA_CIPHER_OPERATION_INIT

.. kdoc-extension:: /public/psa/crypto/cipher.h
   :functions: psa_cipher_operation_init

.. kdoc-extension:: /public/psa/crypto/cipher.h
   :functions: psa_cipher_encrypt_setup psa_cipher_decrypt_setup
               psa_cipher_generate_iv psa_cipher_set_iv psa_cipher_update
               psa_cipher_finish psa_cipher_abort

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_CIPHER_ENCRYPT_OUTPUT_SIZE PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE
            PSA_CIPHER_DECRYPT_OUTPUT_SIZE PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE
            PSA_CIPHER_IV_LENGTH PSA_CIPHER_IV_MAX_SIZE
            PSA_CIPHER_UPDATE_OUTPUT_SIZE PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE
            PSA_CIPHER_FINISH_OUTPUT_SIZE PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE

.. kdoc-extension:: /public/psa/crypto_values.h
   :macros: PSA_BLOCK_CIPHER_BLOCK_LENGTH

.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE
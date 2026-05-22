Asymmetric Signature
""""""""""""""""""""
Single Part
~~~~~~~~~~~
.. kdoc-extension:: /public/psa/crypto/sign.h
   :functions: psa_sign_message psa_verify_message psa_sign_hash psa_verify_hash

Multiple Part
~~~~~~~~~~~~~
There is no dedicated PSA asymmetric signature operation to perform multiple
part sequence. But as the multiple part signature generation or verification
consists in hashing the message, the multiple part sequence can be done by
first use a :ref:`hash multiple part <psa_hash_multipart>` operation and then
pass the hash to either :c:func:`psa_sign_hash` or :c:func:`psa_verify_hash`
to respectively generate or verify a message signature.

The :c:macro:`PSA_ALG_GET_HASH` can be used to determine the hash algorithm
to use.

Macros
~~~~~~
.. kdoc-extension:: /public/psa/crypto_sizes.h
   :macros: PSA_SIGN_OUTPUT_SIZE PSA_SIGNATURE_MAX_SIZE
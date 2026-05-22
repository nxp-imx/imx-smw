Attestation APIs
^^^^^^^^^^^^^^^^
Challenge sizes
"""""""""""""""
The following challenge sizes are supported.

.. table:: PSA initial attestation challenge sizes
   :name: table_psa_initial_attestion_challenge_sizes
   :align: center
   :class: wrap-table

   +--------------------------------------+-------------------+
   | **Name**                             | **Size in bytes** |
   +======================================+===================+
   | PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32 | 32                |
   +--------------------------------------+-------------------+
   | PSA_INITIAL_ATTEST_CHALLENGE_SIZE_48 | 48                |
   +--------------------------------------+-------------------+
   | PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 | 64                |
   +--------------------------------------+-------------------+

Token Attestation
"""""""""""""""""
Functions
~~~~~~~~~
.. kdoc-extension:: /public/psa/initial_attestation.h
   :functions: psa_initial_attest_get_token psa_initial_attest_get_token_size

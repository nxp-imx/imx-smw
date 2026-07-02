Key Types
^^^^^^^^^

SMW's PKCS#11 implementation supports the key types describes in this chapter.

Symmetric Keys
""""""""""""""
.. list-table:: Symmetric Key Types
   :header-rows: 1
   :name: p11_symmetric_key_types
   :widths: 30 70
   :class: wrap-table

   * - **Key Type**
     - **Description**
   * - CKK_AES
     - AES (Advanced Encryption Standard) keys
   * - CKK_DES
     - DES (Data Encryption Standard) keys
   * - CKK_DES3
     - Triple-length DES keys (3-key 3DES)
   * - CKK_GENERIC_SECRET
     - Generic secret keys for HMAC and other purposes

Asymmetric Keys
"""""""""""""""
.. list-table:: Asymmetric Key Types
   :header-rows: 1
   :name: p11_asymmetric_key_types
   :widths: 30 70
   :class: wrap-table

   * - **Key Type**
     - **Description**
   * - CKK_RSA
     - RSA public/private key pairs
   * - CKK_EC
     - Elliptic Curve public/private key pairs
   * - CKK_EC_EDWARDS
     - Edwards Curve keys (Ed25519, Ed448)
   * - CKK_EC_MONTGOMERY
     - Montgomery Curve keys (X25519, X448)
   * - CKK_DH
     - Diffie-Hellman key pairs

Key Management
^^^^^^^^^^^^^^

Key management in PKCS#11 provides comprehensive functions for generating,
deriving, wrapping, and unwrapping cryptographic keys. These operations are
essential for secure key lifecycle management.

SMW's PKCS#11 implementation supports key management operations that allow
applications to:\

  - Generate symmetric and asymmetric keys
  - Generate key pairs for public-key cryptography
  - Derive keys from existing keys or shared secrets
  - Wrap (encrypt) keys for secure transport
  - Unwrap (decrypt) keys received from external sources

All key management operations must be performed within the context of an active
session. Some operations may require specific session states or user
authentication.

Key Creation
""""""""""""
Symmetric Key Generation
~~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/key.c
   :functions: C_GenerateKey

Asymmetric Key Pair Generation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/key.c
   :functions: C_GenerateKeyPair

Key Derivation
""""""""""""""
.. kdoc-extension:: /pkcs11/src/key.c
   :functions: C_DeriveKey

Key Wrapping
""""""""""""
.. kdoc-extension:: /pkcs11/src/key.c
   :functions: C_WrapKey C_UnwrapKey

Key Exportation
"""""""""""""""
The key exportation functionality is not directly supported through a
dedicated API. The key value can be accessed through the
:c:func:`C_GetAttributeValue` function by querying the CKA_VALUE attribute,
provided the key object has the CKA_EXTRACTABLE attribute set to CK_TRUE.

Key Import
""""""""""
A key can be imported into the token through the :c:func:`C_CreateObject`
function. This allows applications to load pre-existing keys or keys generated
externally into the PKCS#11 token for use in cryptographic operations.

Key Deletion
""""""""""""
Keys can be deleted from the token using the :c:func:`C_DestroyObject`
function. This operation permanently removes the key object and its associated
attributes from the token storage.

Key Attributes
""""""""""""""
Key attributes define the properties and permissions of a key object. These
attributes can be set during key creation and queried at any time using
:c:func:`C_GetAttributeValue`.

The key attributes differs based on the type of the key object. For detailed
information on key attributes, refer to the PKCS#11 specification:

 - `PKCS#11 v2.40 <http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html>`_.
 - `PKCS#11 v3.2 <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/pkcs11-spec-v3.2-csd01.html>`_.


Examples
""""""""
Example 1: Generate AES Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <pkcs11.h>

   CK_RV generate_aes_key(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE *phKey)
   {
       CK_RV rv;
       CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
       CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
       CK_KEY_TYPE keyType = CKK_AES;
       CK_ULONG keyLen = 32; /* 256 bits */
       CK_BBOOL bTrue = CK_TRUE;
       CK_BBOOL bFalse = CK_FALSE;
       CK_UTF8CHAR label[] = "My AES Key";

       CK_ATTRIBUTE keyTemplate[] = {
           { CKA_CLASS, &keyClass, sizeof(keyClass) },
           { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
           { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
           { CKA_TOKEN, &bTrue, sizeof(bTrue) },
           { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
           { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
           { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
           { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
           { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
           { CKA_LABEL, label, sizeof(label) - 1 }
       };

       rv = C_GenerateKey(hSession, &mechanism, keyTemplate, 10, phKey);
       if (rv != CKR_OK) {
           printf("Failed to generate AES key: 0x%lx\n", rv);
           return rv;
       }

       printf("AES key generated successfully: %lu\n", *phKey);
       return CKR_OK;
   }

Example 2: Generate RSA Key Pair
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <pkcs11.h>

   CK_RV generate_rsa_keypair(CK_SESSION_HANDLE hSession,
                              CK_OBJECT_HANDLE *phPublicKey,
                              CK_OBJECT_HANDLE *phPrivateKey)
   {
       CK_RV rv;
       CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
       CK_ULONG modulusBits = 2048;
       CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 }; /* 65537 */
       CK_BBOOL bTrue = CK_TRUE;
       CK_BBOOL bFalse = CK_FALSE;
       CK_UTF8CHAR pubLabel[] = "My RSA Public Key";
       CK_UTF8CHAR privLabel[] = "My RSA Private Key";
       CK_BYTE id[] = { 0x01, 0x02, 0x03, 0x04 };

       CK_ATTRIBUTE publicKeyTemplate[] = {
           { CKA_TOKEN, &bTrue, sizeof(bTrue) },
           { CKA_PRIVATE, &bFalse, sizeof(bFalse) },
           { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
           { CKA_VERIFY, &bTrue, sizeof(bTrue) },
           { CKA_WRAP, &bTrue, sizeof(bTrue) },
           { CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
           { CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent) },
           { CKA_LABEL, pubLabel, sizeof(pubLabel) - 1 },
           { CKA_ID, id, sizeof(id) }
       };

       CK_ATTRIBUTE privateKeyTemplate[] = {
           { CKA_TOKEN, &bTrue, sizeof(bTrue) },
           { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
           { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
           { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
           { CKA_SIGN, &bTrue, sizeof(bTrue) },
           { CKA_UNWRAP, &bTrue, sizeof(bTrue) },
           { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
           { CKA_LABEL, privLabel, sizeof(privLabel) - 1 },
           { CKA_ID, id, sizeof(id) }
       };

       rv = C_GenerateKeyPair(hSession, &mechanism,
                              publicKeyTemplate, 9,
                              privateKeyTemplate, 8,
                              phPublicKey, phPrivateKey);
       if (rv != CKR_OK) {
           printf("Failed to generate RSA key pair: 0x%lx\n", rv);
           return rv;
       }

       printf("RSA key pair generated successfully\n");
       printf("  Public key: %lu\n", *phPublicKey);
       printf("  Private key: %lu\n", *phPrivateKey);
       return CKR_OK;
   }

Example 3: ECDH Key Derivation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <pkcs11.h>

   CK_RV derive_ecdh_key(CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hPrivateKey,
                         CK_BYTE_PTR pPublicData,
                         CK_ULONG ulPublicDataLen,
                         CK_OBJECT_HANDLE *phDerivedKey)
   {
       CK_RV rv;
       CK_ECDH1_DERIVE_PARAMS ecdhParams;
       CK_MECHANISM mechanism;
       CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
       CK_KEY_TYPE keyType = CKK_AES;
       CK_ULONG keyLen = 32; /* 256 bits */
       CK_BBOOL bTrue = CK_TRUE;
       CK_BBOOL bFalse = CK_FALSE;
       CK_UTF8CHAR label[] = "Derived AES Key";

       /* Setup ECDH parameters */
       ecdhParams.kdf = CKD_NULL;
       ecdhParams.ulSharedDataLen = 0;
       ecdhParams.pSharedData = NULL_PTR;
       ecdhParams.ulPublicDataLen = ulPublicDataLen;
       ecdhParams.pPublicData = pPublicData;

       mechanism.mechanism = CKM_ECDH1_DERIVE;
       mechanism.pParameter = &ecdhParams;
       mechanism.ulParameterLen = sizeof(ecdhParams);

       CK_ATTRIBUTE derivedKeyTemplate[] = {
           { CKA_CLASS, &keyClass, sizeof(keyClass) },
           { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
           { CKA_VALUE_LEN, &keyLen, sizeof(keyLen) },
           { CKA_TOKEN, &bFalse, sizeof(bFalse) },
           { CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
           { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
           { CKA_DECRYPT, &bTrue, sizeof(bTrue) },
           { CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
           { CKA_LABEL, label, sizeof(label) - 1 }
       };

       rv = C_DeriveKey(hSession, &mechanism, hPrivateKey,
                        derivedKeyTemplate, 9, phDerivedKey);
       if (rv != CKR_OK) {
           printf("Failed to derive key: 0x%lx\n", rv);
           return rv;
       }

       printf("Key derived successfully: %lu\n", *phDerivedKey);
       return CKR_OK;
   }

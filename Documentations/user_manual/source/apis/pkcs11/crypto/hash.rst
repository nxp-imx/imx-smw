Message digests (Hashes)
""""""""""""""""""""""""
The PKCS#11 library provides message digest (hash) operations through a set of
APIs that support both single-part and multi-part hashing.


 The sequence of operations to digest a message with a single part operation
 is as follows\:

    #. Initialize the operation by calling :c:func:`C_DigestInit`.
    #. Digest data in a single operation with the :c:func:`C_Digest`.

 The sequence of operations to digest a message with a multiple part operation
 is as follows\:

    #. Initialize the operation by calling :c:func:`C_DigestInit`.
    #. Process one or more data parts (can be called multiple times) with the
       :c:func:`C_DigestUpdate`.
    #. Finish the digest operation and obtain the digest value with the
       :c:func:`C_DigestFinal`.

Initialization
~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/digest.c
   :functions: C_DigestInit

Single Part
~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/digest.c
   :functions: C_Digest

Multiple Part
~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/digest.c
   :functions: C_DigestUpdate, C_DigestFinal

Example
~~~~~~~

Single-part digest
******************

.. code-block:: c

   CK_RV rv;
   CK_SESSION_HANDLE session;
   CK_MECHANISM mechanism = { CKM_SHA256, NULL, 0 };
   CK_BYTE data[] = "Hello, World!";
   CK_BYTE digest[32];
   CK_ULONG digest_len = sizeof(digest);

   // Initialize the digest operation
   rv = C_DigestInit(session, &mechanism);
   if (rv != CKR_OK) {
       // Handle error
   }

   // Perform single-part digest
   rv = C_Digest(session, data, sizeof(data) - 1, digest, &digest_len);
   if (rv != CKR_OK) {
       // Handle error
   }

Multi-part digest operation
***************************
.. code-block:: c

   CK_RV rv;
   CK_SESSION_HANDLE session;
   CK_MECHANISM mechanism = { CKM_SHA256, NULL, 0 };
   CK_BYTE data1[] = "Hello, ";
   CK_BYTE data2[] = "World!";
   CK_BYTE digest[32];
   CK_ULONG digest_len = sizeof(digest);

   // Initialize the digest operation
   rv = C_DigestInit(session, &mechanism);
   if (rv != CKR_OK) {
       // Handle error
   }

   // Update with first data part
   rv = C_DigestUpdate(session, data1, sizeof(data1) - 1);
   if (rv != CKR_OK) {
       // Handle error
   }

   // Update with second data part
   rv = C_DigestUpdate(session, data2, sizeof(data2) - 1);
   if (rv != CKR_OK) {
       // Handle error
   }

   // Finalize and get the digest
   rv = C_DigestFinal(session, digest, &digest_len);
   if (rv != CKR_OK) {
       // Handle error
   }

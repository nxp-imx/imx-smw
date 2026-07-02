Object Management
^^^^^^^^^^^^^^^^^

Object management in PKCS#11 provides comprehensive functions for creating,
searching, modifying, and destroying cryptographic objects. These operations are
essential for managing keys, certificates, and data objects throughout their
lifecycle.

SMW's PKCS#11 implementation supports object management operations that allow
applications to:

  - Create new objects with specified attributes.
  - Search for objects based on attribute criteria.
  - Retrieve and modify object attributes.
  - Copy existing objects.
  - Destroy objects when no longer needed.

All object management operations must be performed within the context of an
active session. Some operations may require specific session states or user
authentication depending on the object's attributes (e.g., private objects).

Object Creation and Destruction
"""""""""""""""""""""""""""""""
Create Object
~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_CreateObject

Copy Object
~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_CopyObject

Destroy Object
~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_DestroyObject

Object Search
"""""""""""""
Find Objects Initialize
~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_FindObjectsInit

Find Objects
~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_FindObjects

Find Objects Final
~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_FindObjectsFinal

Object Attributes
"""""""""""""""""
Get Attribute Value
~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_GetAttributeValue

Set Attribute Value
~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_SetAttributeValue

Get Object Size
~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/object.c
   :functions: C_GetObjectSize

Examples
""""""""
Example 1: Create Data Object
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <pkcs11.h>

   CK_RV create_data_object(CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE *phObject)
   {
       CK_RV rv;
       CK_OBJECT_CLASS objClass = CKO_DATA;
       CK_BBOOL bTrue = CK_TRUE;
       CK_BBOOL bFalse = CK_FALSE;
       CK_UTF8CHAR label[] = "My Data Object";
       CK_UTF8CHAR application[] = "My Application";
       CK_BYTE data[] = "This is my secret data";

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &objClass, sizeof(objClass) },
           { CKA_TOKEN, &bTrue, sizeof(bTrue) },
           { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
           { CKA_MODIFIABLE, &bTrue, sizeof(bTrue) },
           { CKA_LABEL, label, sizeof(label) - 1 },
           { CKA_APPLICATION, application, sizeof(application) - 1 },
           { CKA_VALUE, data, sizeof(data) - 1 }
       };

       rv = C_CreateObject(hSession, template, 7, phObject);
       if (rv != CKR_OK) {
           printf("Failed to create data object: 0x%lx\n", rv);
           return rv;
       }

       printf("Data object created successfully: %lu\n", *phObject);
       return CKR_OK;
   }

Example 2: Search for Objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <pkcs11.h>

   CK_RV find_aes_keys(CK_SESSION_HANDLE hSession)
   {
       CK_RV rv;
       CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
       CK_KEY_TYPE keyType = CKK_AES;
       CK_BBOOL bTrue = CK_TRUE;
       CK_OBJECT_HANDLE hObjects[10] = { 0 };
       CK_ULONG ulObjectCount = 0;
       CK_ULONG i = 0;

       CK_ATTRIBUTE template[] = {
           { CKA_CLASS, &keyClass, sizeof(keyClass) },
           { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
           { CKA_ENCRYPT, &bTrue, sizeof(bTrue) }
       };

       /* Initialize search */
       rv = C_FindObjectsInit(hSession, template, 3);
       if (rv != CKR_OK) {
           printf("Failed to initialize object search: 0x%lx\n", rv);
           return rv;
       }

       /* Find objects */
       rv = C_FindObjects(hSession, hObjects, 10, &ulObjectCount);
       if (rv != CKR_OK) {
           printf("Failed to find objects: 0x%lx\n", rv);
           C_FindObjectsFinal(hSession);
           return rv;
       }

       printf("Found %lu AES key(s):\n", ulObjectCount);
       for (i = 0; i < ulObjectCount; i++) {
           printf("  Object handle: %lu\n", hObjects[i]);
       }

       /* Finalize search */
       rv = C_FindObjectsFinal(hSession);
       if (rv != CKR_OK) {
           printf("Failed to finalize object search: 0x%lx\n", rv);
           return rv;
       }

       return CKR_OK;
   }

Example 3: Get and Set Object Attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <pkcs11.h>

   CK_RV modify_object_label(CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE hObject)
   {
       CK_RV rv;
       CK_UTF8CHAR oldLabel[256] = { 0 };
       CK_ULONG oldLabelLen = 0;
       CK_UTF8CHAR newLabel[] = "Updated Label";

       /* Get current label */
       CK_ATTRIBUTE getTemplate[] = {
           { CKA_LABEL, oldLabel, sizeof(oldLabel) }
       };

       rv = C_GetAttributeValue(hSession, hObject, getTemplate, 1);
       if (rv != CKR_OK) {
           printf("Failed to get object label: 0x%lx\n", rv);
           return rv;
       }

       oldLabelLen = getTemplate[0].ulValueLen;
       oldLabel[oldLabelLen] = '\0';
       printf("Current label: %s\n", oldLabel);

       /* Set new label */
       CK_ATTRIBUTE setTemplate[] = {
           { CKA_LABEL, newLabel, sizeof(newLabel) - 1 }
       };

       rv = C_SetAttributeValue(hSession, hObject, setTemplate, 1);
       if (rv != CKR_OK) {
           printf("Failed to set object label: 0x%lx\n", rv);
           return rv;
       }

       printf("Label updated to: %s\n", newLabel);
       return CKR_OK;
   }

Example 4: Destroy Object
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <pkcs11.h>

   CK_RV destroy_object(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE hObject)
   {
       CK_RV rv;

       rv = C_DestroyObject(hSession, hObject);
       if (rv != CKR_OK) {
           printf("Failed to destroy object: 0x%lx\n", rv);
           return rv;
       }

       printf("Object %lu destroyed successfully\n", hObject);
       return CKR_OK;
   }
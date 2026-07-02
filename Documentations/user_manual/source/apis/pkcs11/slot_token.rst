Slot and Token Management
^^^^^^^^^^^^^^^^^^^^^^^^^

Overview
""""""""
In PKCS#11, the concepts of **slots** and **tokens** are fundamental to
understanding how cryptographic devices are accessed and managed.

**What is a Slot?**

A **slot** is a logical reader that potentially contains a token. It represents
an interface to a cryptographic device, which is a connection point to the
Security Middleware Library exposing interface to any secure subsystem enabled
(refer to :ref:`Secure Subsystems Capabilities<subsystems-capabilities>`.

**What is a Token?**

A **token** is a logical view of a cryptographic device. It represents the
actual cryptographic resource that\:

  - Stores cryptographic keys and certificates
  - Performs cryptographic operations (encryption, decryption, signing,
    verification)
  - Maintains its own security state (initialized, user logged in, etc.)
  - Has its own storage for objects (keys, certificates, data)

A token can be either\:

  - The unique SMW device abstracting the Secure Subsystem(s)
  - Each Secure Subsystem exposed by the SMW device.

By default, only the SMW device token is available. However, compiling the
PKCS#11 library with the cmake option ``SMW_DEVICE_ONLY" set to ``OFF`` will
expose each Secure Subsystem as a separate token, allowing independent access
to each subsystem's capabilities and operations.

**Typical Workflow**

#. **Enumerate slots** to discover available cryptographic devices
#. **Query slot information** to determine if a token is present
#. **Access token** to retrieve its capabilities and state
#. **Initialize token** (if required) to prepare it for use
#. **Open session** with the token to perform cryptographic operations

Functions
"""""""""

Slot enumeration and information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/slot_token.c
   :functions: C_GetSlotList C_GetSlotInfo

Slot event
~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/slot_token.c
   :functions: C_WaitForSlotEvent

Mechanisms
~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/slot_token.c
   :functions: C_GetMechanismList

.. kdoc-extension:: /pkcs11/src/slot_token.c
   :functions: C_GetMechanismInfo

Token information and initialization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/slot_token.c
   :functions: C_GetTokenInfo C_InitToken

Token PIN management
~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/slot_token.c
   :functions: C_InitPIN C_SetPIN

Example
"""""""
The following example demonstrates how to enumerate slots, query token
information, and get the mechanisms list and information:

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <string.h>
   #include <pkcs11.h>

   static void print_slot_info(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo)
   {
       printf("\nSlot ID: %lu\n", slotID);
       printf("  Description: %.64s\n", pInfo->slotDescription);
       printf("  Manufacturer: %.32s\n", pInfo->manufacturerID);
       printf("  Flags: 0x%08lx\n", pInfo->flags);
       if (pInfo->flags & CKF_TOKEN_PRESENT)
           printf("    - Token present\n");
       if (pInfo->flags & CKF_REMOVABLE_DEVICE)
           printf("    - Removable device\n");
       if (pInfo->flags & CKF_HW_SLOT)
           printf("    - Hardware slot\n");
   }

   static void print_token_info(CK_TOKEN_INFO *pInfo)
   {
       printf("\nToken Information:\n");
       printf("  Label: %.32s\n", pInfo->label);
       printf("  Manufacturer: %.32s\n", pInfo->manufacturerID);
       printf("  Model: %.16s\n", pInfo->model);
       printf("  Serial Number: %.16s\n", pInfo->serialNumber);
       printf("  Flags: 0x%08lx\n", pInfo->flags);
       if (pInfo->flags & CKF_TOKEN_INITIALIZED)
           printf("    - Token initialized\n");
       if (pInfo->flags & CKF_WRITE_PROTECTED)
           printf("    - Write protected\n");
       if (pInfo->flags & CKF_USER_PIN_INITIALIZED)
           printf("    - User PIN initialized\n");
   }

   static void print_mechanism_info(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *pInfo)
   {
       printf("    Min key size: %lu bits\n", pInfo->ulMinKeySize);
       printf("    Max key size: %lu bits\n", pInfo->ulMaxKeySize);
       printf("    Flags: 0x%08lx\n", pInfo->flags);
       if (pInfo->flags & CKF_HW)
           printf("      - Hardware\n");
       if (pInfo->flags & CKF_ENCRYPT)
           printf("      - Encrypt\n");
       if (pInfo->flags & CKF_DECRYPT)
           printf("      - Decrypt\n");
       if (pInfo->flags & CKF_SIGN)
           printf("      - Sign\n");
       if (pInfo->flags & CKF_VERIFY)
           printf("      - Verify\n");
       if (pInfo->flags & CKF_GENERATE)
           printf("      - Generate\n");
       if (pInfo->flags & CKF_GENERATE_KEY_PAIR)
           printf("      - Generate key pair\n");
   }

   static const char *get_mechanism_name(CK_MECHANISM_TYPE type)
   {
       switch (type) {
       case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
       case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
       case CKM_AES_KEY_GEN: return "CKM_AES_KEY_GEN";
       case CKM_AES_CBC: return "CKM_AES_CBC";
       case CKM_AES_GCM: return "CKM_AES_GCM";
       case CKM_SHA256: return "CKM_SHA256";
       case CKM_SHA384: return "CKM_SHA384";
       case CKM_SHA512: return "CKM_SHA512";
       case CKM_ECDSA: return "CKM_ECDSA";
       case CKM_EC_KEY_PAIR_GEN: return "CKM_EC_KEY_PAIR_GEN";
       default: return "Unknown";
       }
   }

   int main(void)
   {
       CK_RV rv;
       CK_FUNCTION_LIST_PTR pFunctionList = NULL;
       CK_SLOT_ID_PTR pSlotList = NULL;
       CK_ULONG ulSlotCount = 0;
       CK_SLOT_INFO slotInfo = { 0 };
       CK_TOKEN_INFO tokenInfo = { 0 };
       CK_MECHANISM_TYPE_PTR pMechanismList = NULL;
       CK_ULONG ulMechCount = 0;
       CK_MECHANISM_INFO mechInfo = { 0 };
       CK_ULONG i = 0;
       CK_ULONG j = 0;

       /* Get function list */
       rv = C_GetFunctionList(&pFunctionList);
       if (rv != CKR_OK) {
           printf("C_GetFunctionList failed: 0x%08lx\n", rv);
           return 1;
       }

       /* Initialize PKCS#11 library */
       rv = pFunctionList->C_Initialize(NULL);
       if (rv != CKR_OK) {
           printf("C_Initialize failed: 0x%08lx\n", rv);
           return 1;
       }

       /* Get number of slots */
       rv = pFunctionList->C_GetSlotList(CK_TRUE, NULL, &ulSlotCount);
       if (rv != CKR_OK) {
           printf("C_GetSlotList (count) failed: 0x%08lx\n", rv);
           goto cleanup;
       }

       printf("Number of slots with tokens: %lu\n", ulSlotCount);

       if (ulSlotCount == 0) {
           printf("No slots with tokens found\n");
           goto cleanup;
       }

       /* Allocate memory for slot list */
       pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
       if (!pSlotList) {
           printf("Memory allocation failed\n");
           goto cleanup;
       }

       /* Get slot list */
       rv = pFunctionList->C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
       if (rv != CKR_OK) {
           printf("C_GetSlotList failed: 0x%08lx\n", rv);
           goto cleanup;
       }

       /* Iterate through each slot */
       for (i = 0; i < ulSlotCount; i++) {
           /* Get slot information */
           rv = pFunctionList->C_GetSlotInfo(pSlotList[i], &slotInfo);
           if (rv != CKR_OK) {
               printf("C_GetSlotInfo failed for slot %lu: 0x%08lx\n",
                      pSlotList[i], rv);
               continue;
           }

           print_slot_info(pSlotList[i], &slotInfo);

           /* Get token information */
           rv = pFunctionList->C_GetTokenInfo(pSlotList[i], &tokenInfo);
           if (rv != CKR_OK) {
               printf("C_GetTokenInfo failed for slot %lu: 0x%08lx\n",
                      pSlotList[i], rv);
               continue;
           }

           print_token_info(&tokenInfo);

           /* Get number of mechanisms */
           rv = pFunctionList->C_GetMechanismList(pSlotList[i], NULL, &ulMechCount);
           if (rv != CKR_OK) {
               printf("C_GetMechanismList (count) failed: 0x%08lx\n", rv);
               continue;
           }

           printf("\nNumber of mechanisms: %lu\n", ulMechCount);

           if (ulMechCount == 0)
               continue;

           /* Allocate memory for mechanism list */
           pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulMechCount *
                                                          sizeof(CK_MECHANISM_TYPE));
           if (!pMechanismList) {
               printf("Memory allocation failed for mechanisms\n");
               continue;
           }

           /* Get mechanism list */
           rv = pFunctionList->C_GetMechanismList(pSlotList[i], pMechanismList,
                                                  &ulMechCount);
           if (rv != CKR_OK) {
               printf("C_GetMechanismList failed: 0x%08lx\n", rv);
               free(pMechanismList);
               pMechanismList = NULL;
               continue;
           }

           /* Display each mechanism and its information */
           printf("\nSupported Mechanisms:\n");
           for (j = 0; j < ulMechCount; j++) {
               printf("  %s (0x%08lx)\n",
                      get_mechanism_name(pMechanismList[j]),
                      pMechanismList[j]);

               rv = pFunctionList->C_GetMechanismInfo(pSlotList[i],
                                                      pMechanismList[j],
                                                      &mechInfo);
               if (rv == CKR_OK) {
                   print_mechanism_info(pMechanismList[j], &mechInfo);
               } else {
                   printf("    C_GetMechanismInfo failed: 0x%08lx\n", rv);
               }
           }

           free(pMechanismList);
           pMechanismList = NULL;
       }

   cleanup:
       if (pMechanismList)
           free(pMechanismList);
       if (pSlotList)
           free(pSlotList);

       /* Finalize PKCS#11 library */
       pFunctionList->C_Finalize(NULL);

       return 0;
   }

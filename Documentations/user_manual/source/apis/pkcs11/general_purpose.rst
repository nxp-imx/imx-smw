General Purpose
^^^^^^^^^^^^^^^

The general purpose APIs allow users of the library to:

  - Initialize the library.
  - Finalize the library.
  - Get general information about the library.
  - Get the entry points of the library.
  - Get the list of available interface.

Before executing any PKCS#11 operation but :c:func:`C_GetInfo`,
:c:func:`C_GetFunctionList`, :c:func:`C_GetInterfaceList` and
:c:func:`C_GetInterface`, the library must be initialized by
the :c:func:`C_Initialize`. If this function is not called, any operation
will return the CKR_CRYPTOKI_NOT_INITIALIZED error.

To finish with the library usage, the application calls the :c:func:`C_Finalize`
to free all resources allocated during the library execution. Before calling
this function, the application must ensure that all operations are complete.

.. note::
   In the context of multiple applications using the library simultaneously,
   the C_Initialize() function must be called at least once before any
   cryptographic operations can be performed. The function is not required
   to be thread-safe, but the application is responsible for ensuring
   proper synchronization if C_Initialize() is called from multiple threads.
   Once initialized, the library remains active until C_Finalize() is called.

Library start/stop
""""""""""""""""""
Initialization
~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/entry.c
   :functions: C_Initialize

Deinitialization
~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/entry.c
   :functions: C_Finalize

General Information
"""""""""""""""""""
Get library information
~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/get_info.c
   :functions: C_GetInfo

Get library entry points
~~~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/get_info.c
   :functions: C_GetFunctionList

Get library interfaces
~~~~~~~~~~~~~~~~~~~~~~
.. kdoc-extension:: /pkcs11/src/get_info.c
  :functions: C_GetInterfaceList C_GetInterface

Example
"""""""
The following example demonstrates how to retrieve library information,
function entry points, and the list of available interfaces:

.. code-block:: c
   :linenos:

   #include <stdio.h>
   #include <pkcs11.h>

   int main(void)
   {
       CK_RV rv;
       CK_INFO info = { 0 };
       CK_FUNCTION_LIST_PTR pFunctionList = NULL;
       CK_INTERFACE_PTR pInterfacesList = NULL;
       CK_ULONG ulCount = 0;
       CK_ULONG i = 0;

       /* Get library information (can be called before C_Initialize) */
       rv = C_GetInfo(&info);
       if (rv != CKR_OK) {
           printf("C_GetInfo failed: 0x%08lX\n", rv);
           return 1;
       }

       printf("Library Information:\n");
       printf("  Cryptoki Version: %d.%d\n",
              info.cryptokiVersion.major, info.cryptokiVersion.minor);
       printf("  Manufacturer ID: %.32s\n", info.manufacturerID);
       printf("  Library Description: %.32s\n", info.libraryDescription);
       printf("  Library Version: %d.%d\n",
              info.libraryVersion.major, info.libraryVersion.minor);

       /* Get function list (can be called before C_Initialize) */
       rv = C_GetFunctionList(&pFunctionList);
       if (rv != CKR_OK) {
           printf("C_GetFunctionList failed: 0x%08lX\n", rv);
           return 1;
       }

       printf("\nFunction List Version: %d.%d\n",
              pFunctionList->version.major, pFunctionList->version.minor);

       /* Get number of interfaces */
       rv = C_GetInterfaceList(NULL, &ulCount);
       if (rv != CKR_OK) {
           printf("C_GetInterfaceList failed: 0x%08lX\n", rv);
           return 1;
       }

       printf("\nNumber of interfaces: %lu\n", ulCount);

       /* Allocate memory for interface list */
       pInterfacesList = malloc(ulCount * sizeof(CK_INTERFACE));
       if (!pInterfacesList) {
           printf("Memory allocation failed\n");
           return 1;
       }

       /* Get interface list */
       rv = C_GetInterfaceList(pInterfacesList, &ulCount);
       if (rv != CKR_OK) {
           printf("C_GetInterfaceList failed: 0x%08lX\n", rv);
           free(pInterfacesList);
           return 1;
       }

       /* Display available interfaces */
       printf("\nAvailable Interfaces:\n");
       for (i = 0; i < ulCount; i++) {
           CK_FUNCTION_LIST_PTR pFuncList =
               (CK_FUNCTION_LIST_PTR)pInterfacesList[i].pFunctionList;
           printf("  Interface %lu:\n", i);
           printf("    Name: %s\n", pInterfacesList[i].pInterfaceName);
           printf("    Version: %d.%d\n",
                  pFuncList->version.major, pFuncList->version.minor);
           printf("    Flags: 0x%lX\n", pInterfacesList[i].flags);
       }

       free(pInterfacesList);

       /* Get a specific interface (PKCS#11 v3.2) */
       CK_VERSION version = { 3, 2 };
       CK_INTERFACE_PTR pInterface = NULL;

       rv = C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11", &version,
                           &pInterface, 0);
       if (rv == CKR_OK) {
           printf("\nRequested PKCS#11 v3.2 interface found\n");
       } else {
           printf("\nPKCS#11 v3.2 interface not available\n");
       }

       return 0;
   }

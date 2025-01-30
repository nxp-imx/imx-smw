// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "local.h"
#include "os_mutex.h"
#include "util_session.h"

#define ISSUER_LEN 4
#define CERT_LEN   6
#define ID_LEN	   2

static int create_cert_bad_param(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_UTF8CHAR label[] = "Certificate";
	CK_BYTE cert[] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE subject[] = { 0x74, 0x65, 0x73, 0x74 };
	CK_BYTE retrieved_cert[6] = { 0 };
	CK_ATTRIBUTE create_template[] = {
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, cert, sizeof(cert) },
		{ CKA_SUBJECT, subject, sizeof(subject) },
	};
	CK_ATTRIBUTE retrieve_template[] = { { CKA_VALUE, retrieved_cert,
					       sizeof(retrieved_cert) } };

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Check session NULL\n");
	ret = pfunc->C_CreateObject(0, create_template,
				    ARRAY_SIZE(create_template), &cert_handle);
	if (CHECK_CK_RV(CKR_SESSION_HANDLE_INVALID, "C_CreateObject"))
		goto end;

	TEST_OUT("Check certificate buffer pointer NULL\n");
	create_template[3].pValue = NULL_PTR;
	ret = pfunc->C_CreateObject(sess, create_template,
				    ARRAY_SIZE(create_template), &cert_handle);
	if (CHECK_CK_RV(CKR_ATTRIBUTE_VALUE_INVALID, "C_CreateObject"))
		goto end;

	TEST_OUT("Check certificate buffer length 0\n");
	create_template[3].pValue = cert;
	create_template[3].ulValueLen = 0;
	ret = pfunc->C_CreateObject(sess, create_template,
				    ARRAY_SIZE(create_template), &cert_handle);
	if (CHECK_CK_RV(CKR_ATTRIBUTE_VALUE_INVALID, "C_CreateObject"))
		goto end;

	TEST_OUT("Create session certificate object\n");
	create_template[3].ulValueLen = sizeof(cert);
	ret = pfunc->C_CreateObject(sess, create_template,
				    ARRAY_SIZE(create_template), &cert_handle);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Retrieve certificate, buffer too small\n");
	retrieve_template[0].ulValueLen = 0;
	ret = pfunc->C_GetAttributeValue(sess, cert_handle, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_BUFFER_TOO_SMALL, "C_GetAttributeValue"))
		goto end;

	if (retrieve_template[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
		TEST_OUT("Wrong certificate length: got %ld, expected %ld\n",
			 retrieve_template[0].ulValueLen,
			 CK_UNAVAILABLE_INFORMATION);
		goto end;
	}

	TEST_OUT("Retrieve certificate, pointer NULL\n");
	retrieve_template[0].pValue = NULL_PTR;
	ret = pfunc->C_GetAttributeValue(sess, cert_handle, retrieve_template,
					 ARRAY_SIZE(retrieve_template));
	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (retrieve_template[0].ulValueLen != sizeof(cert)) {
		TEST_OUT("Wrong certificate length: got %ld, expected %ld\n",
			 retrieve_template[0].ulValueLen,
			 (unsigned long)sizeof(cert));
		goto end;
	}

	TEST_OUT("Destroy Certificate\n");
	ret = pfunc->C_DestroyObject(sess, cert_handle);
	if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int create_cert_bad_attr(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_BBOOL token = CK_FALSE;
	CK_UTF8CHAR label[] = "Certificate";
	CK_UTF8CHAR url[] = "pkcs11:token=MyToken;object=MyCert;type=cert";
	CK_BYTE cert[] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE subject[] = { 0x74, 0x65, 0x73, 0x74 };
	CK_ATTRIBUTE cert_template_1[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_SUBJECT, subject, sizeof(subject) },
		{ CKA_VALUE, cert, sizeof(cert) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
		{ CKA_TOKEN, &token, sizeof(token) }
	};

	CK_ATTRIBUTE cert_template_2[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_SUBJECT, subject, sizeof(subject) },
		{ CKA_URL, NULL_PTR, 0 }
	};

	CK_ATTRIBUTE cert_template_3[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_VALUE, cert, sizeof(cert) }
	};

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("CKA_CERTIFICATE_TYPE is not present in object's template.\n");
	ret = pfunc->C_CreateObject(sess, cert_template_1,
				    ARRAY_SIZE(cert_template_1) - 2,
				    &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	TEST_OUT("Create token certificate object.\n");
	token = CK_TRUE;
	ret = pfunc->C_CreateObject(sess, cert_template_1,
				    ARRAY_SIZE(cert_template_1), &cert_handle);
	if (CHECK_CK_RV(CKR_FUNCTION_NOT_SUPPORTED, "C_CreateObject"))
		goto end;

	cert_template_1[3].ulValueLen = 0;
	cert_template_1[3].pValue = NULL_PTR;

	TEST_OUT("CKA_VALUE is empty.\n");
	ret = pfunc->C_CreateObject(sess, cert_template_1,
				    ARRAY_SIZE(cert_template_1) - 1,
				    &cert_handle);
	if (CHECK_CK_RV(CKR_ATTRIBUTE_VALUE_INVALID, "C_CreateObject"))
		goto end;

	TEST_OUT("CKA_VALUE and CKA_URL are not present in object's temp\n");
	ret = pfunc->C_CreateObject(sess, cert_template_2,
				    ARRAY_SIZE(cert_template_2) - 1,
				    &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	cert_template_2[4].ulValueLen = sizeof(url);
	cert_template_2[4].pValue = url;

	/*
	 * CKA_HASH_OF_ISSUER_PUBLIC_KEY and CKA_HASH_OF_SUBJECT_PUBLIC_KEY both are
	 * not present in object's template, while CKA_URL is present.
	 */
	TEST_OUT("Required attributes are absent in object's template.\n");
	ret = pfunc->C_CreateObject(sess, cert_template_2,
				    ARRAY_SIZE(cert_template_2), &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	TEST_OUT("Attribute check for CKC_WTLS certificate type.\n");

	cert_type = CKC_WTLS;

	TEST_OUT("Both CKA_VALUE and CKA_URL are not present.\n");
	ret = pfunc->C_CreateObject(sess, cert_template_2,
				    ARRAY_SIZE(cert_template_2) - 1,
				    &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	/*
	 * CKA_HASH_OF_ISSUER_PUBLIC_KEY and CKA_HASH_OF_SUBJECT_PUBLIC_KEY both are
	 * not present in object's template, while CKA_URL is present.
	 */
	TEST_OUT("Required attributes are absent in object's template.\n");
	ret = pfunc->C_CreateObject(sess, cert_template_2,
				    ARRAY_SIZE(cert_template_2), &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	TEST_OUT("CKA_VALUE is present but, CKA_SUBJECT is not present\n");
	ret = pfunc->C_CreateObject(sess, cert_template_3,
				    ARRAY_SIZE(cert_template_3), &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	TEST_OUT("Attribute check for CKC_X_509_ATTR_CERT certificate type.\n");

	cert_type = CKC_X_509_ATTR_CERT;

	TEST_OUT("CKA_VALUE is not present in the object's template.\n");
	ret = pfunc->C_CreateObject(sess, cert_template_2,
				    ARRAY_SIZE(cert_template_2), &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	TEST_OUT("CKA_OWNER is not present in the object's template.\n");
	ret = pfunc->C_CreateObject(sess, cert_template_3,
				    ARRAY_SIZE(cert_template_3), &cert_handle);
	if (CHECK_CK_RV(CKR_TEMPLATE_INCOMPLETE, "C_CreateObject"))
		goto end;

	status = TEST_PASS;

end:
	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int compare_attribute_value(CK_FUNCTION_LIST_PTR pfunc,
				   CK_SESSION_HANDLE sess,
				   CK_OBJECT_HANDLE obj_handle,
				   CK_BYTE_PTR cert, CK_BYTE_PTR issuer,
				   CK_BYTE_PTR id,
				   CK_CERTIFICATE_TYPE cert_type)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;

	CK_BYTE retrieved_cert[CERT_LEN] = { 0 };
	CK_BYTE retrieved_issuer[ISSUER_LEN] = { 0 };
	CK_BYTE retrieved_id[ID_LEN] = { 0 };

	CK_ATTRIBUTE retrieve_template[] = {
		{ CKA_VALUE, retrieved_cert, sizeof(retrieved_cert) },
		{ CKA_ISSUER, retrieved_issuer, sizeof(retrieved_issuer) },
		{ CKA_ID, retrieved_id, sizeof(retrieved_id) },
	};

	switch (cert_type) {
	case CKC_X_509:
		ret = pfunc->C_GetAttributeValue(sess, obj_handle,
						 retrieve_template,
						 ARRAY_SIZE(retrieve_template));
		break;

	case CKC_WTLS:
		/* Retrieve CKA_VALUE AND CKA_ISSUER */
		ret = pfunc->C_GetAttributeValue(sess, obj_handle,
						 retrieve_template,
						 ARRAY_SIZE(retrieve_template) -
							 1);
		break;

	case CKC_X_509_ATTR_CERT:
		retrieve_template[1].type = CKA_AC_ISSUER;
		/* Retrieve CKA_VALUE AND CKA_AC_ISSUER */
		ret = pfunc->C_GetAttributeValue(sess, obj_handle,
						 retrieve_template,
						 ARRAY_SIZE(retrieve_template) -
							 1);
		break;

	default:
		TEST_OUT("Invalid certificate type.\n");
		goto end;
	}

	if (CHECK_CK_RV(CKR_OK, "C_GetAttributeValue"))
		goto end;

	if (!util_compare_buffers(cert, CERT_LEN, retrieve_template[0].pValue,
				  retrieve_template[0].ulValueLen)) {
		TEST_OUT("Retrieved certificate is not the same\n");
		goto end;
	}

	if (!util_compare_buffers(issuer, ISSUER_LEN,
				  retrieve_template[1].pValue,
				  retrieve_template[1].ulValueLen)) {
		TEST_OUT("Retrieved issuer is not the same\n");
		goto end;
	}

	if (cert_type == CKC_X_509) {
		if (!util_compare_buffers(id, ID_LEN,
					  retrieve_template[2].pValue,
					  retrieve_template[2].ulValueLen)) {
			TEST_OUT("Retrieved ID is not the same\n");
			goto end;
		}
	}

	status = TEST_PASS;

end:
	return status;
}

static int get_cert_size(CK_FUNCTION_LIST_PTR pfunc, CK_SESSION_HANDLE sess,
			 CK_OBJECT_HANDLE cert_handle)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;

	CK_ULONG cert_size = 0;

	TEST_OUT("Get certificate's size.\n");
	ret = pfunc->C_GetObjectSize(sess, cert_handle, &cert_size);
	if (CHECK_CK_RV(CKR_OK, "C_GetObjectSize"))
		goto end;

	if (CHECK_EXPECTED(cert_size == CERT_LEN,
			   "Got %lu but expected %d object", cert_size,
			   CERT_LEN))
		goto end;

	status = TEST_PASS;

end:
	return status;
}

static int test_x509_cert_obj(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE obj_handle = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_UTF8CHAR label[] = "A certificate object";
	CK_BYTE subject[] = { 0x74, 0x65, 0x73, 0x74 };
	CK_BYTE cert[CERT_LEN] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE issuer[ISSUER_LEN] = { 0x4E, 0x58, 0x50, 0x45 };
	CK_BYTE id[ID_LEN] = { 0xF0, 0xFD };

	CK_ATTRIBUTE create_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_SUBJECT, subject, sizeof(subject) },
		{ CKA_VALUE, cert, sizeof(cert) },
		{ CKA_ISSUER, &issuer, sizeof(issuer) },
		{ CKA_ID, id, sizeof(id) }
	};

	CK_ATTRIBUTE find_cert_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
	};

	CK_ATTRIBUTE set_attr_template[] = { { CKA_ISSUER, &issuer,
					       sizeof(issuer) },
					     { CKA_ID, &id, sizeof(id) } };

	CK_ULONG nb_match = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Create session certificate object.\n");
	ret = pfunc->C_CreateObject(sess, create_template,
				    ARRAY_SIZE(create_template), &obj_handle);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Find certificate objects\n");
	ret = pfunc->C_FindObjectsInit(sess, find_cert_template,
				       ARRAY_SIZE(find_cert_template));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &cert_handle, 10, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	TEST_OUT("Retrieve certificate attributes value.\n");
	if (compare_attribute_value(pfunc, sess, cert_handle, cert, issuer, id,
				    cert_type) == TEST_FAIL)
		goto end;

	memset(issuer, 0x11, sizeof(issuer));
	memset(id, 0xFF, sizeof(id));

	TEST_OUT("Set certificate object attribute value.\n");
	ret = pfunc->C_SetAttributeValue(sess, cert_handle, set_attr_template,
					 ARRAY_SIZE(set_attr_template));
	if (CHECK_CK_RV(CKR_OK, "C_SetAttributeValue"))
		goto end;

	if (compare_attribute_value(pfunc, sess, cert_handle, cert, issuer, id,
				    cert_type) == TEST_FAIL)
		goto end;

	if (get_cert_size(pfunc, sess, cert_handle) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	if (obj_handle != CK_INVALID_HANDLE) {
		TEST_OUT("Destroy Certificate\n");
		ret = pfunc->C_DestroyObject(sess, obj_handle);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int test_wtls_cert_obj(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE obj_handle = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_WTLS;
	CK_UTF8CHAR label[] = "A certificate object";
	CK_BYTE subject[] = { 0x74, 0x65, 0x73, 0x74 };
	CK_BYTE cert[CERT_LEN] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x20 };
	CK_BYTE issuer[ISSUER_LEN] = { 0x4E, 0x58, 0x50, 0x78 };

	CK_ATTRIBUTE create_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_SUBJECT, subject, sizeof(subject) },
		{ CKA_ISSUER, issuer, sizeof(issuer) },
		{ CKA_VALUE, cert, sizeof(cert) }
	};

	CK_ATTRIBUTE find_cert_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
	};

	CK_ATTRIBUTE set_attr_template[] = { { CKA_ISSUER, issuer,
					       sizeof(issuer) } };

	CK_ULONG nb_match = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Create session certificate object.\n");
	ret = pfunc->C_CreateObject(sess, create_template,
				    ARRAY_SIZE(create_template), &obj_handle);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Find certificate objects\n");
	ret = pfunc->C_FindObjectsInit(sess, find_cert_template,
				       ARRAY_SIZE(find_cert_template));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &cert_handle, 10, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	TEST_OUT("Retrieve certificate object attribute value.\n");
	if (compare_attribute_value(pfunc, sess, cert_handle, cert, issuer,
				    NULL, cert_type) == TEST_FAIL)
		goto end;

	memset(issuer, 0x11, sizeof(issuer));

	TEST_OUT("Set certificate attribute value.\n");
	ret = pfunc->C_SetAttributeValue(sess, cert_handle, set_attr_template,
					 ARRAY_SIZE(set_attr_template));
	if (CHECK_CK_RV(CKR_OK, "C_SetAttributeValue"))
		goto end;

	TEST_OUT("Retrieve certificate object attribute value.\n");
	if (compare_attribute_value(pfunc, sess, cert_handle, cert, issuer,
				    NULL, cert_type) == TEST_FAIL)
		goto end;

	if (get_cert_size(pfunc, sess, cert_handle) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	if (obj_handle != CK_INVALID_HANDLE) {
		TEST_OUT("Destroy Certificate\n");
		ret = pfunc->C_DestroyObject(sess, obj_handle);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

static int test_x509_attr_cert_obj(CK_FUNCTION_LIST_PTR pfunc)
{
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_SESSION_HANDLE sess = 0;
	CK_OBJECT_HANDLE obj_handle = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509_ATTR_CERT;
	CK_UTF8CHAR label[] = "A certificate object";
	CK_BYTE owner[] = { 0x4E, 0x58, 0x50 };
	CK_BYTE cert[CERT_LEN] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	CK_BYTE ac_issuer[ISSUER_LEN] = { 0x74, 0x65, 0x73, 0x86 };

	CK_ATTRIBUTE create_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
		{ CKA_LABEL, label, sizeof(label) - 1 },
		{ CKA_AC_ISSUER, ac_issuer, sizeof(ac_issuer) },
		{ CKA_OWNER, owner, sizeof(owner) },
		{ CKA_VALUE, cert, sizeof(cert) }
	};

	CK_ATTRIBUTE find_cert_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type) },
	};

	CK_ATTRIBUTE set_attr_template[] = { { CKA_AC_ISSUER, ac_issuer,
					       sizeof(ac_issuer) } };

	CK_ULONG nb_match = 0;

	SUBTEST_START();

	if (util_open_rw_session(pfunc, 0, &sess) == TEST_FAIL)
		goto end;

	TEST_OUT("Create session certificate object.\n");
	ret = pfunc->C_CreateObject(sess, create_template,
				    ARRAY_SIZE(create_template), &obj_handle);
	if (CHECK_CK_RV(CKR_OK, "C_CreateObject"))
		goto end;

	TEST_OUT("Find certificate objects\n");
	ret = pfunc->C_FindObjectsInit(sess, find_cert_template,
				       ARRAY_SIZE(find_cert_template));
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsInit"))
		goto end;

	ret = pfunc->C_FindObjects(sess, &cert_handle, 10, &nb_match);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjects"))
		goto end;

	if (CHECK_EXPECTED(nb_match == 1, "Got %lu but expected one object",
			   nb_match))
		goto end;

	ret = pfunc->C_FindObjectsFinal(sess);
	if (CHECK_CK_RV(CKR_OK, "C_FindObjectsFinal"))
		goto end;

	TEST_OUT("Retrieve certificate attributes value.\n");
	if (compare_attribute_value(pfunc, sess, cert_handle, cert, ac_issuer,
				    NULL, cert_type) == TEST_FAIL)
		goto end;

	memset(ac_issuer, 0xAA, sizeof(ac_issuer));

	TEST_OUT("Set certificate attribute value.\n");
	ret = pfunc->C_SetAttributeValue(sess, cert_handle, set_attr_template,
					 ARRAY_SIZE(set_attr_template));
	if (CHECK_CK_RV(CKR_OK, "C_SetAttributeValue"))
		goto end;

	TEST_OUT("Retrieve certificate object attribute value.\n");
	if (compare_attribute_value(pfunc, sess, cert_handle, cert, ac_issuer,
				    NULL, cert_type) == TEST_FAIL)
		goto end;

	if (get_cert_size(pfunc, sess, cert_handle) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	if (obj_handle != CK_INVALID_HANDLE) {
		TEST_OUT("Destroy Certificate\n");
		ret = pfunc->C_DestroyObject(sess, obj_handle);
		if (CHECK_CK_RV(CKR_OK, "C_DestroyObject"))
			status = TEST_FAIL;
	}

	util_close_session(pfunc, &sess);

	SUBTEST_END(status);
	return status;
}

void tests_pkcs11_object_cert(void *lib_hdl, CK_VOID_PTR pfunc)
{
	(void)lib_hdl;
	int status = TEST_FAIL;

	CK_RV ret = CKR_OK;
	CK_C_INITIALIZE_ARGS init = { 0 };

	init.CreateMutex = mutex_create;
	init.DestroyMutex = mutex_destroy;
	init.LockMutex = mutex_lock;
	init.UnlockMutex = mutex_unlock;

	TEST_START();

	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Initialize(&init);
	if (CHECK_CK_RV(CKR_OK, "C_Initialize"))
		goto end;

	if (create_cert_bad_param(pfunc) == TEST_FAIL)
		goto end;

	if (create_cert_bad_attr(pfunc) == TEST_FAIL)
		goto end;

	if (test_x509_cert_obj(pfunc) == TEST_FAIL)
		goto end;

	if (test_wtls_cert_obj(pfunc) == TEST_FAIL)
		goto end;

	if (test_x509_attr_cert_obj(pfunc) == TEST_FAIL)
		goto end;

	status = TEST_PASS;

end:
	ret = ((CK_FUNCTION_LIST_PTR)pfunc)->C_Finalize(NULL_PTR);
	if (CHECK_CK_RV(CKR_OK, "C_Finalize"))
		status = TEST_FAIL;

	TEST_END(status);
}

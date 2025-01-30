// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>
#include <limits.h>

#include "attributes.h"
#include "cert.h"

#include "lib_device.h"
#include "lib_session.h"
#include "lib_object.h"
#include "libobj_types.h"
#include "util.h"

#include "trace.h"

enum attr_cert_common_list {
	CERT_TYPE = 0,
	CERT_TRUSTED,
	CERT_CATEGORY,
	CERT_CHECK_VALUE,
	CERT_START_DATE,
	CERT_END_DATE,
	CERT_PUB_KEY_INFO
};

const struct template_attr attr_cert_common[] = {
	[CERT_TYPE] = TATTR(cert, type, CERTIFICATE_TYPE,
			    sizeof(CK_CERTIFICATE_TYPE), MUST, ulong),
	[CERT_TRUSTED] = TATTR(cert, trusted, TRUSTED, sizeof(CK_BBOOL),
			       OPTIONAL, boolean),
	[CERT_CATEGORY] =
		TATTR(cert, cat, CERTIFICATE_CATEGORY,
		      sizeof(CK_CERTIFICATE_TYPE), OPTIONAL, byte_array),
	[CERT_CHECK_VALUE] =
		TATTR(cert, checksum, CHECK_VALUE, 0, OPTIONAL, byte_array),
	[CERT_START_DATE] = TATTR_M(cert, start_date, START_DATE,
				    sizeof(CK_DATE), OPTIONAL, date),
	[CERT_END_DATE] = TATTR_M(cert, end_date, END_DATE, sizeof(CK_DATE),
				  OPTIONAL, date),
	[CERT_PUB_KEY_INFO] = TATTR(cert, pub_key_info, PUBLIC_KEY_INFO, 0,
				    OPTIONAL, byte_array),
};

enum attr_x_509_cert_list {
	X_509_SUBJECT = 0,
	X_509_ID,
	X_509_ISSUER,
	X_509_SER_NUM,
	X_509_VALUE,
	X_509_URL,
	X_509_SPK_HASH,
	X_509_ISP_HASH,
	X_509_JAVA_MIDP_SEC_DOMAIN,
	X_509_HASH_ALGO
};

const struct template_attr attr_x_509_cert[] = {
	[X_509_SUBJECT] =
		TATTR(x_509_cert, subject, SUBJECT, 0, MUST, byte_array),
	[X_509_ID] = TATTR_M(x_509_cert, id, ID, 0, OPTIONAL, byte_array),
	[X_509_ISSUER] =
		TATTR_M(x_509_cert, issuer, ISSUER, 0, OPTIONAL, byte_array),
	[X_509_SER_NUM] = TATTR_M(x_509_cert, ser_num, SERIAL_NUMBER, 0,
				  OPTIONAL, byte_array),
	[X_509_VALUE] =
		TATTR(x_509_cert, value, VALUE, 0, OPTIONAL, byte_array),
	[X_509_URL] = TATTR(x_509_cert, url, URL, 0, OPTIONAL, rfc2279),
	[X_509_SPK_HASH] =
		TATTR(x_509_cert, spk_hash, HASH_OF_SUBJECT_PUBLIC_KEY, 0,
		      OPTIONAL, byte_array),
	[X_509_ISP_HASH] =
		TATTR(x_509_cert, ipk_hash, HASH_OF_ISSUER_PUBLIC_KEY, 0,
		      OPTIONAL, byte_array),
	[X_509_JAVA_MIDP_SEC_DOMAIN] =
		TATTR(x_509_cert, sec_domain, JAVA_MIDP_SECURITY_DOMAIN, 0,
		      OPTIONAL, ulong),
	[X_509_HASH_ALGO] = TATTR(x_509_cert, mech, NAME_HASH_ALGORITHM,
				  sizeof(CK_MECHANISM_TYPE), OPTIONAL, ulong)
};

enum attr_wtls_cert_list {
	WTLS_SUBJECT = 0,
	WTLS_ISSUER,
	WTLS_VALUE,
	WTLS_URL,
	WTLS_SPK_HASH,
	WTLS_ISP_HASH,
	WTLS_HASH_ALGO
};

const struct template_attr attr_wtls_cert[] = {
	[WTLS_SUBJECT] =
		TATTR(wtls_cert, subject, SUBJECT, 0, OPTIONAL, byte_array),
	[WTLS_ISSUER] =
		TATTR_M(wtls_cert, issuer, ISSUER, 0, OPTIONAL, byte_array),
	[WTLS_VALUE] = TATTR(wtls_cert, value, VALUE, 0, OPTIONAL, byte_array),
	[WTLS_URL] = TATTR(wtls_cert, url, URL, 0, OPTIONAL, rfc2279),
	[WTLS_SPK_HASH] = TATTR(wtls_cert, spk_hash, HASH_OF_SUBJECT_PUBLIC_KEY,
				0, OPTIONAL, byte_array),
	[WTLS_ISP_HASH] = TATTR(wtls_cert, ipk_hash, HASH_OF_ISSUER_PUBLIC_KEY,
				0, OPTIONAL, byte_array),
	[WTLS_HASH_ALGO] = TATTR(wtls_cert, mech, NAME_HASH_ALGORITHM,
				 sizeof(CK_MECHANISM_TYPE), OPTIONAL, ulong)
};

enum attr_x_509_attr_cert_list {
	X_509_ATTR_OWNER = 0,
	X_509_ATTR_ISSUER,
	X_509_ATTR_SER_NUM,
	X_509_ATTR_TYPES,
	X_509_ATTR_VALUE
};

const struct template_attr attr_x_509_attr_cert[] = {
	[X_509_ATTR_OWNER] =
		TATTR(x_509_attr_cert, owner, OWNER, 0, MUST, byte_array),
	[X_509_ATTR_ISSUER] = TATTR_M(x_509_attr_cert, issuer, AC_ISSUER, 0,
				      OPTIONAL, byte_array),
	[X_509_ATTR_SER_NUM] = TATTR_M(x_509_attr_cert, ser_num, SERIAL_NUMBER,
				       0, OPTIONAL, byte_array),
	[X_509_ATTR_TYPES] = TATTR_M(x_509_attr_cert, attr_types, ATTR_TYPES, 0,
				     OPTIONAL, byte_array),
	[X_509_ATTR_VALUE] =
		TATTR(x_509_attr_cert, value, VALUE, 0, MUST, byte_array)
};

static struct libobj_cert *cert_allocate(struct libobj_obj *obj)
{
	struct libobj_cert *cert = NULL;

	cert = calloc(1, sizeof(*cert));
	if (cert)
		set_subobj_to(obj, storage, cert);

	DBG_TRACE("Allocated a new cert object (%p)", cert);
	return cert;
}

static void x_509_cert_free(struct libobj_obj *obj)
{
	struct libobj_x_509_cert *cert = get_cert_from(obj);

	if (!cert)
		return;

	DBG_TRACE("Free X.509 public key certificate (%p)", cert);

	if (cert->subject.array)
		free(cert->subject.array);

	if (cert->id.array)
		free(cert->id.array);

	if (cert->issuer.array)
		free(cert->issuer.array);

	if (cert->ser_num.array)
		free(cert->ser_num.array);

	if (cert->value.array)
		free(cert->value.array);

	if (cert->url.string)
		free(cert->url.string);

	if (cert->spk_hash.array)
		free(cert->spk_hash.array);

	if (cert->ipk_hash.array)
		free(cert->ipk_hash.array);

	free(cert);
	set_cert_to(obj, NULL);
}

static void wtls_cert_free(struct libobj_obj *obj)
{
	struct libobj_wtls_cert *cert = get_cert_from(obj);

	if (!cert)
		return;

	DBG_TRACE("Free WTLS public key certificate (%p)", cert);

	if (cert->subject.array)
		free(cert->subject.array);

	if (cert->issuer.array)
		free(cert->issuer.array);

	if (cert->value.array)
		free(cert->value.array);

	if (cert->url.string)
		free(cert->url.string);

	if (cert->spk_hash.array)
		free(cert->spk_hash.array);

	if (cert->ipk_hash.array)
		free(cert->ipk_hash.array);

	free(cert);
	set_cert_to(obj, NULL);
}

static void x_509_attr_cert_free(struct libobj_obj *obj)
{
	struct libobj_x_509_attr_cert *cert = get_cert_from(obj);

	if (!cert)
		return;

	DBG_TRACE("Free X.509 attribute certificate (%p)", cert);

	if (cert->owner.array)
		free(cert->owner.array);

	if (cert->issuer.array)
		free(cert->issuer.array);

	if (cert->ser_num.array)
		free(cert->ser_num.array);

	if (cert->attr_types.array)
		free(cert->attr_types.array);

	if (cert->value.array)
		free(cert->value.array);

	free(cert);
	set_cert_to(obj, NULL);
}

void cert_free(struct libobj_obj *obj)
{
	struct libobj_cert *cert = get_subobj_from(obj, storage);

	DBG_TRACE("Free certificate object (%p)", cert);

	if (!cert)
		return;

	if (cert->checksum.array)
		free(cert->checksum.array);

	if (cert->pub_key_info.array)
		free(cert->pub_key_info.array);

	switch (get_cert_type(obj)) {
	case CKC_X_509:
		x_509_cert_free(obj);
		break;

	case CKC_WTLS:
		wtls_cert_free(obj);
		break;

	case CKC_X_509_ATTR_CERT:
		x_509_attr_cert_free(obj);
		break;

	default:
		break;
	}

	free(cert);
}

CK_RV create_new_cert(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		      struct libattr_list *attrs)
{
	CK_RV ret = CKR_HOST_MEMORY;
	CK_USER_TYPE user = CKU_USER;

	struct libobj_cert *new_cert = NULL;

	new_cert = cert_allocate(obj);
	if (!new_cert)
		return ret;

	DBG_TRACE("Create a new certificate type object (%p)", new_cert);

	ret = attr_get_value(new_cert, &attr_cert_common[CERT_TYPE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_cert_common[CERT_TRUSTED], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	if (new_cert->trusted) {
		ret = libsess_get_user(hsession, &user);
		if (ret != CKR_OK)
			return ret;

		if (user != CKU_SO)
			return CKR_ATTRIBUTE_READ_ONLY;
	}

	ret = attr_get_value(new_cert, &attr_cert_common[CERT_CATEGORY], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_cert_common[CERT_CHECK_VALUE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_cert_common[CERT_START_DATE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_cert_common[CERT_END_DATE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_cert_common[CERT_PUB_KEY_INFO],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	DBG_TRACE("Certificate type object (%p) creation return %ld", obj, ret);
	return ret;
}

static CK_RV create_new_x_509_cert(struct libobj_obj *obj,
				   struct libattr_list *attrs)
{
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_x_509_cert *new_cert = NULL;
	enum attr_req req_overwrite = NO_OVERWRITE;

	new_cert = calloc(1, sizeof(*new_cert));
	if (!new_cert)
		return ret;

	set_cert_to(obj, new_cert);

	DBG_TRACE("Create a new X.509 public key certificate object (%p)",
		  new_cert);

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_SUBJECT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_ID], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_ISSUER], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_SER_NUM], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_VALUE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_URL], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	/* Either CKA_VALUE or CKA_URL must be specified */
	if (!new_cert->value.number && !new_cert->url.length)
		return CKR_TEMPLATE_INCOMPLETE;

	/*
	 * If CKA_URL is present, attributes CKA_HASH_OF_ISSUER_PUBLIC_KEY and
	 * CKA_HASH_OF_SUBJECT_PUBLIC_KEY must be set.
	 */
	if (new_cert->url.length)
		req_overwrite = MUST;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_SPK_HASH], attrs,
			     req_overwrite);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_ISP_HASH], attrs,
			     req_overwrite);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert,
			     &attr_x_509_cert[X_509_JAVA_MIDP_SEC_DOMAIN],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_cert[X_509_HASH_ALGO], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	if (!new_cert->mech)
		new_cert->mech = CKM_SHA_1;

	DBG_TRACE("Certificate type object (%p) creation return %ld", obj, ret);
	return ret;
}

static CK_RV create_new_wtls_cert(struct libobj_obj *obj,
				  struct libattr_list *attrs)
{
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_wtls_cert *new_cert = NULL;

	enum attr_req req_overwrite = NO_OVERWRITE;

	new_cert = calloc(1, sizeof(*new_cert));
	if (!new_cert)
		return ret;

	set_cert_to(obj, new_cert);

	DBG_TRACE("Create a new WTLS public key certificate object (%p)",
		  new_cert);

	ret = attr_get_value(new_cert, &attr_wtls_cert[WTLS_SUBJECT], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_wtls_cert[WTLS_ISSUER], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_wtls_cert[WTLS_VALUE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_wtls_cert[WTLS_URL], attrs,
			     req_overwrite);
	if (ret != CKR_OK)
		return ret;

	/* Either CKA_VALUE or CKA_URL must be specified */
	if (!new_cert->value.number && !new_cert->url.length)
		return CKR_TEMPLATE_INCOMPLETE;

	/*
	 * If CKA_URL is present, attributes CKA_HASH_OF_ISSUER_PUBLIC_KEY and
	 * CKA_HASH_OF_SUBJECT_PUBLIC_KEY must be set.
	 */
	if (new_cert->url.length)
		req_overwrite = MUST;

	ret = attr_get_value(new_cert, &attr_wtls_cert[WTLS_SPK_HASH], attrs,
			     req_overwrite);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_wtls_cert[WTLS_ISP_HASH], attrs,
			     req_overwrite);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_wtls_cert[WTLS_HASH_ALGO], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	if (!new_cert->mech)
		new_cert->mech = CKM_SHA_1;

	/* CKA_SUBJECT can only be empty if CKA_VALUE is empty */
	if (new_cert->value.number && !new_cert->subject.number)
		return CKR_TEMPLATE_INCOMPLETE;

	DBG_TRACE("Certificate type object (%p) creation return %ld", obj, ret);
	return ret;
}

static CK_RV create_new_x_509_attr_cert(struct libobj_obj *obj,
					struct libattr_list *attrs)
{
	CK_RV ret = CKR_HOST_MEMORY;
	struct libobj_x_509_attr_cert *new_cert = NULL;

	new_cert = calloc(1, sizeof(*new_cert));
	if (!new_cert)
		return ret;

	set_cert_to(obj, new_cert);

	DBG_TRACE("Create a new X.509 attribute certificate object (%p)",
		  new_cert);

	ret = attr_get_value(new_cert, &attr_x_509_attr_cert[X_509_ATTR_OWNER],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_attr_cert[X_509_ATTR_ISSUER],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert,
			     &attr_x_509_attr_cert[X_509_ATTR_SER_NUM], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_attr_cert[X_509_ATTR_TYPES],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(new_cert, &attr_x_509_attr_cert[X_509_ATTR_VALUE],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	DBG_TRACE("Certificate type object (%p) creation return %ld", obj, ret);
	return ret;
}

CK_RV cert_create(CK_SESSION_HANDLE hsession, struct libobj_obj *obj,
		  struct libattr_list *attrs)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	DBG_TRACE("Create a new certificate type object");

	if (!obj)
		goto end;

	if (is_token_obj(obj, storage)) {
		DBG_TRACE("Token certificate object creation is not supported");
		ret = CKR_FUNCTION_NOT_SUPPORTED;
		goto end;
	}

	/* Create the common certificate object */
	ret = create_new_cert(hsession, obj, attrs);
	if (ret != CKR_OK)
		goto end;

	switch (get_cert_type(obj)) {
	case CKC_X_509:
		ret = create_new_x_509_cert(obj, attrs);
		break;

	case CKC_WTLS:
		ret = create_new_wtls_cert(obj, attrs);
		break;

	case CKC_X_509_ATTR_CERT:
		ret = create_new_x_509_attr_cert(obj, attrs);
		break;

	default:
		ret = CKR_GENERAL_ERROR;
		break;
	}

end:
	DBG_TRACE("Certificate type object (%p) creation return %ld", obj, ret);
	return ret;
}

static CK_RV x509_cert_get_attr(CK_ATTRIBUTE_PTR attr,
				const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Get attribute type=%#lx", attr->type);

	/* Get attribute from the X.509 certificate object */
	ret = attr_get_obj_value(attr, attr_x_509_cert,
				 ARRAY_SIZE(attr_x_509_cert),
				 get_cert_from(obj));

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

static CK_RV wtls_cert_get_attr(CK_ATTRIBUTE_PTR attr,
				const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Get attribute type=%#lx", attr->type);

	/* Get attribute from the WTLS certificate object */
	ret = attr_get_obj_value(attr, attr_wtls_cert,
				 ARRAY_SIZE(attr_wtls_cert),
				 get_cert_from(obj));

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

static CK_RV x509_attr_cert_get_attr(CK_ATTRIBUTE_PTR attr,
				     const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Get attribute type=%#lx", attr->type);

	/* Get attribute from the X.509 attribute certificate object */
	ret = attr_get_obj_value(attr, attr_x_509_attr_cert,
				 ARRAY_SIZE(attr_x_509_attr_cert),
				 get_cert_from(obj));

	DBG_TRACE("Get attribute type1=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV cert_get_attribute(CK_ATTRIBUTE_PTR attr, const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Get attribute type=%#lx", attr->type);

	/* Get attribute from the common certificate attribute */
	ret = attr_get_obj_value(attr, attr_cert_common,
				 ARRAY_SIZE(attr_cert_common),
				 get_subobj_from(obj, storage));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the common certificate object attributes,
	 * try to get it from the specific certificate type attributes.
	 */
	switch (get_cert_type(obj)) {
	case CKC_X_509:
		ret = x509_cert_get_attr(attr, obj);
		break;

	case CKC_WTLS:
		ret = wtls_cert_get_attr(attr, obj);
		break;

	case CKC_X_509_ATTR_CERT:
		ret = x509_attr_cert_get_attr(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Get attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

static CK_RV x509_cert_modify_attr(CK_ATTRIBUTE_PTR attr,
				   const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Modify attribute of X.509 certificate object */
	ret = attr_modify_obj_value(attr, attr_x_509_cert,
				    ARRAY_SIZE(attr_x_509_cert),
				    get_cert_from(obj));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

static CK_RV wtls_cert_modify_attr(CK_ATTRIBUTE_PTR attr,
				   const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Modify attribute of WTLS certificate object  */
	ret = attr_modify_obj_value(attr, attr_wtls_cert,
				    ARRAY_SIZE(attr_wtls_cert),
				    get_cert_from(obj));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

static CK_RV x509_attr_cert_modify_attr(CK_ATTRIBUTE_PTR attr,
					const struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Modify attribute of X.509 attribute certificate object */
	ret = attr_modify_obj_value(attr, attr_x_509_attr_cert,
				    ARRAY_SIZE(attr_x_509_attr_cert),
				    get_cert_from(obj));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV cert_modify_attribute(CK_ATTRIBUTE_PTR attr, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	DBG_TRACE("Modify attribute type=%#lx", attr->type);

	/* Modify attribute from the common certificate attribute */
	ret = attr_modify_obj_value(attr, attr_cert_common,
				    ARRAY_SIZE(attr_cert_common),
				    get_subobj_from(obj, storage));
	if (ret != CKR_ATTRIBUTE_TYPE_INVALID)
		return ret;

	/*
	 * Attribute not present in the common certificate object attributes,
	 * try to modify it in the specific certificate type object
	 */
	switch (get_cert_type(obj)) {
	case CKC_X_509:
		ret = x509_cert_modify_attr(attr, obj);
		break;

	case CKC_WTLS:
		ret = wtls_cert_modify_attr(attr, obj);
		break;

	case CKC_X_509_ATTR_CERT:
		ret = x509_attr_cert_modify_attr(attr, obj);
		break;

	default:
		ret = CKR_FUNCTION_FAILED;
	}

	DBG_TRACE("Modify attribute type=%#lx ret %ld", attr->type, ret);
	return ret;
}

CK_RV cert_get_size(const struct libobj_obj *obj, CK_ULONG_PTR obj_size)
{
	CK_RV ret = CKR_GENERAL_ERROR;

	struct libobj_x_509_cert *x509_cert = NULL;
	struct libobj_wtls_cert *wtls_cert = NULL;
	struct libobj_x_509_attr_cert *x509_attr_cert = NULL;

	DBG_TRACE("Get certificate size.");

	*obj_size = 0;

	switch (get_cert_type(obj)) {
	case CKC_X_509:
		x509_cert = get_cert_from(obj);
		if (!x509_cert)
			goto end;

		*obj_size = x509_cert->value.number;

		break;

	case CKC_WTLS:
		wtls_cert = get_cert_from(obj);
		if (!wtls_cert)
			goto end;

		*obj_size = wtls_cert->value.number;
		break;

	case CKC_X_509_ATTR_CERT:
		x509_attr_cert = get_cert_from(obj);
		if (!x509_attr_cert)
			goto end;

		*obj_size = x509_attr_cert->value.number;

		break;

	default:
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	ret = CKR_OK;

end:
	DBG_TRACE("Size of certificate object (%p) = %lu return %lu.", obj,
		  *obj_size, ret);
	return ret;
}

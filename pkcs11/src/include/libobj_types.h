/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2025 NXP
 */

#ifndef __LIBOBJ_TYPES_H__
#define __LIBOBJ_TYPES_H__

#include <assert.h>

#include "util.h"
#include "types.h"

/**
 * struct libobj_obj - Definition of an object element of a object list
 * @lock: Mutex to lock object when used
 * @class: Object class
 * @force_destroy: Destroy an object even if it is a token
 * @object: Pointer to the object (type depend on the class)
 * @prev: Previous element of the list
 * @next: Next element of the list
 */
struct libobj_obj {
	CK_VOID_PTR lock;
	CK_OBJECT_CLASS class;
	bool force_destroy;
	void *object;
	struct libobj_obj *prev;
	struct libobj_obj *next;
};

struct libobj_storage {
	bool token;
	bool private;
	bool modifiable;
	bool copyable;
	bool destroyable;
	struct librfc2279 label;
	struct librfc2279 unique_id;
	void *subobject;
};

#define get_object_from(obj)                                                   \
	({                                                                     \
		__typeof__(obj) _obj = (obj);                                  \
		_obj ? _obj->object : NULL;                                    \
	})

#define is_force_destroy_obj(obj)                                              \
	({                                                                     \
		struct libobj_obj *_obj = (obj);                               \
		_obj->force_destroy;                                           \
	})

#define set_force_destroy_obj(obj)                                             \
	({                                                                     \
		struct libobj_obj *_obj = (obj);                               \
		_obj->force_destroy = true;                                    \
	})

#define get_subobj_from(obj, type)                                             \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->subobject;                                          \
	})

#define set_subobj_to(obj, type, subobj)                                       \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->subobject = subobj;                                 \
	})

#define is_token_obj(obj, type)                                                \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->token;                                              \
	})

#define set_token_obj(obj, type)                                               \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->token = true;                                       \
	})

#define is_destroyable_obj(obj, type)                                          \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->destroyable;                                        \
	})

#define is_copyable_obj(obj, type)                                             \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->copyable;                                           \
	})

#define set_copyable_obj(obj, type)                                            \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->copyable = true;                                    \
	})

#define is_modifiable_obj(obj, type)                                           \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->modifiable;                                         \
	})

#define set_non_modifiable_obj(obj, type)                                      \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->modifiable = false;                                 \
	})

#define is_private_obj(obj, type)                                              \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		_obj_type->private;                                            \
	})

#define get_unique_id_obj(obj, type)                                           \
	({                                                                     \
		struct libobj_##type *_obj_type = get_object_from(obj);        \
		assert(_obj_type);                                             \
		&_obj_type->unique_id;                                         \
	})

enum tls_key { NOT_TLS_KEY = 0, TLS12_KEY, TLS13_KEY };

struct libobj_key {
	CK_KEY_TYPE type;
	struct libbytes id;    // User defined key ID. Same for Public/Private
	unsigned int token_id; // Token key ID. Same for Public/Private
	CK_DATE start_date;
	CK_DATE end_date;
	bool derive;
	bool local;
	enum tls_key tls_key;
	CK_MECHANISM_TYPE gen_mech;
	struct libmech_list mech_list;
	void *key;
	void *subkey;
};

#define set_key_to(obj, ptr)                                                   \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->key = ptr;                                               \
	})

#define set_subkey_to(obj, ptr)                                                \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->subkey = ptr;                                            \
	})

#define get_key_type(obj)                                                      \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->type;                                                    \
	})

#define set_key_type(obj, _type)                                               \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->type = _type;                                            \
	})

#define get_key_from(obj)                                                      \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->key;                                                     \
	})

#define get_subkey_from(obj)                                                   \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->subkey;                                                  \
	})

#define is_derive_key(obj)                                                     \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->derive;                                                  \
	})

#define set_derive_key(obj)                                                    \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->derive = true;                                           \
	})

#define get_key_mech_list(obj)                                                 \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		&_key->mech_list;                                              \
	})

#define get_cert_type(obj)                                                     \
	({                                                                     \
		struct libobj_cert *_cert = get_subobj_from(obj, storage);     \
		assert(_cert);                                                 \
		_cert->type;                                                   \
	})

#define set_cert_to(obj, ptr)                                                  \
	({                                                                     \
		struct libobj_cert *_cert = get_subobj_from(obj, storage);     \
		assert(_cert);                                                 \
		_cert->cert = ptr;                                             \
	})

#define get_cert_from(obj)                                                     \
	({                                                                     \
		struct libobj_cert *_cert = get_subobj_from(obj, storage);     \
		assert(_cert);                                                 \
		_cert->cert;                                                   \
	})

#define set_key_token_id(obj, _token_id)                                       \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->token_id = _token_id;                                    \
	})

#define get_key_token_id(obj)                                                  \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->token_id;                                                \
	})

#define set_data_token_id(obj, _token_id)                                      \
	({                                                                     \
		struct libobj_data *_data = get_subobj_from(obj, storage);     \
		assert(_data);                                                 \
		_data->token_id = _token_id;                                   \
	})

#define get_data_token_id(obj)                                                 \
	({                                                                     \
		struct libobj_data *_data = get_subobj_from(obj, storage);     \
		assert(_data);                                                 \
		_data->token_id;                                               \
	})

#define set_key_tls(obj, _tls_key)                                             \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->tls_key = _tls_key;                                      \
	})

#define get_key_tls(obj)                                                       \
	({                                                                     \
		struct libobj_key *_key = get_subobj_from(obj, storage);       \
		assert(_key);                                                  \
		_key->tls_key;                                                 \
	})

/*
 * Define the libobj public/private/keypair type
 */
#define LIBOBJ_KEY_PUBLIC  BIT(0)
#define LIBOBJ_KEY_PRIVATE BIT(1)
#define LIBOBJ_KEY_PAIR	   (LIBOBJ_KEY_PUBLIC | LIBOBJ_KEY_PRIVATE)

struct libobj_key_ec_pair {
	unsigned int type;	    // Private/Public key type
	struct libobj_obj *pub_obj; // Reference to public key obj
	struct libbytes params;
	struct libbytes point_q;     // Public Key point
	struct libbignumber value_d; // Secure Key scalar
};

struct libobj_key_rsa_pair {
	unsigned int type;	      // Private/Public key type
	struct libobj_obj *pub_obj;   // Reference to public key obj
	struct libbignumber modulus;  // Modulus n
	CK_ULONG modulus_length;      // Modulus length in bits
	struct libbignumber pub_exp;  // Public Exponent e
	struct libbignumber priv_exp; // Private Exponent d
	struct libbignumber prime_p;  // Private Prime p
	struct libbignumber prime_q;  // Private Prime q
	struct libbignumber exp_dp;   // Private exponent d modulo p-1
	struct libbignumber exp_dq;   // Private exponent d modulo q-1
	struct libbignumber coeff;    // Private CRT coefficient q^-1 mod p
};

struct libobj_key_cipher {
	struct libbytes value;
	size_t value_len;
};

struct libobj_key_hmac {
	struct libbytes value;
	size_t value_len;
};

/**
 * lib_derive_ctx - Derive context
 * @hkey: Operation key handle
 * @peer_buffer: Peer public buffer
 * @peer_buffer_len: Peer public buffer length in bytes
 * @shared_buffer: Shared secret buffer
 * @shared_buffer_len: Shared secret buffer length in bytes
 * @skipped: Is derivation to be skip
 * @extractable: Is derived object to be extractable
 * @context: Internal operation context
 */
struct lib_derive_ctx {
	CK_OBJECT_HANDLE hkey;
	CK_BYTE_PTR peer_buffer;
	CK_ULONG peer_buffer_len;
	CK_BYTE_PTR shared_buffer;
	CK_ULONG shared_buffer_len;
	CK_BBOOL skipped;
	CK_BBOOL extractable;
	void *context;
};

struct libobj_key_derive_params {
	CK_SESSION_HANDLE hsession;
	CK_OBJECT_HANDLE base_key;
	struct libobj_obj *derived_key;
	struct lib_derive_ctx *ctx;
	union {
		struct {
			CK_BBOOL extract;
			CK_BBOOL expand;
			CK_MECHANISM_TYPE prf_hash_mech;
			CK_ULONG salt_type;
			CK_BYTE_PTR salt;
			CK_ULONG salt_len;
			CK_BYTE_PTR info;
			CK_ULONG info_len;
		} hkdf_params;
		struct {
			CK_EC_KDF_TYPE kdf;
			CK_ULONG ulSharedDataLen;
			CK_BYTE_PTR pSharedData;
			CK_ULONG ulPublicDataLen;
			CK_BYTE_PTR pPublicData;
		} ecdh_params;
		struct {
			CK_ULONG ulMacSizeInBits;
			CK_ULONG ulKeySizeInBits;
			CK_ULONG ulIVSizeInBits;
			CK_BBOOL bIsExport;
			CK_SSL3_RANDOM_DATA RandomInfo;
			CK_VERSION_PTR pVersion;
			CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
			CK_MECHANISM_TYPE prfHashMechanism;
			CK_BYTE_PTR pSessionHash;
			CK_ULONG ulSessionHashLen;
		} tls12_params;
	};
};

struct libobj_data {
	unsigned int token_id;	       // Token data ID
	struct librfc2279 application; // Application managing object
	struct libbytes id;	       // Object identifier
	struct libbytes value;	       // Value of the object
};

struct libobj_key_public {
	struct libbytes subject;
	bool encrypt;
	bool verify;
	bool verify_recover;
	bool wrap;
	bool trusted;
	struct libattr_list wrap_attrs;
	struct libbytes info;
};

struct libobj_key_private {
	struct libbytes subject;
	bool sensitive;
	bool always_sensitive;
	bool decrypt;
	bool sign;
	bool sign_recover;
	bool extractable;
	bool never_extractable;
	bool wrap_with_trusted;
	bool unwrap;
	struct libattr_list unwrap_attrs;
	bool always_authenticate;
	struct libbytes info;
};

struct libobj_key_secret {
	bool sensitive;
	bool always_sensitive;
	bool encrypt;
	bool decrypt;
	bool sign;
	bool verify;
	bool extractable;
	bool never_extractable;
	bool wrap;
	struct libattr_list wrap_attrs;
	bool wrap_with_trusted;
	bool unwrap;
	struct libattr_list unwrap_attrs;
	bool trusted;
	struct libbytes checksum;
};

struct libobj_cert {
	unsigned int token_id; // Token certificate ID
	CK_CERTIFICATE_TYPE type;
	bool trusted;
	CK_CERTIFICATE_CATEGORY cat;
	struct libbytes checksum;
	CK_DATE start_date;
	CK_DATE end_date;
	struct libbytes pub_key_info;
	void *cert;
};

struct libobj_x_509_cert {
	struct libbytes subject;
	struct libbytes id;
	struct libbytes issuer;
	struct libbytes ser_num;
	struct libbytes value;
	struct librfc2279 url;
	struct libbytes spk_hash;
	struct libbytes ipk_hash;
	CK_JAVA_MIDP_SECURITY_DOMAIN sec_domain;
	CK_MECHANISM_TYPE mech;
};

struct libobj_wtls_cert {
	unsigned int cert_id;
	struct libbytes subject;
	struct libbytes issuer;
	struct libbytes value;
	struct librfc2279 url;
	struct libbytes spk_hash;
	struct libbytes ipk_hash;
	CK_MECHANISM_TYPE mech;
};

struct libobj_x_509_attr_cert {
	unsigned int cert_id;
	struct libbytes owner;
	struct libbytes issuer;
	struct libbytes ser_num;
	struct libbytes attr_types;
	struct libbytes value;
};

#endif /* __LIBOBJ_TYPES_H__ */

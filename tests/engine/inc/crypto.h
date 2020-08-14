/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

/**
 * hash() - Do a hash operation.
 * @args: Hash args.
 *
 * Return:
 * 0	- Success.
 * 1	- Fail.
 */
int hash(json_object *args);

#endif /* __CRYPTO_H__ */

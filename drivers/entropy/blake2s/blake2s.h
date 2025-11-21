/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _CRYPTO_BLAKE2S_H
#define _CRYPTO_BLAKE2S_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum blake2s_lengths {
	BLAKE2S_BLOCK_SIZE = 64,
	BLAKE2S_HASH_SIZE = 32,
	BLAKE2S_KEY_SIZE = 32,

	BLAKE2S_128_HASH_SIZE = 16,
	BLAKE2S_160_HASH_SIZE = 20,
	BLAKE2S_224_HASH_SIZE = 28,
	BLAKE2S_256_HASH_SIZE = 32,
};

struct blake2s_state {
	/* 'h', 't', and 'f' are used in assembly code, so keep them as-is. */
	uint32_t h[8];
	uint32_t t[2];
	uint32_t f[2];
	uint8_t buf[BLAKE2S_BLOCK_SIZE];
	unsigned int buflen;
	unsigned int outlen;
};

enum blake2s_iv {
	BLAKE2S_IV0 = 0x6A09E667UL,
	BLAKE2S_IV1 = 0xBB67AE85UL,
	BLAKE2S_IV2 = 0x3C6EF372UL,
	BLAKE2S_IV3 = 0xA54FF53AUL,
	BLAKE2S_IV4 = 0x510E527FUL,
	BLAKE2S_IV5 = 0x9B05688CUL,
	BLAKE2S_IV6 = 0x1F83D9ABUL,
	BLAKE2S_IV7 = 0x5BE0CD19UL,
};

void blake2s_init(struct blake2s_state *state, const size_t outlen);
void blake2s_update(struct blake2s_state *state, const uint8_t *in, size_t inlen);
void blake2s_final(struct blake2s_state *state, uint8_t *out);
void blake2s_compress(struct blake2s_state *state, const uint8_t *block, 
                      size_t nblocks, const uint32_t inc);

#endif /* _CRYPTO_BLAKE2S_H */

/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Adapted for Zephyr RTOS
 */

#include "blake2s.h"
#include <string.h>

#define unlikely(x) (x)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static void memzero_explicit(void *s, size_t count)
{
	volatile uint8_t *p = (volatile uint8_t *)s;
	while (count--) {
		*p++ = 0;
	}
}

static void cpu_to_le32_array(uint32_t *buf, size_t words)
{
	/* Assuming little-endian target (ESP32) */
	(void)buf;
	(void)words;
}

static inline void blake2s_set_lastblock(struct blake2s_state *state)
{
	state->f[0] = -1;
}

void blake2s_init(struct blake2s_state *state, const size_t outlen)
{
	memset(state, 0, sizeof(*state));

	state->h[0] = BLAKE2S_IV0 ^ (0x01010000 | outlen);
	state->h[1] = BLAKE2S_IV1;
	state->h[2] = BLAKE2S_IV2;
	state->h[3] = BLAKE2S_IV3;
	state->h[4] = BLAKE2S_IV4;
	state->h[5] = BLAKE2S_IV5;
	state->h[6] = BLAKE2S_IV6;
	state->h[7] = BLAKE2S_IV7;
	state->outlen = outlen;
}

void blake2s_update(struct blake2s_state *state, const uint8_t *in, size_t inlen)
{
	const size_t fill = BLAKE2S_BLOCK_SIZE - state->buflen;

	if (unlikely(!inlen))
		return;
	
	if (inlen > fill) {
		memcpy(state->buf + state->buflen, in, fill);
		blake2s_compress(state, state->buf, 1, BLAKE2S_BLOCK_SIZE);
		state->buflen = 0;
		in += fill;
		inlen -= fill;
	}
	
	if (inlen > BLAKE2S_BLOCK_SIZE) {
		const size_t nblocks = DIV_ROUND_UP(inlen, BLAKE2S_BLOCK_SIZE);
		blake2s_compress(state, in, nblocks - 1, BLAKE2S_BLOCK_SIZE);
		in += BLAKE2S_BLOCK_SIZE * (nblocks - 1);
		inlen -= BLAKE2S_BLOCK_SIZE * (nblocks - 1);
	}
	
	memcpy(state->buf + state->buflen, in, inlen);
	state->buflen += inlen;
}

void blake2s_final(struct blake2s_state *state, uint8_t *out)
{
	blake2s_set_lastblock(state);
	memset(state->buf + state->buflen, 0,
	       BLAKE2S_BLOCK_SIZE - state->buflen);
	blake2s_compress(state, state->buf, 1, state->buflen);
	cpu_to_le32_array(state->h, ARRAY_SIZE(state->h));
	memcpy(out, state->h, state->outlen);
	memzero_explicit(state, sizeof(*state));
}

/*
 * Copyright (c) 2024-2025 Javier Blanco-Romero (UC3M, QURSA project)
 * SPDX-License-Identifier: Apache-2.0
 * 
 * BLAKE2s-based Entropy Pool Driver for Zephyr RTOS
 * 
 * This driver implements a hardware-agnostic BLAKE2s entropy pool inspired by:
 * - Linux kernel 5.17+ /dev/random implementation (Jason A. Donenfeld)
 * 
 * Architecture:
 * - Works with ANY Zephyr entropy driver as backend (ESP32, nRF, STM32, etc.)
 * - Backend device specified via devicetree 'hardware-device' property
 * - Uses standard entropy_get_entropy() API for hardware access
 * - BLAKE2s provides cryptographic mixing and forward secrecy
 */

#define DT_DRV_COMPAT zephyr_entropy_blake2s_pool

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "blake2s/blake2s.h"

LOG_MODULE_REGISTER(entropy_blake2s, CONFIG_ENTROPY_LOG_LEVEL);

/*
 * Pool configuration
 * These values are based on the paper and reference implementation
 */
#define POOL_SIZE_BYTES 512        /* Virtual pool size for accounting */
#define POOL_REFILL_THRESHOLD 128  /* Trigger refill when below this */
#define FAST_BUFFER_SIZE 64        /* Pre-computed output for ISR fast path */
#define INITIAL_SEED_SIZE 64       /* Bootstrap seed from hardware */
#define HW_REFILL_SIZE 64          /* Bytes per hardware refill */

/*
 * Entropy pool structure (based on linux-blake2s-entropy-pool)
 * This follows the reference implementation closely
 */
struct entropy_pool {
	struct blake2s_state hash;  /* BLAKE2s state - the core of the pool */
	unsigned int init_bits;     /* Entropy bits accounting */
};

/*
 * Driver data structure
 */
struct entropy_blake2s_data {
	/* Backend hardware entropy device (from devicetree) */
	const struct device *hw_dev;
	
	/* The entropy pool */
	struct entropy_pool pool;
	
	/* Fast buffer for ISR access (pre-computed BLAKE2s output) */
	uint8_t fast_buffer[FAST_BUFFER_SIZE];
	uint8_t fast_buffer_pos;    /* Next read position */
	uint8_t fast_buffer_avail;  /* Bytes available */
	
	/* Synchronization */
	struct k_mutex lock;        /* Protects pool state */
	struct k_work refill_work;  /* Asynchronous hardware refill */
	
	/* State flags */
	bool initialized;
	bool refilling;
	
	/* Statistics (for debugging and paper validation) */
	uint32_t hw_refill_count;
	uint32_t extract_count;
	uint32_t external_add_count;
	uint32_t isr_busywait_count;
	uint64_t total_hw_bytes;
	uint64_t total_external_bytes;
	uint64_t total_extracted_bytes;
};

static struct entropy_blake2s_data blake2s_data;

/*
 * Hardware entropy acquisition (generic, works with any backend)
 * Uses the Zephyr entropy driver API on the backend device
 */
static int get_hw_entropy(uint8_t *buffer, size_t len)
{
	int ret;
	
	if (!blake2s_data.hw_dev) {
		LOG_ERR("No hardware entropy backend configured");
		return -ENODEV;
	}
	
	if (!device_is_ready(blake2s_data.hw_dev)) {
		LOG_ERR("Hardware entropy device not ready");
		return -ENODEV;
	}
	
	ret = entropy_get_entropy(blake2s_data.hw_dev, buffer, len);
	if (ret < 0) {
		LOG_ERR("Failed to get hardware entropy: %d", ret);
		return ret;
	}
	
	return 0;
}

/*
 * Mix entropy into the pool
 * This is the core operation from the reference implementation
 */
static void mix_pool_bytes(struct entropy_pool *pool, const void *buf, size_t len)
{
	blake2s_update(&pool->hash, buf, len);
}

/*
 * Add entropy to the pool (without credit)
 * From linux-blake2s-entropy-pool/drivers/random.c
 */
static void add_entropy(struct entropy_pool *pool, const void *buf, size_t len)
{
	mix_pool_bytes(pool, buf, len);
}

/*
 * Credit entropy bits to the pool
 * From linux-blake2s-entropy-pool/drivers/random.c
 */
static void credit_entropy(struct entropy_pool *pool, int ent_count)
{
	/* Saturate at maximum pool size in bits */
	unsigned int max_bits = POOL_SIZE_BYTES * 8;
	
	if (pool->init_bits + ent_count > max_bits) {
		pool->init_bits = max_bits;
	} else {
		pool->init_bits += ent_count;
	}
}

/*
 * Add entropy with credit
 * From linux-blake2s-entropy-pool/drivers/random.c
 */
static void add_entropy_credit(struct entropy_pool *pool, const void *buf, 
                               size_t len, int ent_count)
{
	if (ent_count > 0) {
		credit_entropy(pool, ent_count);
	}
}

/*
 * Extract entropy from the pool
 * This follows the Linux kernel pattern: snapshot → finalize → backfeed
 */
static void extract_entropy(struct entropy_pool *pool, uint8_t *output, size_t outlen)
{
	struct blake2s_state snapshot;
	uint8_t hash[BLAKE2S_HASH_SIZE];
	size_t remaining = outlen;
	size_t offset = 0;

	while (remaining > 0) {
		/* Step 1: Snapshot current state (non-destructive) */
		memcpy(&snapshot, &pool->hash, sizeof(snapshot));

		/* Step 2: Extract output via finalization */
		blake2s_final(&snapshot, hash);

		/* Step 3: Copy to output buffer */
		size_t to_copy = MIN(remaining, BLAKE2S_HASH_SIZE);
		memcpy(output + offset, hash, to_copy);

		/* Step 4: CRITICAL - Backfeed for forward secrecy */
		blake2s_update(&pool->hash, hash, BLAKE2S_HASH_SIZE);

		remaining -= to_copy;
		offset += to_copy;
	}

	/* Debit entropy accounting */
	unsigned int bits_extracted = outlen * 8;
	if (pool->init_bits >= bits_extracted) {
		pool->init_bits -= bits_extracted;
	} else {
		pool->init_bits = 0;
	}

	/* Clear sensitive data */
	memset(hash, 0, sizeof(hash));
	memset(&snapshot, 0, sizeof(snapshot));

	LOG_DBG("Extracted %zu bytes, pool bits: %u/%u",
		outlen, pool->init_bits, POOL_SIZE_BYTES * 8);
}

/*
 * Refill fast buffer for ISR fast path
 */
static void refill_fast_buffer(void)
{
	extract_entropy(&blake2s_data.pool, blake2s_data.fast_buffer, 
	                FAST_BUFFER_SIZE);
	
	blake2s_data.fast_buffer_pos = 0;
	blake2s_data.fast_buffer_avail = FAST_BUFFER_SIZE;

	LOG_DBG("Fast buffer refilled: %u bytes", FAST_BUFFER_SIZE);
}

/*
 * Hardware refill work handler
 * Reads hardware backend and mixes into pool
 */
static void hw_refill_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	uint8_t hw_entropy[HW_REFILL_SIZE];
	int err;

	LOG_DBG("HW refill work started");

	err = k_mutex_lock(&blake2s_data.lock, K_FOREVER);
	if (err != 0) {
		LOG_ERR("Failed to lock mutex in refill work: %d", err);
		blake2s_data.refilling = false;
		return;
	}

	/* Read entropy from hardware backend */
	err = get_hw_entropy(hw_entropy, sizeof(hw_entropy));
	if (err != 0) {
		LOG_ERR("HW refill failed: %d", err);
		blake2s_data.refilling = false;
		k_mutex_unlock(&blake2s_data.lock);
		return;
	}

	/* Mix into pool with full entropy credit (hardware source) */
	add_entropy(&blake2s_data.pool, hw_entropy, sizeof(hw_entropy));
	credit_entropy(&blake2s_data.pool, sizeof(hw_entropy) * 8);
	
	blake2s_data.total_hw_bytes += sizeof(hw_entropy);
	blake2s_data.hw_refill_count++;

	LOG_INF("HW refill #%u: +%zu bytes → pool bits: %u/%u",
		blake2s_data.hw_refill_count, sizeof(hw_entropy),
		blake2s_data.pool.init_bits, POOL_SIZE_BYTES * 8);

	/* Refill fast buffer if needed */
	if (blake2s_data.fast_buffer_avail < (FAST_BUFFER_SIZE / 2)) {
		refill_fast_buffer();
	}

	blake2s_data.refilling = false;
	k_mutex_unlock(&blake2s_data.lock);

	/* Clear sensitive data */
	memset(hw_entropy, 0, sizeof(hw_entropy));
}

/*
 * Trigger hardware refill if pool is low
 */
static void check_and_trigger_refill(void)
{
	unsigned int pool_bytes = blake2s_data.pool.init_bits / 8;
	
	if (pool_bytes < POOL_REFILL_THRESHOLD && !blake2s_data.refilling) {
		blake2s_data.refilling = true;
		k_work_submit(&blake2s_data.refill_work);
		LOG_DBG("Triggered HW refill (pool low: %u/%u bytes)",
			pool_bytes, POOL_REFILL_THRESHOLD);
	}
}

/*
 * Public API: Get entropy (thread context)
 */
static int entropy_blake2s_get_entropy(const struct device *dev,
					uint8_t *buf, uint16_t len)
{
	ARG_UNUSED(dev);
	int err;

	if (!buf || len == 0) {
		return -EINVAL;
	}

	if (!blake2s_data.initialized) {
		LOG_ERR("Driver not initialized");
		return -ENODEV;
	}

	LOG_DBG("get_entropy: %u bytes requested", len);

	err = k_mutex_lock(&blake2s_data.lock, K_FOREVER);
	if (err != 0) {
		LOG_ERR("Failed to acquire lock: %d", err);
		return err;
	}

	/* Trigger refill if needed (before extraction) */
	check_and_trigger_refill();

	/* Extract from BLAKE2s pool */
	extract_entropy(&blake2s_data.pool, buf, len);
	
	blake2s_data.extract_count++;
	blake2s_data.total_extracted_bytes += len;

	/* Trigger refill if needed (after extraction) */
	check_and_trigger_refill();

	k_mutex_unlock(&blake2s_data.lock);

	LOG_DBG("get_entropy: %u bytes delivered", len);

	return 0;
}

/*
 * Public API: Get entropy (ISR context)
 * Fast path: Use pre-computed buffer
 * Fallback: Direct hardware read (BUSYWAIT mode)
 */
static int entropy_blake2s_get_entropy_isr(const struct device *dev,
					    uint8_t *buf, uint16_t len,
					    uint32_t flags)
{
	ARG_UNUSED(dev);

	if (!buf || len == 0) {
		return -EINVAL;
	}

	if (!blake2s_data.initialized) {
		return -ENODEV;
	}

	/* BUSYWAIT mode: Bypass pool, read directly from hardware */
	if (flags & ENTROPY_BUSYWAIT) {
		int ret;

		LOG_DBG("ISR BUSYWAIT: Reading %u bytes directly from hardware", len);

		/* In ISR context, we can't use the mutex, so directly call hardware
		 * This is safe because we're just reading, not modifying pool state
		 */
		ret = entropy_get_entropy_isr(blake2s_data.hw_dev, buf, len, flags);
		if (ret < 0) {
			LOG_ERR("ISR busywait HW read failed: %d", ret);
			return ret;
		}

		blake2s_data.isr_busywait_count++;
		return ret;
	}

	/* Non-blocking mode: Try fast buffer */
	unsigned int key = irq_lock();

	uint8_t available = blake2s_data.fast_buffer_avail;
	
	if (available == 0) {
		irq_unlock(key);
		LOG_DBG("ISR fast path: Buffer empty");
		return 0;
	}

	/* Limit to available bytes */
	uint16_t to_copy = MIN(len, available);
	uint8_t pos = blake2s_data.fast_buffer_pos;

	/* Copy from fast buffer */
	memcpy(buf, &blake2s_data.fast_buffer[pos], to_copy);

	/* Update buffer state */
	blake2s_data.fast_buffer_pos = pos + to_copy;
	blake2s_data.fast_buffer_avail = available - to_copy;

	irq_unlock(key);

	blake2s_data.total_extracted_bytes += to_copy;

	LOG_DBG("ISR fast path: Delivered %u/%u bytes", to_copy, len);

	/* Trigger refill if fast buffer is low */
	if (blake2s_data.fast_buffer_avail < (FAST_BUFFER_SIZE / 4)) {
		k_work_submit(&blake2s_data.refill_work);
	}

	return to_copy;
}

/*
 * Public API: Add external entropy
 * This is the key API for quantum entropy from QEaaS
 * Based on add_entropy_cmd from linux-blake2s-entropy-pool
 */
static int entropy_blake2s_add_entropy(const struct device *dev,
					const uint8_t *data, uint16_t len,
					uint16_t entropy_bits)
{
	ARG_UNUSED(dev);
	int err;

	if (!data || len == 0) {
		return -EINVAL;
	}

	if (!blake2s_data.initialized) {
		return -ENODEV;
	}

	LOG_INF(">>> ADD_ENTROPY #%u: %u bytes, %u bits claimed <<<",
		blake2s_data.external_add_count + 1, len, entropy_bits);

	err = k_mutex_lock(&blake2s_data.lock, K_FOREVER);
	if (err != 0) {
		LOG_ERR("Failed to acquire lock for add_entropy: %d", err);
		return err;
	}

	/* Add entropy to pool (mix + credit) */
	add_entropy(&blake2s_data.pool, data, len);
	add_entropy_credit(&blake2s_data.pool, data, len, entropy_bits);

	blake2s_data.external_add_count++;
	blake2s_data.total_external_bytes += len;

	LOG_INF("External entropy added: pool bits=%u/%u",
		blake2s_data.pool.init_bits, POOL_SIZE_BYTES * 8);

	/* Refill fast buffer to propagate quantum entropy to ISR path */
	if (blake2s_data.fast_buffer_avail < FAST_BUFFER_SIZE) {
		refill_fast_buffer();
	}

	k_mutex_unlock(&blake2s_data.lock);

	return 0;
}

/*
 * Driver initialization
 */
static int entropy_blake2s_init(const struct device *dev)
{
	uint8_t initial_seed[INITIAL_SEED_SIZE];
	int ret;
	const char *hw_name = "unknown";

	/* Get hardware backend device from devicetree */
	blake2s_data.hw_dev = DEVICE_DT_GET(DT_INST_PHANDLE(0, hardware_device));
	
	if (!device_is_ready(blake2s_data.hw_dev)) {
		LOG_ERR("Hardware entropy backend not ready");
		return -ENODEV;
	}

	hw_name = blake2s_data.hw_dev->name;

	LOG_INF("========================================");
	LOG_INF("  BLAKE2s Entropy Pool Initialization  ");
	LOG_INF("========================================");
	LOG_INF("Pool size: %u bytes", POOL_SIZE_BYTES);
	LOG_INF("Refill threshold: %u bytes", POOL_REFILL_THRESHOLD);
	LOG_INF("Fast buffer: %u bytes", FAST_BUFFER_SIZE);
	LOG_INF("Backend: %s", hw_name);
	LOG_INF("Reference: linux-blake2s-entropy-pool");

	/* Initialize synchronization */
	k_mutex_init(&blake2s_data.lock);
	k_work_init(&blake2s_data.refill_work, hw_refill_work_handler);

	/* Initialize entropy pool (from reference implementation) */
	blake2s_init(&blake2s_data.pool.hash, BLAKE2S_HASH_SIZE);
	blake2s_data.pool.init_bits = 0;
	
	LOG_INF("BLAKE2s pool initialized (hash output: %u bytes)", BLAKE2S_HASH_SIZE);

	/* Bootstrap: Seed from hardware backend */
	LOG_INF("Bootstrapping with %u bytes from hardware...", INITIAL_SEED_SIZE);
	ret = get_hw_entropy(initial_seed, sizeof(initial_seed));
	if (ret != 0) {
		LOG_ERR("Failed to get initial seed: %d", ret);
		return ret;
	}

	/* Mix initial seed into pool with full entropy credit */
	add_entropy(&blake2s_data.pool, initial_seed, sizeof(initial_seed));
	credit_entropy(&blake2s_data.pool, sizeof(initial_seed) * 8);
	blake2s_data.total_hw_bytes = sizeof(initial_seed);

	LOG_INF("Initial seed mixed: pool bits=%u/%u",
		blake2s_data.pool.init_bits, POOL_SIZE_BYTES * 8);

	/* Pre-fill fast buffer for ISR */
	refill_fast_buffer();
	LOG_INF("Fast buffer initialized: %u bytes", FAST_BUFFER_SIZE);

	/* Mark as initialized */
	blake2s_data.initialized = true;

	LOG_INF("========================================");
	LOG_INF("  BLAKE2s Entropy Pool READY          ");
	LOG_INF("========================================");

	/* Clear sensitive data */
	memset(initial_seed, 0, sizeof(initial_seed));

	return 0;
}

/*
 * Driver API structure
 */
static DEVICE_API(entropy, entropy_blake2s_api) = {
	.get_entropy = entropy_blake2s_get_entropy,
	.get_entropy_isr = entropy_blake2s_get_entropy_isr,
	.add_entropy = entropy_blake2s_add_entropy,
};

/*
 * Device instantiation
 */
DEVICE_DT_INST_DEFINE(0,
		      entropy_blake2s_init,
		      NULL,
		      NULL,
		      NULL,
		      PRE_KERNEL_1,
		      CONFIG_ENTROPY_INIT_PRIORITY,
		      &entropy_blake2s_api);

/* SPDX-License-Identifier: Apache-2.0 */

/*
 * mbedtls_threading_zephyr.c — Zephyr k_mutex / k_condvar bindings for
 * MBEDTLS_THREADING_ALT (TF-PSA-crypto v1.x API).  Registered via
 * mbedtls_threading_set_alt() at SYS_INIT POST_KERNEL priority high
 * enough to land BEFORE Zephyr's own _mbedtls_init() (which calls
 * psa_crypto_init at POST_KERNEL default priority 40).
 *
 * Background: TF-PSA-crypto's internal state (key-slot table, slot
 * reader counters, internal allocator metadata) is not thread-safe
 * unless MBEDTLS_THREADING_C is enabled.  OpenThread's MLE security
 * thread calls into PSA crypto on its own thread; without a shared
 * mutex it races with our identity_sign calls, corrupting the slot
 * table, which eventually surfaces as PSA_ERROR_INSUFFICIENT_MEMORY
 * (-141) from psa_sign_hash on an unrelated, perfectly valid call.
 *
 * The threading_alt.h header in the mbedtls include path declares
 * mbedtls_platform_mutex_t / _condition_variable_t as opaque byte
 * buffers (NOT as struct k_mutex / k_condvar) — this avoids dragging
 * <zephyr/kernel.h> into OpenThread's mbedtls.cpp compile, which
 * would create a build-order deadlock against heap_constants.h.
 * The casts below + the static_asserts below pin the opaque buffer
 * sizes to the real Zephyr types at compile time.
 */

#include <mbedtls/threading.h>

#include <nn_osal/osal.h>

NN_OSAL_LOG_MODULE(mbedtls_threading);

/* Pin the opaque-buffer sizes in threading_alt.h to the real Zephyr
 * struct sizes.  If a future Zephyr bump grows either struct past
 * these budgets, the build will fail loudly here instead of silently
 * corrupting memory. */
BUILD_ASSERT(sizeof(struct k_mutex)   <= MBEDTLS_THREADING_ZEPHYR_MUTEX_SIZE,
	     "MBEDTLS_THREADING_ZEPHYR_MUTEX_SIZE too small");
BUILD_ASSERT(sizeof(struct k_condvar) <= MBEDTLS_THREADING_ZEPHYR_CONDVAR_SIZE,
	     "MBEDTLS_THREADING_ZEPHYR_CONDVAR_SIZE too small");

static inline struct k_mutex *to_kmutex(mbedtls_platform_mutex_t *m)
{
	return (struct k_mutex *)m;
}

static inline struct k_condvar *to_kcondvar(mbedtls_platform_condition_variable_t *c)
{
	return (struct k_condvar *)c;
}

/* ── mutex callbacks ─────────────────────────────────────────────── */

static int zmt_mutex_init(mbedtls_platform_mutex_t *m)
{
	if (!m) {
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	}
	return k_mutex_init(to_kmutex(m)) == 0 ? 0
					       : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static void zmt_mutex_destroy(mbedtls_platform_mutex_t *m)
{
	(void)m;
}

static int zmt_mutex_lock(mbedtls_platform_mutex_t *m)
{
	if (!m) {
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	}
	return k_mutex_lock(to_kmutex(m), K_FOREVER) == 0
		       ? 0
		       : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static int zmt_mutex_unlock(mbedtls_platform_mutex_t *m)
{
	if (!m) {
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	}
	return k_mutex_unlock(to_kmutex(m)) == 0
		       ? 0
		       : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

/* ── condition variable callbacks ────────────────────────────────── */

static int zmt_cond_init(mbedtls_platform_condition_variable_t *c)
{
	if (!c) {
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	}
	return k_condvar_init(to_kcondvar(c)) == 0
		       ? 0
		       : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

static void zmt_cond_destroy(mbedtls_platform_condition_variable_t *c)
{
	(void)c;
}

static int zmt_cond_signal(mbedtls_platform_condition_variable_t *c)
{
	if (!c) {
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	}
	(void)k_condvar_signal(to_kcondvar(c));
	return 0;
}

static int zmt_cond_broadcast(mbedtls_platform_condition_variable_t *c)
{
	if (!c) {
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	}
	(void)k_condvar_broadcast(to_kcondvar(c));
	return 0;
}

static int zmt_cond_wait(mbedtls_platform_condition_variable_t *c,
			 mbedtls_platform_mutex_t *m)
{
	if (!c || !m) {
		return MBEDTLS_ERR_THREADING_USAGE_ERROR;
	}
	return k_condvar_wait(to_kcondvar(c), to_kmutex(m), K_FOREVER) == 0
		       ? 0
		       : MBEDTLS_ERR_THREADING_USAGE_ERROR;
}

/* ── registration ────────────────────────────────────────────────── */

static int zephyr_mbedtls_threading_init(void)
{
	printk("SYS_INIT[mbedtls_threading]: set_alt begin\n");
	mbedtls_threading_set_alt(zmt_mutex_init,
				  zmt_mutex_destroy,
				  zmt_mutex_lock,
				  zmt_mutex_unlock,
				  zmt_cond_init,
				  zmt_cond_destroy,
				  zmt_cond_signal,
				  zmt_cond_broadcast,
				  zmt_cond_wait);
	printk("SYS_INIT[mbedtls_threading]: set_alt done\n");
	NN_LOG_INF("mbedtls threading_alt installed (k_mutex + k_condvar)");
	return 0;
}

/* POST_KERNEL priority 25 — runs BEFORE Zephyr's _mbedtls_init() which
 * uses CONFIG_KERNEL_INIT_PRIORITY_DEFAULT (=40) at POST_KERNEL.  Routed
 * through NN_OSAL_INIT_EARLY which maps to SYS_INIT(POST_KERNEL, level). */
NN_OSAL_INIT_EARLY(zephyr_mbedtls_threading_init, 25);

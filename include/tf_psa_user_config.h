/*
 * tf_psa_user_config.h — appended after Zephyr's config-tf-psa-crypto.h.
 *
 * Wired via CONFIG_TF_PSA_CRYPTO_USER_CONFIG_FILE in prj.conf.  Adds the
 * threading-safety macros that the base config explicitly does NOT
 * define, so TF-PSA-crypto serialises its internal state through our
 * registered k_mutex callbacks (see threading_alt.h + mbedtls_threading_
 * zephyr.c).
 *
 * Why: identity_sign was returning PSA_ERROR_INSUFFICIENT_MEMORY (-141)
 * non-deterministically during OTA, even though the mbedtls heap was
 * 99.7 % free.  The cause was concurrent access from OpenThread's MLE
 * security crypto, which corrupts PSA's key-slot table without
 * internal locking.  See feedback_psa_141_partial_mitigations.md.
 */

#ifndef TF_PSA_USER_CONFIG_H_
#define TF_PSA_USER_CONFIG_H_

#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT

#endif /* TF_PSA_USER_CONFIG_H_ */

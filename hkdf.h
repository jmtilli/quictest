#ifndef _HKDF_H_
#define _HKDF_H_

#include <stdint.h>
#include <stddef.h>
#include "sha_hp.h"

void hmac_hash(uint8_t finalresult[32],
               const void *initial_salt, size_t initial_salt_len,
               const void *material, size_t material_len);

void hkdf_extract(uint8_t result[32],
                  const void *initial_salt, size_t initial_salt_len,
                  const void *material, size_t material_len);

void hkdf_expand(void *result, uint16_t result_len,
                 const void *info, uint16_t info_len,
                 const uint8_t prk[32]);

void hkdf_form_label(char hkdf_label[520], uint16_t *hkdf_label_len,
                     const void *label, uint8_t label_len,
                     const void *context, uint8_t context_len,
		     uint16_t result_len);

void hkdf_expand_label(void *result, uint16_t result_len,
                       const void *label, uint8_t label_len,
                       const void *context, uint8_t context_len,
                       const uint8_t prk[32]);
void hkdf_expand_label_precalc(void *result, uint16_t result_len,
                               const char hkdf_label[520], uint16_t hkdf_label_len,
                               const uint8_t prk[32]);

struct sha256_ctx {
	sha256_ctx meat;
};

void sha256_ctx_init(struct sha256_ctx *ctx);

void sha256_feed(struct sha256_ctx *ctx, const void *data, size_t data_len);

struct hmac_ctx {
	struct sha256_ctx key_opad;
	struct sha256_ctx key_ipad;
};

void hmac_begin(struct hmac_ctx *ctx,
		const void *initial_salt, size_t initial_salt_len);

void hmac_do(const struct hmac_ctx *ctx,
             uint8_t finalresult[32],
             const void *material, size_t material_len);

struct hkdf_ctx {
	struct hmac_ctx hmac;
};

void hkdf_precalc(struct hkdf_ctx *ctx, const uint8_t prk[32]);

void hkdf_expand_precalc(const struct hkdf_ctx *ctx,
                         void *result, uint16_t result_len,
                         const void *info, uint16_t info_len);

void hkdf_expand_label_precalc2(const struct hkdf_ctx *ctx,
                                void *result, uint16_t result_len,
                                const char hkdf_label[520], uint16_t hkdf_label_len);

#endif

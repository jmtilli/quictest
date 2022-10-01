#include "hkdf.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha_hp.h"

void sha256_get(struct sha256_ctx *ctx, uint8_t result[32]);

void hmac_begin(struct hmac_ctx *ctx,
                const void *initial_salt, size_t initial_salt_len)
{
	struct sha256_ctx sha;
	uint8_t initial_salt64_xor[64] = {0};
	int i;

	if (initial_salt_len > 64)
	{
		sha256_ctx_init(&sha);
		sha256_feed(&sha, initial_salt, initial_salt_len);
		sha256_get(&sha, initial_salt64_xor);
	}
	else
	{
		memcpy(initial_salt64_xor, initial_salt, initial_salt_len);
	}

	for (i = 0; i < 64; i++)
	{
		initial_salt64_xor[i] ^= 0x36;
	}
	sha256_ctx_init(&ctx->key_ipad);
	sha256_feed(&ctx->key_ipad, initial_salt64_xor, 64);

	for (i = 0; i < 64; i++)
	{
		initial_salt64_xor[i] ^= (0x36^0x5c);
	}
	sha256_ctx_init(&ctx->key_opad);
	sha256_feed(&ctx->key_opad, initial_salt64_xor, 64);
}

void hmac_do(const struct hmac_ctx *constctx,
             uint8_t finalresult[32],
             const void *material, size_t material_len)
{
	struct hmac_ctx ctx = *constctx;
	uint8_t result[32];

	sha256_feed(&ctx.key_ipad, material, material_len);
	sha256_get(&ctx.key_ipad, result);

	sha256_feed(&ctx.key_opad, result, 32);
	sha256_get(&ctx.key_opad, finalresult);
}


void sha256_ctx_init(struct sha256_ctx *ctx)
{
#ifdef SHA_HP
	sha256_init(&ctx->meat);
#else
	sha256_pd_init(&ctx->meat);
#endif
}

void sha256_feed(struct sha256_ctx *ctx, const void *data, size_t data_len)
{
#if 0
	const uint8_t *bytes = data;
	int i;
	printf("----\n");
	for (i = 0; i < data_len; i++)
	{
		printf("%.2x, ", bytes[i]);
	}
	printf("\n");
	printf("----\n");
#endif

#ifdef SHA_HP
	sha256_update(&ctx->meat, data, data_len);
#else
	sha256_append(&ctx->meat, data, data_len);
#endif
}

void sha256_get(struct sha256_ctx *ctx, uint8_t result[32])
{
#ifdef SHA_HP
	sha256_final(&ctx->meat, result);
#else
	sha256_finalize_bytes(&ctx->meat, result);
#endif
}

void hmac_hash(uint8_t finalresult[32],
               const void *initial_salt, size_t initial_salt_len,
               const void *material, size_t material_len)
{
	//const uint8_t block_size = 64;
	uint8_t initial_salt64[64] = {0};
	uint8_t initial_salt64_xor[64];
	uint8_t result[32];
	size_t i;
	struct sha256_ctx ctx;
	sha256_ctx_init(&ctx);
	if (initial_salt_len > 64)
	{
		sha256_feed(&ctx, initial_salt, initial_salt_len);
		sha256_get(&ctx, initial_salt64);
	}
	else
	{
		memcpy(initial_salt64, initial_salt, initial_salt_len);
	}

	memcpy(initial_salt64_xor, initial_salt64, 64);
	for (i = 0; i < 64; i++)
	{
		initial_salt64_xor[i] ^= 0x36;
	}
	sha256_ctx_init(&ctx);
	sha256_feed(&ctx, initial_salt64_xor, 64);
	sha256_feed(&ctx, material, material_len);
	sha256_get(&ctx, result);


	memcpy(initial_salt64_xor, initial_salt64, 64);
	for (i = 0; i < 64; i++)
	{
		initial_salt64_xor[i] ^= 0x5c;
	}
	sha256_ctx_init(&ctx);
	sha256_feed(&ctx, initial_salt64_xor, 64);
	sha256_feed(&ctx, result, 32);
	sha256_get(&ctx, finalresult);
	// H((K' xor opad) || H((K' xor ipad) || m))
}

void hkdf_extract(uint8_t result[32],
                  const void *initial_salt, size_t initial_salt_len,
                  const void *material, size_t material_len)
{
	return hmac_hash(result, initial_salt, initial_salt_len, material, material_len);
}

void hkdf_precalc(struct hkdf_ctx *ctx, const uint8_t prk[32])
{
	hmac_begin(&ctx->hmac, prk, 32);
}

void hkdf_expand_precalc(const struct hkdf_ctx *ctx,
                         void *result, uint16_t result_len,
                         const void *info, uint16_t info_len)
{
	const size_t hash_len = 32;
	size_t N;
	uint8_t T[32];
	uint8_t Tinfo[32+info_len+1];
	uint16_t Tinfo_len;
	size_t iter;
	size_t tocopy = 32;
	char *cresult = (char*)result;
	memcpy(Tinfo, info, info_len);
	Tinfo[info_len] = 0x01;
	Tinfo_len = info_len+1;
	N = (result_len+hash_len-1)/hash_len;
	if (N > 255)
	{
		abort();
	}
	for (iter = 1; iter <= N; iter++)
	{
		//printf("iter %d\n", (int)iter);
		//hmac_hash(T, prk, 32, Tinfo, Tinfo_len);
		hmac_do(&ctx->hmac, T, Tinfo, Tinfo_len);
		memcpy(Tinfo, T, 32);
		memcpy(Tinfo+32, info, info_len);
		Tinfo[32+info_len] = iter+1;
		Tinfo_len = 32+info_len+1;
		if (result_len < tocopy)
		{
			tocopy = result_len;
		}
		memcpy(cresult, T, tocopy);
		cresult += tocopy;
		result_len -= tocopy;
	}
}

void hkdf_expand(void *result, uint16_t result_len,
                 const void *info, uint16_t info_len,
                 const uint8_t prk[32])
{
	const size_t hash_len = 32;
	size_t N;
	uint8_t T[32];
	uint8_t Tinfo[32+info_len+1];
	uint16_t Tinfo_len;
	size_t iter;
	size_t tocopy = 32;
	char *cresult = (char*)result;
	memcpy(Tinfo, info, info_len);
	Tinfo[info_len] = 0x01;
	Tinfo_len = info_len+1;
	N = (result_len+hash_len-1)/hash_len;
	if (N > 255)
	{
		abort();
	}
	for (iter = 1; iter <= N; iter++)
	{
		//printf("iter %d\n", (int)iter);
		hmac_hash(T, prk, 32, Tinfo, Tinfo_len);
		memcpy(Tinfo, T, 32);
		memcpy(Tinfo+32, info, info_len);
		Tinfo[32+info_len] = iter+1;
		Tinfo_len = 32+info_len+1;
		if (result_len < tocopy)
		{
			tocopy = result_len;
		}
		memcpy(cresult, T, tocopy);
		cresult += tocopy;
		result_len -= tocopy;
	}
}

void hkdf_form_label(char hkdf_label[520], uint16_t *hkdf_label_len,
                     const void *label, uint8_t label_len,
                     const void *context, uint8_t context_len,
		     uint16_t result_len)
{
	size_t off = 0;
	const size_t siz_hkdf_label = 520;
	if (hkdf_label == NULL || hkdf_label_len == NULL)
	{
		abort();
	}
	hkdf_label[off++] = (result_len>>8)&0xFF;
	hkdf_label[off++] = (result_len>>0)&0xFF;
	hkdf_label[off++] = (char)(label_len+6);
	memcpy(hkdf_label+off, "tls13 ", 6);
	off += 6;
	if (off + label_len > siz_hkdf_label)
	{
		abort();
	}
	memcpy(hkdf_label+off, label, label_len);
	off += label_len;
	if (off + 1 > siz_hkdf_label)
	{
		abort();
	}
	hkdf_label[off++] = (char)context_len;
	if (off + context_len > siz_hkdf_label)
	{
		abort();
	}
	memcpy(hkdf_label+off, context, context_len);
	off += context_len;
	*hkdf_label_len = off;
}

void hkdf_expand_label(void *result, uint16_t result_len,
                       const void *label, uint8_t label_len,
                       const void *context, uint8_t context_len,
                       const uint8_t prk[32])
{
	char hkdf_label[520];
	uint16_t hkdf_label_len = 0;
	hkdf_form_label(hkdf_label, &hkdf_label_len, label, label_len, context, context_len, result_len);
	hkdf_expand(result, result_len, hkdf_label, hkdf_label_len, prk);
}
void hkdf_expand_label_precalc(void *result, uint16_t result_len,
                               const char hkdf_label[520], uint16_t hkdf_label_len,
                               const uint8_t prk[32])
{
	hkdf_expand(result, result_len, hkdf_label, hkdf_label_len, prk);
}
void hkdf_expand_label_precalc2(const struct hkdf_ctx *ctx,
                                void *result, uint16_t result_len,
                                const char hkdf_label[520], uint16_t hkdf_label_len)
{
	//hkdf_expand(result, result_len, hkdf_label, hkdf_label_len, prk);
	hkdf_expand_precalc(ctx, result, result_len, hkdf_label, hkdf_label_len);
}

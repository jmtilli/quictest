#include "hkdf.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha_hp.h"


// Public domain code begins, https://github.com/983/SHA-256

#if 0

#define SHA256_HEX_SIZE (64 + 1)
#define SHA256_BYTES_SIZE 32

/*
 * Compute the SHA-256 checksum of a memory region given a pointer and
 * the size of that memory region.
 * The output is a hexadecimal string of 65 characters.
 * The last character will be the null-character.
 */
void sha256_hex(const void *src, size_t n_bytes, char *dst_hex65);

void sha256_bytes(const void *src, size_t n_bytes, void *dst_bytes32);

typedef struct sha256 {
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t n_bits;
    uint8_t buffer_counter;
} sha256;

/* Functions to compute streaming SHA-256 checksums. */
void sha256_init(struct sha256 *sha);
void sha256_append(struct sha256 *sha, const void *data, size_t n_bytes);
void sha256_finalize_hex(struct sha256 *sha, char *dst_hex65);
void sha256_finalize_bytes(struct sha256 *sha, void *dst_bytes32);

// Public domain header ends, public domain C code begins

static inline uint32_t rotr(uint32_t x, int n){
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t step1(uint32_t e, uint32_t f, uint32_t g){
    return (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ ((~ e) & g));
}

static inline uint32_t step2(uint32_t a, uint32_t b, uint32_t c){
    return (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
}

static inline void update_w(uint32_t *w, int i, const uint8_t *buffer){
    int j;
    for (j = 0; j < 16; j++){
        if (i < 16){
            w[j] =
                ((uint32_t)buffer[0] << 24) |
                ((uint32_t)buffer[1] << 16) |
                ((uint32_t)buffer[2] <<  8) |
                ((uint32_t)buffer[3]);
            buffer += 4;
        }else{
            uint32_t a = w[(j + 1) & 15];
            uint32_t b = w[(j + 14) & 15];
            uint32_t s0 = (rotr(a,  7) ^ rotr(a, 18) ^ (a >>  3));
            uint32_t s1 = (rotr(b, 17) ^ rotr(b, 19) ^ (b >> 10));
            w[j] += w[(j + 9) & 15] + s0 + s1;
        }
    }
}

static void sha256_block(struct sha256 *sha){
    uint32_t *state = sha->state;

    static const uint32_t k[8 * 8] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    uint32_t w[16];

    int i, j;
    for (i = 0; i < 64; i += 16){
        update_w(w, i, sha->buffer);

        for (j = 0; j < 16; j += 4){
            uint32_t temp;
            temp = h + step1(e, f, g) + k[i + j + 0] + w[j + 0];
            h = temp + d;
            d = temp + step2(a, b, c);
            temp = g + step1(h, e, f) + k[i + j + 1] + w[j + 1];
            g = temp + c;
            c = temp + step2(d, a, b);
            temp = f + step1(g, h, e) + k[i + j + 2] + w[j + 2];
            f = temp + b;
            b = temp + step2(c, d, a);
            temp = e + step1(f, g, h) + k[i + j + 3] + w[j + 3];
            e = temp + a;
            a = temp + step2(b, c, d);
        }
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(struct sha256 *sha){
    sha->state[0] = 0x6a09e667;
    sha->state[1] = 0xbb67ae85;
    sha->state[2] = 0x3c6ef372;
    sha->state[3] = 0xa54ff53a;
    sha->state[4] = 0x510e527f;
    sha->state[5] = 0x9b05688c;
    sha->state[6] = 0x1f83d9ab;
    sha->state[7] = 0x5be0cd19;
    sha->n_bits = 0;
    sha->buffer_counter = 0;
}

void sha256_append_byte(struct sha256 *sha, uint8_t byte){
    sha->buffer[sha->buffer_counter++] = byte;
    sha->n_bits += 8;

    if (sha->buffer_counter == 64){
        sha->buffer_counter = 0;
        sha256_block(sha);
    }
}

void sha256_append(struct sha256 *sha, const void *src, size_t n_bytes){
    const uint8_t *bytes = (const uint8_t*)src;
    size_t i;

    for (i = 0; i < n_bytes; i++){
        sha256_append_byte(sha, bytes[i]);
    }
}

void sha256_finalize(struct sha256 *sha){
    int i;
    uint64_t n_bits = sha->n_bits;

    sha256_append_byte(sha, 0x80);

    while (sha->buffer_counter != 56){
        sha256_append_byte(sha, 0);
    }

    for (i = 7; i >= 0; i--){
        uint8_t byte = (n_bits >> 8 * i) & 0xff;
        sha256_append_byte(sha, byte);
    }
}

void sha256_finalize_hex(struct sha256 *sha, char *dst_hex65){
    int i, j;
    sha256_finalize(sha);

    for (i = 0; i < 8; i++){
        for (j = 7; j >= 0; j--){
            uint8_t nibble = (sha->state[i] >> j * 4) & 0xf;
            *dst_hex65++ = "0123456789abcdef"[nibble];
        }
    }

    *dst_hex65 = '\0';
}

void sha256_finalize_bytes(struct sha256 *sha, void *dst_bytes32){
    uint8_t *ptr = (uint8_t*)dst_bytes32;
    int i, j;
    sha256_finalize(sha);

    for (i = 0; i < 8; i++){
        for (j = 3; j >= 0; j--){
            *ptr++ = (sha->state[i] >> j * 8) & 0xff;
        }
    }
}

void sha256_hex(const void *src, size_t n_bytes, char *dst_hex65){
    struct sha256 sha;

    sha256_init(&sha);

    sha256_append(&sha, src, n_bytes);

    sha256_finalize_hex(&sha, dst_hex65);
}

void sha256_bytes(const void *src, size_t n_bytes, void *dst_bytes32){
    struct sha256 sha;

    sha256_init(&sha);

    sha256_append(&sha, src, n_bytes);

    sha256_finalize_bytes(&sha, dst_bytes32);
}

#endif

// Public domain code ends

struct sha256_ctx {
	//struct sha256 meat;
	sha256_ctx meat;
};

void sha256_ctx_init(struct sha256_ctx *ctx)
{
	sha256_init(&ctx->meat);
}

void sha256_feed(struct sha256_ctx *ctx, const void *data, size_t data_len)
{
	//sha256_append(&ctx->meat, data, data_len);
	sha256_update(&ctx->meat, data, data_len);
}

void sha256_get(struct sha256_ctx *ctx, uint8_t result[32])
{
	//sha256_finalize_bytes(&ctx->meat, result);
	sha256_final(&ctx->meat, result);
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Public domain code begins, https://github.com/983/SHA-256

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

// Public domain code ends

struct sha256_ctx {
	struct sha256 meat;
};

void sha256_ctx_init(struct sha256_ctx *ctx)
{
	sha256_init(&ctx->meat);
}

void sha256_feed(struct sha256_ctx *ctx, const void *data, size_t data_len)
{
	sha256_append(&ctx->meat, data, data_len);
}

void sha256_get(struct sha256_ctx *ctx, uint8_t result[32])
{
	sha256_finalize_bytes(&ctx->meat, result);
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

void hkdf_expand_label(void *result, uint16_t result_len,
                       const void *label, uint8_t label_len,
                       const void *context, uint8_t context_len,
                       const uint8_t prk[32])
{
	char hkdf_label[512];
	size_t off = 0;
	hkdf_label[off++] = (result_len>>8)&0xFF;
	hkdf_label[off++] = (result_len>>0)&0xFF;
	memcpy(hkdf_label+off, "tls13 ", 6);
	off += 6;
	if (off + label_len > 512)
	{
		abort();
	}
	memcpy(hkdf_label+off, label, label_len);
	off += label_len;
	if (off + context_len > 512)
	{
		abort();
	}
	memcpy(hkdf_label+off, context, context_len);
	off += context_len;
	hkdf_expand(result, result_len, hkdf_label, off, prk);
}

void hkdf_test1(void)
{
	uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
	uint8_t salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
	uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
	uint8_t prk[32];
	uint8_t result[42];
	uint8_t L = 42;
	int i;
	hkdf_extract(prk, salt, sizeof(salt), ikm, sizeof(ikm));
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", prk[i]);
	}
	printf("\n");
	printf("expected: 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5\n");
	hkdf_expand(result, L, info, sizeof(info), prk);
	for (i = 0; i < L; i++)
	{
		printf("%.2x ", result[i]);
	}
	printf("\n");
	printf("expected: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865\n");
}

void hkdf_test2(void)
{
	uint8_t ikm[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
	uint8_t salt[] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
	uint8_t info[] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
	uint8_t prk[32];
	uint8_t result[82];
	uint8_t L = 82;
	int i;
	hkdf_extract(prk, salt, sizeof(salt), ikm, sizeof(ikm));
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", prk[i]);
	}
	printf("\n");
	printf("expected: 06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244\n");
	hkdf_expand(result, L, info, sizeof(info), prk);
	for (i = 0; i < L; i++)
	{
		printf("%.2x ", result[i]);
	}
	printf("\n");
	printf("expected: b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87\n");
}

void hkdf_test3(void)
{
	uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
	uint8_t salt[] = {};
	uint8_t info[] = {};
	uint8_t prk[32];
	uint8_t result[42];
	uint8_t L = 42;
	int i;
	hkdf_extract(prk, salt, sizeof(salt), ikm, sizeof(ikm));
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", prk[i]);
	}
	printf("\n");
	printf("expected: 19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04\n");
	hkdf_expand(result, L, info, sizeof(info), prk);
	for (i = 0; i < L; i++)
	{
		printf("%.2x ", result[i]);
	}
	printf("\n");
	printf("expected: 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8\n");
}

void hkdf_test(void)
{
	hkdf_test1();
	printf("---\n");
	hkdf_test2();
	printf("---\n");
	hkdf_test3();
}

/*
 * HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog")
 * = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
 *
 * HMAC_SHA256("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog", "message")
 * = 5597b93a2843078cbb0c920ae41dfe20f1685e10c67e423c11ab91adfc319d12
 */

int main(int argc, char **argv)
{
	uint8_t finalresult[32];
	int i;
	char *key = "key";
	char *data = "The quick brown fox jumps over the lazy dog";
	uint8_t expected1[32] = {0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8};
	uint8_t expected2[32] = {0x55, 0x97, 0xb9, 0x3a, 0x28, 0x43, 0x07, 0x8c, 0xbb, 0x0c, 0x92, 0x0a, 0xe4, 0x1d, 0xfe, 0x20, 0xf1, 0x68, 0x5e, 0x10, 0xc6, 0x7e, 0x42, 0x3c, 0x11, 0xab, 0x91, 0xad, 0xfc, 0x31, 0x9d, 0x12};
	hmac_hash(finalresult, key, strlen(key), data, strlen(data));
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", finalresult[i]);
	}
	printf("\n");
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", expected1[i]);
	}
	printf("\n");
	printf("---\n");
	key = "The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog";
	data = "message";
	hmac_hash(finalresult, key, strlen(key), data, strlen(data));
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", finalresult[i]);
	}
	printf("\n");
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", expected2[i]);
	}
	printf("\n");
	printf("---\n");
	hkdf_test();
	return 0;
}

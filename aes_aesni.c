// Compile with -march=skylake
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>
#include "aes_aesni.h"

#if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || defined(i386) || defined(__i386) || defined(__i386__) || defined(__IA32__) || defined(_M_IX86) || defined(__X86__) || defined(_X86_) || defined(__I86__) || defined(__386)

/*
_mm_aeskeygenassist_si128, args: key, constant
_mm_aesenc_si128, args: block, key
_mm_aesenclast_si128, args: block, key
_mm_xor_si128, args: a, b
_mm_add_epi32, args: a,b 
_mm_loadu_si128: load from non-__m128i memory block into register
_mm_storeu_si128, args: dst, src: store into non-__m128i memory block from reg

Apparently encryption is:
block = _mm_xor_si128 block, key0
block = _mm_aesenc_si128 block, key1
block = _mm_aesenc_si128 block, key2
block = _mm_aesenc_si128 block, key3
block = _mm_aesenc_si128 block, key4
block = _mm_aesenc_si128 block, key5
block = _mm_aesenc_si128 block, key6
block = _mm_aesenc_si128 block, key7
block = _mm_aesenc_si128 block, key8
block = _mm_aesenc_si128 block, key9
block = _mm_aesenclast_si128 block, key10

Apparently expansion is:
store key into array
aeskeygenassist res, key, 0x1 // res = _mm_aeskeygenassist_si128 key, 0x1
res = _mm_shuffle_epi32 res, 0xff
tmp = _mm_slli_si128 key, 0x4
key = _mm_xor_si128 key, tmp // ???
tmp = _mm_slli_si128 key, 0x4
key = _mm_xor_si128 key, tmp // ???
tmp = _mm_slli_si128 key, 0x4
key = _mm_xor_si128 key, tmp // ???
key = _mm_xor_si128 key, res // ???
store key into array
aeskeygenassist res, key, 0x2
aeskeygenassist res, key, 0x4
aeskeygenassist res, key, 0x8
aeskeygenassist res, key, 0x10
aeskeygenassist res, key, 0x20
aeskeygenassist res, key, 0x40
aeskeygenassist res, key, 0x80
aeskeygenassist res, key, 0x1B
aeskeygenassist res, key, 0x36
*/

/*
 * TODO:
 * _mm_slli_si128
 * _mm_shuffle_epi32
 */

#define cpuid1ecx(out)                                  \
	asm("movl $1, %%eax\n\t"                        \
	    "cpuid\n\t"                                 \
	    "movl %%ecx, %0\n\t"                        \
	    : "=r" (out)                                \
	    :                                           \
	    : "eax", "ebx", "ecx", "edx")

int aesni_has_ni(void)
{
	uint32_t capabilities;
	cpuid1ecx(capabilities);
	return ((capabilities & (1<<25)) != 0);
}

struct aesni_expanded_key {
	__m128i data[11];
};

struct aesni_expanded_key *aesni_alloc_expanded_key(void)
{
	return aligned_alloc(16, sizeof(struct aesni_expanded_key));
}
void aesni_free_expanded_key(struct aesni_expanded_key *k)
{
	free(k);
}

#define KEYEXP_HELPER \
	do { \
		res = _mm_shuffle_epi32(res, 0xff); \
		tmp = _mm_slli_si128(keyreg, 0x4); \
		keyreg = _mm_xor_si128(keyreg, tmp); \
		tmp = _mm_slli_si128(keyreg, 0x4); \
		keyreg = _mm_xor_si128(keyreg, tmp); \
		tmp = _mm_slli_si128(keyreg, 0x4); \
		keyreg = _mm_xor_si128(keyreg, tmp); \
		keyreg = _mm_xor_si128(keyreg, res); \
	} while(0)

__m128i aesni_keyexp_helper_fn(__m128i keyreg, __m128i res)
{
	__m128i tmp;
	res = _mm_shuffle_epi32(res, 0xff);
	tmp = _mm_slli_si128(keyreg, 0x4);
	keyreg = _mm_xor_si128(keyreg, tmp);
	tmp = _mm_slli_si128(keyreg, 0x4);
	keyreg = _mm_xor_si128(keyreg, tmp);
	tmp = _mm_slli_si128(keyreg, 0x4);
	keyreg = _mm_xor_si128(keyreg, tmp);
	keyreg = _mm_xor_si128(keyreg, res);
	return keyreg;
}

void aesni_128_keyexp(struct aesni_expanded_key *key, const uint8_t keymaterial[16])
{
	__m128i *keyout = (__m128i*)key->data;
	__m128i keyreg = _mm_loadu_si128((const __m128i*)keymaterial);
	__m128i res;
	__m128i tmp;

	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x1);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x2);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x4);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x8);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x10);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x20);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x40);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x80);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x1B);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;

	res = _mm_aeskeygenassist_si128(keyreg, 0x36);
	KEYEXP_HELPER;
	//keyreg = aesni_keyexp_helper_fn(keyreg, res);
	*keyout = keyreg;
	keyout += 1;
}

void aesni_128_encrypt(const struct aesni_expanded_key *key, uint8_t block[16])
{
	__m128i blockreg = _mm_loadu_si128((__m128i*)block);
	const __m128i *key0 = (const __m128i*)key->data;
	const __m128i *key1 = key0 + 1;
	const __m128i *key2 = key1 + 1;
	const __m128i *key3 = key2 + 1;
	const __m128i *key4 = key3 + 1;
	const __m128i *key5 = key4 + 1;
	const __m128i *key6 = key5 + 1;
	const __m128i *key7 = key6 + 1;
	const __m128i *key8 = key7 + 1;
	const __m128i *key9 = key8 + 1;
	const __m128i *key10 = key9 + 1;
	blockreg = _mm_xor_si128(blockreg, *key0);
	blockreg = _mm_aesenc_si128(blockreg, *key1);
	blockreg = _mm_aesenc_si128(blockreg, *key2);
	blockreg = _mm_aesenc_si128(blockreg, *key3);
	blockreg = _mm_aesenc_si128(blockreg, *key4);
	blockreg = _mm_aesenc_si128(blockreg, *key5);
	blockreg = _mm_aesenc_si128(blockreg, *key6);
	blockreg = _mm_aesenc_si128(blockreg, *key7);
	blockreg = _mm_aesenc_si128(blockreg, *key8);
	blockreg = _mm_aesenc_si128(blockreg, *key9);
	blockreg = _mm_aesenclast_si128(blockreg, *key10);
	_mm_storeu_si128((__m128i*)block, blockreg);
}

#endif

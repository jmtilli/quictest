#ifndef _AES_AESNI_H_
#define _AES_AESNI_H_

#include <stdint.h>

struct aesni_expanded_key;

#if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || defined(i386) || defined(__i386) || defined(__i386__) || defined(__IA32__) || defined(_M_IX86) || defined(__X86__) || defined(_X86_) || defined(__I86__) || defined(__386)
int aesni_has_ni(void);
struct aesni_expanded_key *aesni_alloc_expanded_key(void);
void aesni_free_expanded_key(struct aesni_expanded_key *k);
void aesni_128_keyexp(struct aesni_expanded_key *key, const uint8_t keymaterial[16]);
void aesni_128_encrypt(const struct aesni_expanded_key *key, uint8_t block[16]);
#else
static inline int aesni_has_ni()
{
	return 0;
}
static inline struct aesni_expanded_key *aesni_alloc_expanded_key(void)
{
	return NULL;
}
static inline void aesni_free_expanded_key(struct aesni_expanded_key *k)
{
}
static inline void aesni_128_keyexp(struct aesni_expanded_key *key, const uint8_t keymaterial[16])
{
}
static inline void aesni_128_encrypt(const struct aesni_expanded_key *key, uint8_t block[16])
{
}
#endif

#endif

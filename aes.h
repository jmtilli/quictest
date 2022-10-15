#ifndef _AES_H_
#define _AES_H_
#include <stdint.h>
#include "aes_aesni.h"

struct aes_initer {
	int ni;
};

void aes_initer_init(struct aes_initer *in);

struct expanded_key {
	union {
		uint32_t W[44];
		struct aesni_expanded_key *niimpl;
	} u;
	int ni;
};

void calc_expanded_key(struct aes_initer *in, struct expanded_key *ex, const uint32_t key[4]);
void free_expanded_key(struct expanded_key *ex);

/*
 * State
 */

struct aes_state {
	uint8_t state[16];
};

void aes128(const struct expanded_key *e, uint8_t data[16]);

// Internal functions that we nevertheless test:
void mix_columns(struct aes_state *s);
uint8_t gmul(uint8_t a, uint8_t b);

#endif

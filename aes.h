#ifndef _AES_H_
#define _AES_H_
#include <stdint.h>

struct expanded_key{
	uint32_t W[44];
};

void calc_expanded_key(struct expanded_key *ex, const uint32_t key[4]);

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

#include "aes.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void aes_initer_init(struct aes_initer *in)
{
	in->ni = !!(aesni_has_ni());
}

/*
 * Galois field multiplication
 */
uint8_t gmod0(uint16_t a)
{
	const uint16_t b = 0x11B;
	for (int i = 15; i >= 8; i--)
	{
		if ((a>>i)&1)
		{
			a ^= b<<(i-8);
		}
	}
	return a;
}
uint8_t gmul0(uint8_t a, uint8_t b)
{
	uint16_t c = 0;
	for (int i = 0; i < 8; i++)
	{
		if ((b>>i)&1)
		{
			c ^= (a<<i);
		}
	}
	return gmod0(c);
}
uint8_t gmod(uint16_t a)
{
	const uint16_t b = 0x11B;
#if 0
	int bit;
	while (a&0xFF00)
	{
		bit = ffs(a&0xFF00)-1;
		a ^= b<<(bit-8);
	}
#else
	for (int i = 15; i >= 8; i--)
	{
		if ((a>>i)&1)
		{
			a ^= b<<(i-8);
		}
	}
#endif
	return a;
}
uint8_t gmul(uint8_t a, uint8_t b)
{
	uint16_t c = 0;
	int bit;
	while (b)
	{
		bit = ffs(b)-1;
		c ^= (a<<bit);
		b ^= (1<<bit);
	}
	return gmod(c);
}
const uint8_t gmul2tbl[256] = {
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
	0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
	0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
	0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
	0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
	0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
	0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
	0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
	0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
	0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
	0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15,
	0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
	0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35,
	0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
	0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
	0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
	0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
	0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
	0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
	0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
	0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
	0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
	0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5,
	0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
	0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5,
	0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5,
};
static inline uint8_t gmul2(uint8_t a)
{
	return gmul2tbl[a];
}

/*
 * AES S-box
 */

const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};
const uint8_t inv_sbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

static inline uint8_t S(uint8_t x)
{
	return sbox[x];
}
static inline uint8_t invS(uint8_t x)
{
	return inv_sbox[x];
}

/*
 * AES-128 key schedule implementation
 */

struct rcons {
	uint32_t rcon[11];
};

static inline uint32_t rot_word(uint32_t x)
{
	return ((x<<8)&0xFFFFFF00U) | ((x>>24)&0xFFU);
}
static inline uint32_t sub_word(uint32_t x)
{
	return (S((x>>24)&0xFF)<<24) |
	       (S((x>>16)&0xFF)<<16) |
	       (S((x>>8)&0xFF)<<8) |
	       (S((x>>0)&0xFF)<<0);
}
static inline void calc_rcons(struct rcons *rc)
{
	int i;
	uint8_t rcs[11];
	rcs[1] = 1;
	rc->rcon[1] = ((uint32_t)rcs[1])<<24;
	for (i = 2; i < 11; i++)
	{
		uint8_t last = rcs[i-1];
		if (last < 0x80)
		{
			rcs[i] = 2*last;
		}
		else
		{
			rcs[i] = (uint8_t)((2*(uint32_t)last)^0x11B);
		}
		rc->rcon[i] = ((uint32_t)rcs[i])<<24;
	}
}
void calc_expanded_key(struct aes_initer *in, struct expanded_key *ex, const uint32_t key[4])
{
	int i;
	struct rcons rc;
	ex->ni = in->ni;
	if (ex->ni)
	{
		uint8_t key8[16] = {
			key[0]>>24, key[0]>>16, key[0]>>8, key[0],
			key[1]>>24, key[1]>>16, key[1]>>8, key[1],
			key[2]>>24, key[2]>>16, key[2]>>8, key[2],
			key[3]>>24, key[3]>>16, key[3]>>8, key[3]
		};
		ex->u.niimpl = aesni_alloc_expanded_key();
		aesni_128_keyexp(ex->u.niimpl, key8);
		return;
	}
	calc_rcons(&rc);
	for (i = 0; i < 4; i++)
	{
		ex->u.W[i] = key[i];
	}
	for (i = 4; i < 44; i++)
	{
		if ((i%4) == 0)
		{
			ex->u.W[i] = sub_word(rot_word(ex->u.W[i-1])) ^ rc.rcon[i/4];
		}
		else
		{
			ex->u.W[i] = ex->u.W[i-1];
		}
		ex->u.W[i] ^= ex->u.W[i-4];
	}
}
void free_expanded_key(struct expanded_key *ex)
{
	if (ex->ni)
	{
		aesni_free_expanded_key(ex->u.niimpl);
		ex->u.niimpl = NULL;
	}
}

/*
 * State
 */

/*
struct aes_state {
	uint8_t state[16];
};
struct expanded_key{
	uint32_t W[44];
};
*/

static inline void add_round_key(struct aes_state *s, const struct expanded_key *e, int round)
{
	int i;
	for (i = 0; i < 16; i++)
	{
#ifdef AESDEBUG
		printf(" %.2x", (e->u.W[4*round+(i/4)] >> (24-8*(i%4)))&0xFF);
#endif
		s->state[i] ^= (e->u.W[4*round+(i/4)] >> (24-8*(i%4)))&0xFF;
		//s->state[i] ^= (e->W[4*round+(i/4)] >> (8*(i%4)));
	}
#ifdef AESDEBUG
	printf("\n");
#endif
}

static inline void sub_bytes(struct aes_state *s)
{
	int i;
	for (i = 0; i < 16; i++)
	{
		s->state[i] = S(s->state[i]);
	}
}

static inline void shift_rows(struct aes_state *s)
{
	//struct aes_state s2;
	uint8_t tmp;

	// 0, 4, 8, 12 stays the same

	tmp = s->state[1];
	s->state[1] = s->state[5];
	s->state[5] = s->state[9];
	s->state[9] = s->state[13];
	s->state[13] = tmp;

	tmp = s->state[2];
	s->state[2] = s->state[10];
	s->state[10] = s->state[2];

	tmp = s->state[3];
	s->state[3] = s->state[15];
	s->state[15] = s->state[11];
	s->state[11] = s->state[7];
	s->state[7] = tmp;

	tmp = s->state[6];
	s->state[6] = s->state[14];
	s->state[14] = tmp;

	/*
	s2.state[0] = s->state[0];
	s2.state[1] = s->state[5];
	s2.state[2] = s->state[10];
	s2.state[3] = s->state[15];
	s2.state[4] = s->state[4];
	s2.state[5] = s->state[9];
	s2.state[6] = s->state[14];
	s2.state[7] = s->state[3];
	s2.state[8] = s->state[8];
	s2.state[9] = s->state[13];
	s2.state[10] = s->state[2];
	s2.state[11] = s->state[7];
	s2.state[12] = s->state[12];
	s2.state[13] = s->state[1];
	s2.state[14] = s->state[6];
	s2.state[15] = s->state[11];
	*s = s2;
	*/
}

void mix_columns(struct aes_state *s)
{
	uint8_t a0j, a1j, a2j, a3j;
	uint8_t b0j, b1j, b2j, b3j;
	uint8_t a0j_2, a1j_2, a2j_2, a3j_2;
	uint8_t a0j_3, a1j_3, a2j_3, a3j_3;

	int i;
	for (i = 0; i < 4; i++)
	{
		a0j = s->state[4*i+0];
		a1j = s->state[4*i+1];
		a2j = s->state[4*i+2];
		a3j = s->state[4*i+3];
		a0j_2 = gmul2(a0j);
		a1j_2 = gmul2(a1j);
		a2j_2 = gmul2(a2j);
		a3j_2 = gmul2(a3j);
		//a0j_2 = gmul(a0j, 2);
		//a1j_2 = gmul(a1j, 2);
		//a2j_2 = gmul(a2j, 2);
		//a3j_2 = gmul(a3j, 2);
		a0j_3 = a0j_2 ^ a0j;
		a1j_3 = a1j_2 ^ a1j;
		a2j_3 = a2j_2 ^ a2j;
		a3j_3 = a3j_2 ^ a3j;
		b0j =      a0j_2  ^      a1j_3  ^      a2j    ^      a3j;
		b1j =      a0j    ^      a1j_2  ^      a2j_3  ^      a3j;
		b2j =      a0j    ^      a1j    ^      a2j_2  ^      a3j_3;
		b3j =      a0j_3  ^      a1j    ^      a2j    ^      a3j_2;
		s->state[4*i+0] = b0j;
		s->state[4*i+1] = b1j;
		s->state[4*i+2] = b2j;
		s->state[4*i+3] = b3j;
	}
}

void aes128(const struct expanded_key *e, uint8_t data[16])
{
	struct aes_state s;
	int j;
#ifdef AESDEBUG
	int i;
#endif
	if (e->ni)
	{
		aesni_128_encrypt(e->u.niimpl, data);
		return;
	}
	memcpy(s.state, data, 16);
#ifdef AESDEBUG
	for (i = 0; i < 16; i++)
	{
		printf("%.2x ", s.state[i]);
	}
	printf("\n");
#endif
	add_round_key(&s, e, 0);
#ifdef AESDEBUG
	for (i = 0; i < 16; i++)
	{
		printf("%.2x ", s.state[i]);
	}
	printf("\n");
#endif
	for (j = 0; j < 9; j++)
	{
#ifdef AESDEBUG
		printf("--\n");
#endif
		sub_bytes(&s);
#ifdef AESDEBUG
		for (i = 0; i < 16; i++)
		{
			printf("%.2x ", s.state[i]);
		}
		printf("\n");
#endif
		shift_rows(&s);
#ifdef AESDEBUG
		for (i = 0; i < 16; i++)
		{
			printf("%.2x ", s.state[i]);
		}
		printf("\n");
#endif
		mix_columns(&s);
#ifdef AESDEBUG
		for (i = 0; i < 16; i++)
		{
			printf("%.2x ", s.state[i]);
		}
		printf("\n");
#endif
		add_round_key(&s, e, j+1);
#ifdef AESDEBUG
		for (i = 0; i < 16; i++)
		{
			printf("%.2x ", s.state[i]);
		}
		printf("\n");
#endif
	}
#ifdef AESDEBUG
	printf("--\n");
#endif
	sub_bytes(&s);
#ifdef AESDEBUG
	for (i = 0; i < 16; i++)
	{
		printf("%.2x ", s.state[i]);
	}
	printf("\n");
#endif
	shift_rows(&s);
#ifdef AESDEBUG
	for (i = 0; i < 16; i++)
	{
		printf("%.2x ", s.state[i]);
	}
	printf("\n");
#endif
	add_round_key(&s, e, 10);
#ifdef AESDEBUG
	for (i = 0; i < 16; i++)
	{
		printf("%.2x ", s.state[i]);
	}
	printf("\n");
#endif
	memcpy(data, s.state, 16);
}

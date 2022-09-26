#include <stdio.h>
#include "aes.h"
#include "flo-aesni.h"

int main(int argc, char **argv)
{
	uint32_t key[4];
	__attribute__((aligned(16))) uint8_t key8[16];
	char *keyex;
	//uint8_t data[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
	//uint8_t expected[16] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
	//http://www.herongyang.com/Cryptography/AES-Example-Vector-of-AES-Encryption.html
	__attribute__((aligned(16))) uint8_t data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	__attribute__((aligned(16))) uint8_t data2[16];
	uint8_t expected[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	struct expanded_key ex;
	int i, j;
	//key[0] = 0x2b7e1516U;
	//key[1] = 0x28aed2a6U;
	//key[2] = 0xabf71588U;
	//key[3] = 0x09cf4f3cU;
	key[0] = 0x00010203U;
	key[1] = 0x04050607U;
	key[2] = 0x08090a0bU;
	key[3] = 0x0c0d0e0fU;
	for (i = 0; i < 16; i++)
	{
		key8[i] = (uint8_t)i;
	}
	calc_expanded_key(&ex, key);

	keyex = AES_KeyExpansion(key8, AES_128);

#if 0
	aes128(&ex, data);
#else
	AES_encrypt_all(data, data, keyex, AES_128_numRounds);
#endif
	for (i = 0; i < 15; i++)
	{
		printf("%.2x %.2x\n", data[i], expected[i]);
	}

	printf("--\n");
	key[0] = 0; // ok
	key[1] = 0;
	key[2] = 0;
	key[3] = 0;
	calc_expanded_key(&ex, key);
	for (i = 0; i < 44; i++)
	{
		printf("%.8x\n", ex.W[i]);
	}

	printf("--\n");
	key[0] = 0x00010203; // ok
	key[1] = 0x04050607;
	key[2] = 0x08090a0b;
	key[3] = 0x0c0d0e0f;
	calc_expanded_key(&ex, key);
	for (i = 0; i < 44; i++)
	{
		printf("%.8x\n", ex.W[i]);
	}

	printf("--\n");

	struct aes_state s; // ok
	s.state[0] = 0xdb;
	s.state[1] = 0x13;
	s.state[2] = 0x53;
	s.state[3] = 0x45;
	mix_columns(&s);
	for (i = 0; i < 4; i++)
	{
		printf("%.2x\n", s.state[i]);
	}
	printf("%.2x\n", gmul(0x53, 0xca)); // 0x01 is correct, ok

	// Perf test, QUIC packet
	// 1.74 seconds per 100k packets
	// 57KPPS (566 Mbps)
#if 0
	for (j = 0; j < 100*1000; j++)
	{
		for (i = 0; i < 67; i++)
		{
			aes128(&ex, data);
		}
	}
#else
	for (j = 0; j < 100*1000; j++)
	{
		for (i = 0; i < 67; i++)
		{
			AES_encrypt_all(data2, data, keyex, AES_128_numRounds);
		}
	}
#endif
	return 0;
}

#include "hkdf.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void quic_test(void)
{
	char hkdf_label1[520] = {};
	char hkdf_label2[520] = {};
	char hkdf_label3[520] = {};
	char hkdf_label4[520] = {};
	char hkdf_label5[520] = {};
	uint16_t hkdf_label1_len = 0;
	uint16_t hkdf_label2_len = 0;
	uint16_t hkdf_label3_len = 0;
	uint16_t hkdf_label4_len = 0;
	uint16_t hkdf_label5_len = 0;
	const char *label;
	uint8_t dstconnid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}; // example
	const uint8_t initial_salt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}; // constant
	uint8_t initial_secret[32];
	uint8_t client_initial_secret[32];
	uint8_t key[16];
	uint8_t iv[12];
	uint8_t hp[16];
	uint16_t i;

	label = "client in";
	hkdf_form_label(hkdf_label1, &hkdf_label1_len, label, strlen(label), "", 0, 32);
	for (i = 0; i < hkdf_label1_len; i++)
	{
		printf("%.2x ", (uint8_t)hkdf_label1[i]);
	}
	printf("\n");
	printf("expected: 00200f746c73313320636c69656e7420696e00\n");

	label = "server in";
	hkdf_form_label(hkdf_label2, &hkdf_label2_len, label, strlen(label), "", 0, 32);
	for (i = 0; i < hkdf_label2_len; i++)
	{
		printf("%.2x ", (uint8_t)hkdf_label2[i]);
	}
	printf("\n");
	printf("expected: 00200f746c7331332073657276657220696e00\n");

	label = "quic key";
	hkdf_form_label(hkdf_label3, &hkdf_label3_len, label, strlen(label), "", 0, 16);
	for (i = 0; i < hkdf_label3_len; i++)
	{
		printf("%.2x ", (uint8_t)hkdf_label3[i]);
	}
	printf("\n");
	printf("expected: 00100e746c7331332071756963206b657900\n");

	label = "quic iv";
	hkdf_form_label(hkdf_label4, &hkdf_label4_len, label, strlen(label), "", 0, 12);
	for (i = 0; i < hkdf_label4_len; i++)
	{
		printf("%.2x ", (uint8_t)hkdf_label4[i]);
	}
	printf("\n");
	printf("expected: 000c0d746c733133207175696320697600\n");

	label = "quic hp";
	hkdf_form_label(hkdf_label5, &hkdf_label5_len, label, strlen(label), "", 0, 16);
	for (i = 0; i < hkdf_label5_len; i++)
	{
		printf("%.2x ", (uint8_t)hkdf_label5[i]);
	}
	printf("\n");
	printf("expected: 00100d746c733133207175696320687000\n");

	hkdf_extract(initial_secret, initial_salt, sizeof(initial_salt), dstconnid, sizeof(dstconnid));
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", (uint8_t)initial_secret[i]);
	}
	printf("\n");
	printf("expected: 7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44\n");
	hkdf_expand_label_precalc(client_initial_secret, 32, hkdf_label1, hkdf_label1_len, initial_secret);
	for (i = 0; i < 32; i++)
	{
		printf("%.2x ", (uint8_t)client_initial_secret[i]);
	}
	printf("\n");
	printf("expected: c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea\n");
	hkdf_expand_label_precalc(key, 16, hkdf_label3, hkdf_label3_len, client_initial_secret);
	for (i = 0; i < 16; i++)
	{
		printf("%.2x ", (uint8_t)key[i]);
	}
	printf("\n");
	printf("expected: 1f369613dd76d5467730efcbe3b1a22d\n");
	hkdf_expand_label_precalc(iv, 12, hkdf_label4, hkdf_label4_len, client_initial_secret);
	for (i = 0; i < 12; i++)
	{
		printf("%.2x ", (uint8_t)iv[i]);
	}
	printf("\n");
	printf("expected: fa044b2f42a3fd3b46fb255c\n");
	hkdf_expand_label_precalc(hp, 16, hkdf_label5, hkdf_label5_len, client_initial_secret);
	for (i = 0; i < 16; i++)
	{
		printf("%.2x ", (uint8_t)hp[i]);
	}
	printf("\n");
	printf("expected: 9f50449e04a0e810283a1e9933adedd2\n");
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
	printf("---\n");
	quic_test();
	return 0;
}

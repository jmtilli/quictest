#define _GNU_SOURCE
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include "aes.h"
#include "hkdf.h"
#include "rbtree.h"
#include "linkedlist.h"
#include "containerof.h"

struct packet_descriptor {
	struct linked_list_node node;
	size_t sz;
	void *data;
};

static inline void packet_init(struct packet_descriptor *pkt, size_t sz)
{
	linked_list_node_init(&pkt->node);
	pkt->sz = sz;
	pkt->data = ((char*)pkt) + sizeof(*pkt);
}

static inline struct packet_descriptor *packet_malloc(size_t sz)
{
	struct packet_descriptor *pkt;
	pkt = malloc(sizeof(struct packet_descriptor) + sz);
	if (pkt == NULL)
	{
		return NULL;
	}
	packet_init(pkt, sz);
	return pkt;
}

static inline void packet_mfree(struct packet_descriptor *pkt)
{
	free(pkt);
}

struct inorder_ctx {
	struct linked_list_head pkts;
	uint32_t cur_off;
	struct rb_tree_nocmp tree;
};

struct inorder_entry {
	struct rb_tree_node node;
	struct packet_descriptor *pkt;
	uint32_t start_content_off;
	uint32_t crypto_content_len;
	uint32_t start_in_frame_off;
	uint32_t quic_hdr_start_in_frame_off;
};

void inorder_ctx_init(struct inorder_ctx *ctx)
{
	ctx->cur_off = 0;
	linked_list_head_init(&ctx->pkts);
	rb_tree_nocmp_init(&ctx->tree);
}

struct inorder_entry *inorder_entry_malloc(void)
{
	return malloc(sizeof(struct inorder_entry));
}
void inorder_entry_mfree(struct inorder_entry *e)
{
	free(e);
}

void inorder_ctx_free(struct inorder_ctx *ctx)
{
	while (!linked_list_is_empty(&ctx->pkts))
	{
		struct packet_descriptor *pkt;
		pkt = CONTAINER_OF(ctx->pkts.node.next, struct packet_descriptor, node);
		linked_list_delete(&pkt->node);
		packet_mfree(pkt);
	}
	while (rb_tree_nocmp_root(&ctx->tree) != NULL)
	{
		struct rb_tree_node *root = rb_tree_nocmp_root(&ctx->tree);
		struct inorder_entry *e;
		e = CONTAINER_OF(root, struct inorder_entry, node);
		rb_tree_nocmp_delete(&ctx->tree, &e->node);
		inorder_entry_mfree(e);
	}
}

void inorder_add_packet(struct inorder_ctx *ctx, struct packet_descriptor *pkt)
{
	linked_list_add_tail(&pkt->node, &ctx->pkts);
}

int cmp(struct rb_tree_node *na, struct rb_tree_node *nb, void *ud)
{
	struct inorder_entry *ea = CONTAINER_OF(na, struct inorder_entry, node);
	struct inorder_entry *eb = CONTAINER_OF(nb, struct inorder_entry, node);
	if (ea->start_content_off < eb->start_content_off)
	{
		return -1;
	}
	if (ea->start_content_off > eb->start_content_off)
	{
		return 1;
	}
	return 0;
}

int inorder_add_entry(struct inorder_ctx *ctx, uint32_t start_content_off, uint32_t crypto_content_len, uint32_t start_in_frame_off, uint32_t quic_hdr_start_in_frame_off, struct packet_descriptor *pkt)
{
	struct inorder_entry *e, *e2;
	int ret;
	if (start_content_off <= ctx->cur_off)
	{
		abort(); // should process immediately instead
	}
	e = inorder_entry_malloc();
	if (e == NULL)
	{
		return -ENOMEM;
	}
	e->pkt = pkt;
	e->start_content_off = start_content_off;
	e->crypto_content_len = crypto_content_len;
	e->start_in_frame_off = start_in_frame_off;
	e->quic_hdr_start_in_frame_off = quic_hdr_start_in_frame_off;
	ret = rb_tree_nocmp_insert_nonexist(&ctx->tree, cmp, NULL, &e->node); 
	if (ret == -EEXIST)
	{
		struct rb_tree_node *n2;
		n2 = RB_TREE_NOCMP_FIND(&ctx->tree, cmp, NULL, &e->node);
		if (n2 == NULL)
		{
			abort();
		}
		e2 = CONTAINER_OF(n2, struct inorder_entry, node);
		if (e2->start_content_off != e->start_content_off)
		{
			abort();
		}
		if (e2->crypto_content_len >= e->crypto_content_len)
		{
			inorder_entry_mfree(e);
		}
		else
		{
			rb_tree_nocmp_delete(&ctx->tree, &e2->node);
			inorder_entry_mfree(e2);
			ret = rb_tree_nocmp_insert_nonexist(&ctx->tree, cmp, NULL, &e->node);
			if (ret != 0)
			{
				printf("Couldn't add\n");
				abort();
			}
		}
	}
	else if (ret != 0)
	{
		abort();
	}
	return 0;
}

struct inorder_entry *inorder_get_entry(struct inorder_ctx *ctx)
{
	struct rb_tree_node *n;
	struct inorder_entry *e;
	for (;;)
	{
		n = rb_tree_nocmp_leftmost(&ctx->tree);
		if (n == NULL)
		{
			printf("get_entry_ret\n");
			return NULL;
		}
		e = CONTAINER_OF(n, struct inorder_entry, node);
		if (e->start_content_off > ctx->cur_off)
		{
			printf("get_entry_ret\n");
			return NULL;
		}
		else if (e->start_content_off + e->crypto_content_len > ctx->cur_off)
		{
			rb_tree_nocmp_delete(&ctx->tree, &e->node);
			printf("get_entry_ret\n");
			return e; // caller frees
		}
		else
		{
			rb_tree_nocmp_delete(&ctx->tree, &e->node);
			inorder_entry_mfree(e);
		}
		printf("get_entry_iter\n");
	}
}

void inorder_processed(struct inorder_ctx *ctx, struct inorder_entry *e)
{
	uint32_t end;
	end = e->start_content_off + e->crypto_content_len;
	if (end <= ctx->cur_off)
	{
		abort(); // no additional value
	}
	ctx->cur_off = end;
	inorder_entry_mfree(e);
}

#undef QUICDEBUG

#ifdef QUICDEBUG
#define QD_PRINTF printf
#else
#define QD_PRINTF if(0) printf
#endif

const uint8_t precalc_label_client_in[] = {0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x69, 0x6e, 0x00}; // constant
const uint8_t precalc_label_quic_hp[] = {0x00, 0x10, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x68, 0x70, 0x00}; // constant
const uint8_t precalc_label_quic_iv[] = {0x00, 0x0c, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x69, 0x76, 0x00}; // constant
const uint8_t precalc_label_quic_key[] = {0x00, 0x10, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x71, 0x75, 0x69, 0x63, 0x20, 0x6b, 0x65, 0x79, 0x00}; // constant
const uint8_t initial_salt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}; // constant

struct maypull_ctx {
	uint8_t past_data[8];
	uint8_t past_data_len;
	uint16_t dataop_remain;
	uint16_t dataop_outoff;
	uint32_t al_cnt;
};

struct tls_layer {
	struct maypull_ctx maypull;
	uint8_t state;
	uint32_t tlslen;
	uint32_t ext_start_al_cnt;
	uint8_t session_id_length;
	uint16_t cipher_suites_length;
	uint8_t compression_methods_length;
	uint16_t extensions_length;
	uint8_t sname_type;
	uint16_t sname_len;
	uint16_t ext_type;
	uint16_t ext_len;
	uint32_t ext_data_start_al_cnt;
	uint16_t sname_list_len;
	char hostname[256]; // 255 bytes + NUL
	uint8_t hostname_len;
};

struct quic_ctx {
	const uint8_t *quic_data;
	const uint8_t *data0;
	size_t siz0; // RFE make smaller?
	size_t quic_data_off_in_data0; // RFE make smaller?
	//uint64_t cur_crypto_off;
	struct packet_descriptor *pkt;

	const uint8_t *payload;
	uint16_t payload_len;
	uint8_t cur_iv[16];
	uint8_t cur_cryptostream[16];
	uint16_t tls_limit;
	uint16_t off;
	//uint16_t first_nondecrypted_off;
	//uint8_t quic_data[2048];
	uint16_t siz;
	uint16_t dstcidoff;
	uint16_t srccidoff;
	uint8_t dstcidlen;
	uint8_t srccidlen;
	// Type specific
	uint16_t tokenlen;
	uint16_t tokenoff;
	uint16_t pnumoff;
	uint16_t payoff;
	uint16_t len;
	uint8_t pnumlen;
	uint32_t pnum;
	uint8_t first_byte;
	//uint8_t cur_iv[16];
	struct expanded_key aes_exp;
};

static inline void quic_al_cnt_reset(struct tls_layer *tls)
{
	tls->maypull.al_cnt = 0;
}

#if 0
int prepare_get(struct quic_ctx *ctx, uint16_t new_first_nondecrypted_off)
{
	uint8_t mask[16];
	int i;
	for (;;)
	{
		memcpy(mask, ctx->cur_iv, 16);
		aes128(&ctx->aes_exp, mask);
		/*
		printf("Full IV before:");
		for (i = 0; i < 16; i++)
		{
			printf(" %.2x", ctx->cur_iv[i]);
		}
		printf("\n");
		*/
		for (i = 15; i >= 12; i--) // increment counter
		{
			ctx->cur_iv[i]++;
			if (ctx->cur_iv[i] != 0)
			{
				break;
			}
		}
		/*
		printf("Full IV after:");
		for (i = 0; i < 16; i++)
		{
			printf(" %.2x", ctx->cur_iv[i]);
		}
		printf("\n");
		*/
		int maxbound = 16;
		int maxbound2 =
			((int)ctx->payoff) + ((int)ctx->len) - ((int)ctx->pnumlen) - ((int)ctx->first_nondecrypted_off) - 16; // 16 for AEAD tag
		if (maxbound2 < maxbound)
		{
			maxbound = maxbound2;
		}
		if (maxbound2 == 0)
		{
			//printf("Err %d %d\n", (int)ctx->first_nondecrypted_off, (int)new_first_nondecrypted_off);
			return -ENODATA;
		}
		//printf("Max bound: %d\n", maxbound);
		//printf("Old bytes:");
		for (i = 0; i < maxbound; i++)
		{
			//printf(" %.2x", ctx->quic_data[ctx->first_nondecrypted_off]);
			ctx->quic_data[ctx->first_nondecrypted_off++] ^= mask[i];
			//printf(" (mask %.2x)", (int)mask[i]);
			//ctx->first_nondecrypted_off++;
		}
		//printf("\n");
		if (ctx->first_nondecrypted_off >= new_first_nondecrypted_off)
		{
			break;
		}	
	}
	return 0;
}

static inline int prepare_get_fast(struct quic_ctx *ctx, uint16_t new_first_nondecrypted_off)
{
	if (ctx->first_nondecrypted_off >= new_first_nondecrypted_off)
	{
		return 0;
	}
	return prepare_get(ctx, new_first_nondecrypted_off);
}
#endif

void calc_stream(struct quic_ctx *c);

int quic_init0(struct quic_ctx *ctx)
{
	//ctx->cur_crypto_off = 0;
}

void quic_free_after_init(struct quic_ctx *ctx)
{
	free_expanded_key(&ctx->aes_exp);
}

int quic_init(struct aes_initer *in, struct inorder_ctx *inorder, struct quic_ctx *ctx, const uint8_t *data0, size_t siz0, size_t off, size_t siz)
{
	uint8_t hp[16];
	uint8_t key[16];
	uint8_t initial_secret[32];
	uint8_t client_initial_secret[32];
	uint32_t aes_key[4];
	uint8_t mask[16];
	uint16_t tokenlenoff;
	uint64_t tokenlen;
	uint64_t len;
	uint16_t lenoff;
	struct hkdf_ctx hkdf;
	int i;
	const uint8_t *data = data0 + off;
	if (siz + off > siz0)
	{
		return -EFAULT;
	}

	ctx->pkt = packet_malloc(siz0);
	memcpy(ctx->pkt->data, data0, siz0);
	inorder_add_packet(inorder, ctx->pkt);

	//ctx->past_data_len = 0;
	//ctx->dataop_remain = 0;

#if 0
	if (siz > sizeof(ctx->quic_data))
	{
		return -ENOMEM;
	}
#endif
	if (siz < 6)
	{
		return -ENODATA;
	}
	if (data[0] == 0)
	{
		for (i = 0; i < (int)siz; i++)
		{
			if (data[i] != 0)
			{
				return -ENOMSG;
			}
		}
		// Contains just padding
		return -EAGAIN;
	}
	if ((data[0] & 0xf0) != 0xc0)
	{
		return -ENOMSG;
	}
	ctx->first_byte = data[0];
	if (data[1] != 0 || data[2] != 0 || data[3] != 0 || data[4] != 1)
	{
		return -ENOMSG;
	}
	ctx->dstcidoff = 6;
	ctx->dstcidlen = (uint8_t)data[5];
	if (siz < ctx->dstcidoff + ctx->dstcidlen)
	{
		return -ENODATA;
	}

	hkdf_extract(initial_secret, initial_salt, sizeof(initial_salt), &data[ctx->dstcidoff], ctx->dstcidlen);
#ifdef QUICDEBUG
	printf("Initial secret:");
	for (i = 0; i < 32; i++)
	{
		printf(" %.2x", initial_secret[i]);
	}
	printf("\n");
#endif
	hkdf_expand_label_precalc(client_initial_secret, 32, precalc_label_client_in, sizeof(precalc_label_client_in), initial_secret);
#ifdef QUICDEBUG
	printf("Client initial secret:");
	for (i = 0; i < 32; i++)
	{
		printf(" %.2x", client_initial_secret[i]);
	}
	printf("\n");
#endif

	hkdf_precalc(&hkdf, client_initial_secret);

	//hkdf_expand_label_precalc(hp, 16, precalc_label_quic_hp, sizeof(precalc_label_quic_hp), client_initial_secret);
	hkdf_expand_label_precalc2(&hkdf, hp, 16, precalc_label_quic_hp, sizeof(precalc_label_quic_hp));
#ifdef QUICDEBUG
	printf("HP key:");
	for (i = 0; i < 16; i++)
	{
		printf(" %.2x", hp[i]);
	}
	printf("\n");
#endif
	//hkdf_expand_label_precalc(ctx->cur_iv, 12, precalc_label_quic_iv, sizeof(precalc_label_quic_iv), client_initial_secret);
	hkdf_expand_label_precalc2(&hkdf, ctx->cur_iv, 12, precalc_label_quic_iv, sizeof(precalc_label_quic_iv));
#ifdef QUICDEBUG
	printf("IV:");
	for (i = 0; i < 12; i++)
	{
		printf(" %.2x", ctx->cur_iv[i]);
	}
	printf("\n");
#endif
	ctx->cur_iv[12] = 0;
	ctx->cur_iv[13] = 0;
	ctx->cur_iv[14] = 0;
	ctx->cur_iv[15] = 2;
#ifdef QUICDEBUG
	printf("Full IV:");
	for (i = 0; i < 16; i++)
	{
		printf(" %.2x", ctx->cur_iv[i]);
	}
	printf("\n");
#endif
	aes_key[0] =
		(((uint32_t)hp[0])<<24) |
		(((uint32_t)hp[1])<<16) |
		(((uint32_t)hp[2])<<8) |
		((uint32_t)hp[3]);
	aes_key[1] =
		(((uint32_t)hp[4])<<24) |
		(((uint32_t)hp[5])<<16) |
		(((uint32_t)hp[6])<<8) |
		((uint32_t)hp[7]);
	aes_key[2] =
		(((uint32_t)hp[8])<<24) |
		(((uint32_t)hp[9])<<16) |
		(((uint32_t)hp[10])<<8) |
		((uint32_t)hp[11]);
	aes_key[3] =
		(((uint32_t)hp[12])<<24) |
		(((uint32_t)hp[13])<<16) |
		(((uint32_t)hp[14])<<8) |
		((uint32_t)hp[15]);

	ctx->srccidoff = ctx->dstcidoff + ctx->dstcidlen+1;
	ctx->srccidlen = (uint8_t)data[ctx->dstcidoff + ctx->dstcidlen];
	if (siz < ctx->srccidoff + ctx->srccidlen)
	{
		return -ENODATA;
	}
	tokenlenoff = ctx->srccidoff + ctx->srccidlen;
	if (siz < tokenlenoff + 1)
	{
		return -ENODATA;
	}
	if (siz < tokenlenoff + 1<<(data[tokenlenoff]>>6))
	{
		return -ENODATA;
	}
	switch (data[tokenlenoff]>>6)
	{
		case 0:
			tokenlen = data[tokenlenoff]&0x3f;
			ctx->tokenoff = tokenlenoff + 1;
			break;
		case 1:
			tokenlen =
				(((uint64_t)data[tokenlenoff]&0x3f) << 8) |
				 ((uint64_t)data[tokenlenoff+1]);
			ctx->tokenoff = tokenlenoff + 2;
			break;
		case 2:
			tokenlen =
				(((uint64_t)data[tokenlenoff]&0x3f) << 24) |
				 (((uint64_t)data[tokenlenoff+1]) << 16) |
				 (((uint64_t)data[tokenlenoff+2]) << 8) |
				 ((uint64_t)data[tokenlenoff+3]);
			ctx->tokenoff = tokenlenoff + 4;
			break;
		case 3:
			tokenlen =
				(((uint64_t)data[tokenlenoff]&0x3f) << 56) |
				 (((uint64_t)data[tokenlenoff+1]) << 48) |
				 (((uint64_t)data[tokenlenoff+2]) << 40) |
				 (((uint64_t)data[tokenlenoff+3]) << 32) |
				 (((uint64_t)data[tokenlenoff+4]) << 24) |
				 (((uint64_t)data[tokenlenoff+5]) << 16) |
				 (((uint64_t)data[tokenlenoff+6]) << 8) |
				 ((uint64_t)data[tokenlenoff+7]);
			ctx->tokenoff = tokenlenoff + 8;
			break;
	}
	if (siz < ctx->tokenoff + tokenlen)
	{
		return -ENODATA;
	}
	ctx->tokenlen = (uint16_t)tokenlen;
	lenoff = ctx->tokenoff + ctx->tokenlen;
	if (siz < lenoff + 1)
	{
		return -ENODATA;
	}
	if (siz < lenoff + 1<<(data[lenoff]>>6))
	{
		return -ENODATA;
	}
	switch (data[lenoff]>>6)
	{
		case 0:
			len = data[lenoff]&0x3f;
			ctx->pnumoff = lenoff + 1;
			break;
		case 1:
			len =
				(((uint64_t)data[lenoff]&0x3f) << 8) |
				 ((uint64_t)data[lenoff+1]);
			ctx->pnumoff = lenoff + 2;
			break;
		case 2:
			len =
				(((uint64_t)data[lenoff]&0x3f) << 24) |
				 (((uint64_t)data[lenoff+1]) << 16) |
				 (((uint64_t)data[lenoff+2]) << 8) |
				 ((uint64_t)data[lenoff+3]);
			ctx->pnumoff = lenoff + 4;
			break;
		case 3:
			len =
				(((uint64_t)data[lenoff]&0x3f) << 56) |
				 (((uint64_t)data[lenoff+1]) << 48) |
				 (((uint64_t)data[lenoff+2]) << 40) |
				 (((uint64_t)data[lenoff+3]) << 32) |
				 (((uint64_t)data[lenoff+4]) << 24) |
				 (((uint64_t)data[lenoff+5]) << 16) |
				 (((uint64_t)data[lenoff+6]) << 8) |
				 ((uint64_t)data[lenoff+7]);
			ctx->pnumoff = lenoff + 8;
			break;
	}
	ctx->len = (uint16_t)len; // length of payload (incl 16 bytes verif) + length of pnum

	if (siz < ctx->pnumoff + 4 + 16)
	{
		return -ENODATA;
	}
	memcpy(mask, &data[ctx->pnumoff + 4], 16); // sample
	calc_expanded_key(in, &ctx->aes_exp, aes_key);
	aes128(&ctx->aes_exp, mask);
	free_expanded_key(&ctx->aes_exp);
	ctx->first_byte ^= (mask[0] & 0x0f);
	ctx->pnumlen = (ctx->first_byte&3) + 1;

	if (siz < ctx->pnumoff + ctx->pnumlen)
	{
		return -ENODATA;
	}
	ctx->pnum = 0;
	for (i = 0; i < ctx->pnumlen; i++)
	{
		ctx->pnum |= ((data[ctx->pnumoff+i] ^ (mask[i+1])) << (8*(ctx->pnumlen-1-i)));
	}
#ifdef QUICDEBUG
	printf("Length: %llu\n", (unsigned long long)ctx->len);
	printf("Packet number: %llu (len %d)\n", (unsigned long long)ctx->pnum, (int)ctx->pnumlen);
#endif
	ctx->payoff = ctx->pnumoff + ctx->pnumlen;
	if (siz < ctx->payoff + len - ctx->pnumlen)
	{
		return -ENODATA;
	}
#if 0
	ctx->first_nondecrypted_off = ctx->payoff;
#endif


	//ctx->cur_iv[4] ^= (ctx->pnum>>24)&0xFF;
	//ctx->cur_iv[5] ^= (ctx->pnum>>16)&0xFF;
	//ctx->cur_iv[6] ^= (ctx->pnum>>8)&0xFF;
	//ctx->cur_iv[7] ^= (ctx->pnum>>0)&0xFF;
	ctx->cur_iv[8] ^= (ctx->pnum>>24)&0xFF;
	ctx->cur_iv[9] ^= (ctx->pnum>>16)&0xFF;
	ctx->cur_iv[10] ^= (ctx->pnum>>8)&0xFF;
	ctx->cur_iv[11] ^= (ctx->pnum>>0)&0xFF;
#ifdef QUICDEBUG
	printf("Full nonce:");
	for (i = 0; i < 16; i++)
	{
		printf(" %.2x", ctx->cur_iv[i]);
	}
	printf("\n");
#endif

	//hkdf_expand_label_precalc(key, 16, precalc_label_quic_key, sizeof(precalc_label_quic_key), client_initial_secret);
	hkdf_expand_label_precalc2(&hkdf, key, 16, precalc_label_quic_key, sizeof(precalc_label_quic_key));
#ifdef QUICDEBUG
	printf("Key:");
	for (i = 0; i < 16; i++)
	{
		printf(" %.2x", key[i]);
	}
	printf("\n");
#endif
	aes_key[0] =
		(((uint32_t)key[0])<<24) |
		(((uint32_t)key[1])<<16) |
		(((uint32_t)key[2])<<8) |
		((uint32_t)key[3]);
	aes_key[1] =
		(((uint32_t)key[4])<<24) |
		(((uint32_t)key[5])<<16) |
		(((uint32_t)key[6])<<8) |
		((uint32_t)key[7]);
	aes_key[2] =
		(((uint32_t)key[8])<<24) |
		(((uint32_t)key[9])<<16) |
		(((uint32_t)key[10])<<8) |
		((uint32_t)key[11]);
	aes_key[3] =
		(((uint32_t)key[12])<<24) |
		(((uint32_t)key[13])<<16) |
		(((uint32_t)key[14])<<8) |
		((uint32_t)key[15]);

	// packet number length: 0 = 1 byte, 1 = 2 bytes, 2 = 3 bytes, 3 = 4 bytes
	// this is encrypted

	if (siz > (size_t)UINT16_MAX || (size_t)len > (size_t)UINT16_MAX)
	{
		return -ENODATA;
	}
	ctx->siz = (uint16_t)siz;
	//memcpy(ctx->quic_data, data, ctx->siz);
	ctx->quic_data = data;
	ctx->data0 = data0;
	ctx->siz0 = siz0;
	ctx->quic_data_off_in_data0 = off;
	calc_expanded_key(in, &ctx->aes_exp, aes_key);
	calc_stream(ctx);

	if (siz <= ctx->payoff + len - ctx->pnumlen)
	{
		return 0;
	}
	return ctx->payoff + len - ctx->pnumlen;
}

/*
// Ethernet, IP, UDP header
52 54 00 12 35 02 08 00 27 c7 df b3 08 00 45 00
05 69 00 00 40 00 40 11 7f 76 0a 00 02 0f d8 3a
d1 c4 e8 6c 01 bb 05 55 be 48
*/

// QUIC data, www.google.com
const uint8_t quic_data[] = {
0xc9, 0x00, 0x00, 0x00, 0x01, 0x10,
0x06, 0x7f, 0x7d, 0x53, 0x54, 0x81, 0xef, 0x9e, 0x37, 0xbf, 0x1f, 0x3e, 0x42, 0xb8, 0x5e, 0xa8,
0x03, 0xf1, 0xf8, 0x7a, 0x00, 0x42, 0x15, 0x61, 0xa2, 0xff, 0x31, 0xfa, 0xa7, 0x23, 0xd7, 0xc3,
0xc4, 0x57, 0x1e, 0x89, 0x85, 0x5c, 0x9b, 0xd1, 0x2e, 0x58, 0xc6, 0x74, 0xab, 0x3c, 0x16, 0x3b,
0x8d, 0xc5, 0x9b, 0x3d, 0xa0, 0xa1, 0xe9, 0x71, 0xc3, 0x14, 0x2c, 0xca, 0x38, 0x6d, 0x9e, 0x65,
0x65, 0xa5, 0x18, 0xb2, 0xe5, 0x49, 0x07, 0x38, 0x5b, 0xaa, 0x79, 0x44, 0xbb, 0x3b, 0x63, 0xe5,
0x4e, 0x06, 0xe9, 0x1e, 0x2d, 0xbf, 0xb9, 0x59, 0xeb, 0x35, 0x5d, 0x11, 0xf5, 0x14, 0x72, 0x4a,
0xa3, 0x1f, 0x21, 0xeb, 0x2b, 0xc8, 0x6a, 0x93, 0xd7, 0x85, 0x04, 0x94, 0x9a, 0x41, 0x3e, 0xaa,
0x13, 0xcf, 0xfe, 0x8a, 0xbe, 0x22, 0x12, 0xce, 0xe2, 0x7a, 0xab, 0xf7, 0x48, 0xa9, 0x10, 0x73,
0xa5, 0xa6, 0xfa, 0xdf, 0xfb, 0x82, 0x36, 0xe3, 0x29, 0x2e, 0x26, 0x7e, 0x06, 0x04, 0xb8, 0xb9,
0x9a, 0x87, 0x9e, 0xe6, 0x3b, 0xfe, 0xfb, 0x71, 0x3b, 0x2b, 0xab, 0xca, 0x2d, 0x3a, 0x91, 0x09,
0xcb, 0xa6, 0x99, 0x8f, 0xff, 0x4e, 0xb8, 0xf2, 0x72, 0xd4, 0xee, 0x34, 0x53, 0xf5, 0x7c, 0x40,
0x4d, 0x89, 0x5e, 0x9f, 0x8e, 0xac, 0x37, 0x19, 0xbf, 0x98, 0x6e, 0x8f, 0x94, 0x48, 0xa7, 0x6f,
0x54, 0x18, 0xf9, 0x13, 0xd6, 0x74, 0xa0, 0x10, 0x82, 0x4e, 0xe2, 0x84, 0xf6, 0xdd, 0xbc, 0x27,
0x4b, 0x86, 0x59, 0x22, 0x85, 0xc9, 0xbc, 0x9d, 0x4f, 0xeb, 0xe6, 0x9f, 0x7e, 0xa1, 0x56, 0x48,
0x6e, 0x15, 0xd7, 0x8b, 0x32, 0x8d, 0xc0, 0xc6, 0x94, 0x11, 0x1f, 0xdb, 0x1a, 0xc3, 0x1c, 0x7c,
0x9c, 0xbc, 0x4b, 0x65, 0xde, 0xed, 0x33, 0x47, 0xb8, 0x1a, 0xc9, 0x5e, 0x4d, 0x95, 0xc3, 0x75,
0x5c, 0x33, 0x8f, 0x13, 0xd9, 0xf2, 0x9a, 0x10, 0x54, 0xaf, 0x0c, 0x5a, 0xb7, 0x1c, 0xed, 0xe0,
0x79, 0xef, 0x81, 0xe2, 0xe9, 0xee, 0x8b, 0x0b, 0x9a, 0xeb, 0x68, 0xd8, 0x1d, 0x2e, 0xe6, 0xa2,
0xf7, 0x7d, 0x4e, 0x3d, 0x6c, 0xff, 0x98, 0x4f, 0x67, 0x25, 0xf3, 0x8f, 0xea, 0xd8, 0x1e, 0x25,
0xf3, 0x36, 0xb8, 0x9f, 0x43, 0x29, 0x54, 0x39, 0x1e, 0x23, 0xfd, 0x62, 0xb3, 0xf6, 0xa0, 0x85,
0xbf, 0x17, 0x1e, 0xe7, 0x7e, 0xa8, 0x59, 0xfa, 0x09, 0xc7, 0x32, 0xb3, 0x90, 0x05, 0x38, 0xc4,
0xf2, 0xd4, 0x3f, 0x1f, 0x53, 0xda, 0x83, 0xca, 0x05, 0xfc, 0x4a, 0x2a, 0x3f, 0x9b, 0x6e, 0x62,
0x53, 0x03, 0xb3, 0x2a, 0xc6, 0xeb, 0x9f, 0x71, 0x7d, 0x2b, 0x4a, 0xbe, 0xdb, 0x7e, 0x3c, 0x95,
0x23, 0x23, 0x19, 0xcf, 0x82, 0xa7, 0x4a, 0x32, 0x33, 0x2a, 0xab, 0x2f, 0x4b, 0xf7, 0x7b, 0xf2,
0xa4, 0xe0, 0x05, 0xf6, 0x87, 0x70, 0x65, 0x0a, 0xbe, 0xb4, 0xbb, 0x2d, 0xe0, 0xdb, 0x2d, 0xce,
0x69, 0x2b, 0x0e, 0x07, 0x98, 0x02, 0x8a, 0xb4, 0x3d, 0x24, 0x08, 0xad, 0x81, 0x9f, 0x3f, 0x9c,
0x42, 0xb0, 0x7d, 0xa2, 0xce, 0x42, 0xc5, 0x17, 0x07, 0x1d, 0xd2, 0xf9, 0xeb, 0x26, 0x3c, 0x0f,
0xb9, 0x47, 0xfe, 0xaf, 0x12, 0x6a, 0x0e, 0x51, 0x63, 0xd8, 0x32, 0xb8, 0xd8, 0x82, 0x18, 0x36,
0xcd, 0x24, 0x69, 0x41, 0x82, 0x1c, 0xef, 0x24, 0x29, 0xd0, 0xc6, 0x7e, 0x8a, 0xd4, 0x5c, 0xf8,
0x3b, 0xbe, 0x05, 0x36, 0xba, 0xb1, 0x5b, 0x48, 0xa9, 0x8f, 0x59, 0xf6, 0xcb, 0x26, 0xf1, 0xf1,
0xc8, 0x7e, 0x6f, 0x66, 0xcd, 0xf5, 0x1d, 0xf4, 0xfd, 0xb3, 0xae, 0x4e, 0x7a, 0x5c, 0xe9, 0x6c,
0x65, 0x3d, 0x3b, 0x8b, 0x3d, 0xcc, 0xb3, 0xb9, 0x8a, 0x4d, 0x06, 0xd3, 0x07, 0x05, 0x7a, 0xc4,
0xc7, 0x28, 0x6d, 0x1d, 0xb0, 0x0e, 0xc5, 0xfb, 0xc7, 0x77, 0x63, 0x5e, 0xbd, 0x59, 0x7d, 0xf4,
0xd9, 0x8c, 0xc0, 0x9e, 0xe8, 0x31, 0xf9, 0xf6, 0xa7, 0x8d, 0x0c, 0xef, 0xc0, 0x11, 0xe4, 0xcf,
0xb5, 0xb9, 0x3b, 0x84, 0x36, 0xab, 0xe2, 0xaa, 0xa5, 0x4c, 0x4d, 0x61, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t official_data[] = {
0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11,
0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36, 0xb4, 0x7d, 0x92, 0xec, 0x35, 0x6c, 0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd, 0x44, 0x9f, 0x63, 0x30, 0x00, 0x99, 0xf3, 0x99,
0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d, 0x17, 0xb3, 0x1f, 0x84, 0x29, 0x15, 0x7b, 0xb3, 0x5a, 0x12, 0x82, 0xa6, 0x43, 0xa8, 0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50, 0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c,
0x8e, 0xb7, 0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed, 0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1, 0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6, 0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf, 0x62, 0x12,
0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43, 0xfa, 0x02, 0x8c, 0xea, 0x7f, 0x7f, 0xb5, 0xff, 0x89, 0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0, 0x22, 0x52, 0x15, 0x5e, 0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5,
0x45, 0x7a, 0xfd, 0x84, 0xd0, 0x5d, 0xff, 0xfd, 0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15, 0x46, 0x82, 0xe9, 0xcf, 0x01, 0x2f, 0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08,
0x4d, 0xce, 0x25, 0xff, 0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3, 0x62, 0xc2, 0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5, 0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec,
0x4e, 0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1, 0xd9, 0x8e, 0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba, 0xd1, 0xdb, 0x4b, 0xa3,
0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3, 0xfd, 0xb4, 0x1e, 0xd1, 0x5f, 0xb6, 0xa8, 0xe5, 0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3, 0x0c, 0x5c, 0x42, 0x87, 0xe5, 0x38, 0x05, 0xdb,
0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2, 0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39, 0xbe, 0x2e, 0x20, 0xd8, 0x2d, 0xf5, 0x66, 0xda, 0x8d, 0xd5, 0x99, 0x8c, 0xca, 0xbd, 0xae, 0x05, 0x30, 0x60, 0xae, 0x6c,
0x7b, 0x43, 0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b, 0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7, 0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6, 0x81, 0xd5, 0x82, 0x36, 0x3a, 0xa5, 0xf8,
0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63, 0xad, 0x6f, 0x1a, 0x0b, 0x1d, 0x96, 0xdb, 0xd4, 0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b, 0xa6, 0x61, 0x17, 0x22, 0x39, 0x5c, 0x90, 0x65, 0x56,
0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65, 0x63, 0x6a, 0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74, 0x3e, 0xeb, 0x52, 0x4b, 0xe2, 0x2b, 0x3d, 0xcb, 0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74,
0x68, 0x44, 0x9a, 0x13, 0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7, 0xfe, 0x94, 0x2b, 0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a,
0xc6, 0x98, 0x90, 0xf4, 0x15, 0x70, 0x15, 0x85, 0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c, 0x22, 0x7a, 0x33, 0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b, 0x9d, 0x90, 0xca, 0x00,
0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f, 0xe9, 0xc5, 0xd0, 0xb2, 0x3a, 0x22, 0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81, 0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72, 0x66, 0x32,
0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11, 0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f, 0xeb, 0x3e, 0xdf, 0x33, 0x0f, 0x2c, 0x60, 0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d, 0xbf, 0xe5, 0x89, 0x64,
0x25, 0xc5, 0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57, 0xa8, 0x5a, 0xaf, 0x4e, 0x25, 0x13, 0xe4, 0xf0, 0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06, 0xf8, 0xd2, 0xc2, 0x5e, 0x50, 0xfd,
0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02, 0xf9, 0x39, 0xb0, 0xe1, 0xab, 0xd5, 0x76, 0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c, 0x1f, 0x28, 0xff, 0x18, 0xf5, 0x88, 0x91, 0xff,
0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93, 0x46, 0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2, 0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33, 0x41, 0x13, 0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98,
0xe3, 0xfc, 0x43, 0x3f, 0x9f, 0x25, 0x41, 0x01, 0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f, 0x60, 0x47, 0x47, 0x2f, 0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd,
0xc3, 0x24, 0x04, 0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95, 0xde, 0x37, 0x25, 0x2d, 0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84, 0x39, 0x2b, 0x06, 0x10, 0x85, 0x34, 0x9d, 0x73,
0x20, 0x3a, 0x4a, 0x13, 0xe9, 0x6f, 0x54, 0x32, 0xec, 0x0f, 0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd, 0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5, 0x10, 0xb0, 0xff, 0x20, 0xdc, 0xc0, 0xc7, 0x7f,
0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05, 0xcb, 0x05, 0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3, 0xd8, 0xb4, 0xda, 0xe6, 0xe7, 0x05, 0x76, 0x9d, 0x1d, 0xe3, 0x54, 0x27, 0x01, 0x23, 0xcb, 0x11, 0x45, 0x0e,
0xfc, 0x60, 0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d, 0x0f, 0x81, 0x13, 0x65, 0x56, 0x5f, 0xd9, 0x8c, 0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06, 0x9f, 0xc3, 0x3b, 0xd8, 0x01, 0xb0, 0x3a, 0xde,
0xa2, 0xe1, 0xfb, 0xc5, 0xaa, 0x46, 0x3d, 0x08, 0xca, 0x19, 0x89, 0x6d, 0x2b, 0xf5, 0x9a, 0x07, 0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17, 0x2f, 0x29, 0x6b, 0xfb, 0x5e, 0x72, 0x40, 0x47,
0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a, 0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03, 0x68, 0xcc, 0x39, 0xdb, 0xb2, 0xd1, 0x98, 0x06, 0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2,
0x16, 0x2f, 0x40, 0xa2, 0x9f, 0x0c, 0x3c, 0x87, 0x45, 0xc0, 0xf5, 0x0f, 0xba, 0x38, 0x52, 0xe5, 0x66, 0xd4, 0x45, 0x75, 0xc2, 0x9d, 0x39, 0xa0, 0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4,
0x40, 0x59, 0x1f, 0x35, 0x5e, 0x12, 0xd4, 0x39, 0xff, 0x15, 0x0a, 0xab, 0x76, 0x13, 0x49, 0x9d, 0xbd, 0x49, 0xad, 0xab, 0xc8, 0x67, 0x6e, 0xef, 0x02, 0x3b, 0x15, 0xb6, 0x5b, 0xfc, 0x5c, 0xa0,
0x69, 0x48, 0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb, 0x82, 0x12, 0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33, 0xbd, 0xab, 0xcb, 0x90, 0x92, 0x71, 0xa6, 0xec, 0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e,
0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01, 0x75, 0xf1, 0x13, 0x25, 0x3d, 0x8f, 0xa9, 0xca, 0x88, 0x85, 0xc2, 0xf5, 0x52, 0xe6, 0x57, 0xdc, 0x60, 0x3f, 0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f, 0x76, 0xf0,
0xbe, 0x79, 0xe2, 0xfb, 0x8f, 0x5d, 0x5f, 0xbb, 0xe2, 0xe3, 0x0e, 0xca, 0xdd, 0x22, 0x07, 0x23, 0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb, 0x38, 0x68, 0x26, 0x3f, 0xf8, 0xf0, 0x94, 0x00,
0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4, 0x9a, 0xd5, 0xaf, 0xf4, 0xaf, 0x30, 0x0c, 0xd8, 0x04, 0xa6, 0xb6, 0x27, 0x9a, 0xb3, 0xff, 0x3a, 0xfb, 0x64, 0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab,
0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f, 0x44, 0x00, 0xe8, 0xb3, 0x85, 0x91, 0x35, 0x6f, 0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d, 0xc8, 0x52, 0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9,
0xf9, 0x6f, 0x3c, 0xa9, 0xec, 0x1d, 0xde, 0x43, 0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd, 0xf3, 0xd1, 0xf9, 0xaf, 0x93, 0xd1, 0xaf, 0x59, 0x50, 0xbd, 0x49, 0x3f, 0x5a, 0xa7, 0x31, 0xb4,
0x05, 0x6d, 0xf3, 0x1b, 0xd2, 0x67, 0xb6, 0xb9, 0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5, 0x79, 0xbe, 0x0a, 0x39, 0x01, 0x31, 0x37, 0xaa, 0xc6, 0xd4, 0x04, 0xf5, 0x18, 0xcf, 0xd4, 0x68, 0x40, 0x64,
0x7e, 0x78, 0xbf, 0xe7, 0x06, 0xca, 0x4c, 0xf5, 0xe9, 0xc5, 0x45, 0x3e, 0x9f, 0x7c, 0xfd, 0x2b, 0x8b, 0x4c, 0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c, 0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41,
0xe2, 0x21, 0xaf, 0x44, 0x86, 0x00, 0x18, 0xab, 0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34
};


#if 0
struct ctx {
	uint8_t past_data[8];
	uint8_t past_data_len;
	const uint8_t *payload;
	uint16_t payload_len;
	uint16_t dataop_remain;
	uint16_t dataop_outoff;
	uint8_t cur_iv[16];
	uint8_t cur_cryptostream[16];
	uint16_t off;
	struct expanded_key aes_exp;
};
#endif

void next_iv(struct quic_ctx *c)
{
#if 1
	uint32_t ctr = (c->off/16) + 2;
	c->cur_iv[12] = ctr>>24;
	c->cur_iv[13] = ctr>>16;
	c->cur_iv[14] = ctr>>8;
	c->cur_iv[15] = ctr>>0;
#else
	int i;
	for (i = 15; i >= 12; i--) // increment counter
	{
		c->cur_iv[i]++;
		if (c->cur_iv[i] != 0)
		{
			break;
		}
	}
#endif
}

void calc_stream(struct quic_ctx *c)
{
	memcpy(c->cur_cryptostream, c->cur_iv, 16);
	aes128(&c->aes_exp, c->cur_cryptostream);
}

void next_iv_and_stream(struct quic_ctx *c)
{
	next_iv(c);
	calc_stream(c);
}

int ctx_skip(struct quic_ctx *c, struct maypull_ctx *t, uint16_t cnt)
{
	uint8_t consumed_cryptostream = c->off - (c->off/16)*16;
	uint8_t change;
	uint16_t cntthis;
	int retval = 0;
	if (t->dataop_remain == 0)
	{
		t->dataop_remain = cnt;
	}
	else
	{
		cnt = t->dataop_remain;
	}
	cntthis = cnt;
	if (cntthis > c->tls_limit - c->off)
	{
		cntthis = c->tls_limit - c->off;
		retval = -EAGAIN;
	}
	if (cntthis + consumed_cryptostream < 16)
	{
		c->off += cntthis;
		cnt -= cntthis;
		t->dataop_remain = cnt;
		return retval;
	}
	change = 16 - consumed_cryptostream; // consume this
	c->off += change;
	cntthis -= change;
	cnt -= change;
	next_iv(c);
	while (cntthis >= 16)
	{
		c->off += 16;
		cntthis -= 16;
		cnt -= 16;
		next_iv(c);
	}
	if (cntthis > 0)
	{
		c->off += cntthis;
		cnt -= cntthis;
	}
	calc_stream(c);
	t->dataop_remain = cnt;
	return retval;
}

int ctx_getdata(struct quic_ctx *c, struct maypull_ctx *t, void *out, uint16_t cnt)
{
	uint8_t *uout = (uint8_t*)out;
	uint16_t outoff = 0;
	uint8_t consumed_cryptostream = c->off - (c->off/16)*16;
	uint8_t change;
	uint16_t cntthis;
	int retval = 0;
	uint16_t i;
	if (t->dataop_remain == 0)
	{
		t->dataop_remain = cnt;
		t->dataop_outoff = outoff;
	}
	else
	{
		cnt = t->dataop_remain;
		outoff = t->dataop_outoff;
	}
	cntthis = cnt;
	if (cntthis > c->tls_limit - c->off)
	{
		cntthis = c->tls_limit - c->off;
		retval = -EAGAIN;
	}
	if (cntthis + consumed_cryptostream < 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			uout[outoff++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[consumed_cryptostream + i];
			t->al_cnt++;
		}
		cnt -= cntthis;
		t->dataop_remain = cnt;
		t->dataop_outoff = outoff;
		return retval;
	}
	change = 16 - consumed_cryptostream; // consume this
	for (i = 0; i < change; i++)
	{
		uout[outoff++] =
			c->payload[c->off++] ^
			c->cur_cryptostream[consumed_cryptostream + i];
		t->al_cnt++;
	}
	cntthis -= change;
	cnt -= change;
	next_iv_and_stream(c);
	while (cntthis >= 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			uout[outoff++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
			t->al_cnt++;
		}
		cntthis -= 16;
		cnt -= 16;
		next_iv_and_stream(c);
	}
	if (cntthis > 0)
	{
		for (i = 0; i < cntthis; i++)
		{
			uout[outoff++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
			t->al_cnt++;
		}
		cnt -= cntthis;
	}
	t->dataop_remain = cnt;
	t->dataop_outoff = outoff;
	return retval;
}

int may_pull(struct quic_ctx *c, struct maypull_ctx *t, uint8_t cnt)
{
	uint8_t consumed_cryptostream = c->off - (c->off/16)*16;
	uint8_t change;
	uint8_t cntthis;
	uint8_t i;
	int retval = 0;
	if (cnt > 8 || cnt == 0)
	{
		abort();
	}
	if (t->past_data_len >= cnt)
	{
		abort();
	}
	cnt -= t->past_data_len;
	cntthis = cnt;
	if (cntthis > c->tls_limit - c->off)
	{
		cntthis = c->tls_limit - c->off;
		retval = -EAGAIN;
	}
	if (cntthis + consumed_cryptostream < 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			t->past_data[t->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[consumed_cryptostream + i];
			t->al_cnt++;
		}
		cnt -= cntthis;
		if (retval == 0)
		{
			t->past_data_len = 0;
		}
		return retval;
	}
	change = 16 - consumed_cryptostream; // consume this
	for (i = 0; i < change; i++)
	{
		t->past_data[t->past_data_len++] =
			c->payload[c->off++] ^
			c->cur_cryptostream[consumed_cryptostream + i];
		t->al_cnt++;
	}
	cntthis -= change;
	cnt -= change;
	next_iv_and_stream(c);
#if 0
	while (cntthis >= 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			t->past_data[t->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
			t->al_cnt++;
		}
		cntthis -= 16;
		cnt -= 16;
		next_iv_and_stream(c);
	}
#endif
	if (cntthis > 0)
	{
		if (cntthis >= 16)
		{
			abort();
		}
		for (i = 0; i < cntthis; i++)
		{
			t->past_data[t->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
			t->al_cnt++;
		}
		cnt -= cntthis;
	}
	if (retval == 0)
	{
		t->past_data_len = 0;
	}
	return retval;
}

void get_varint_slowpath(struct quic_ctx *c, struct maypull_ctx *t, uint64_t *intout)
{
	if (!intout)
	{
		return;
	}
	if (t->past_data_len == 0 || t->past_data_len < (1<<(t->past_data[0]>>6)))
	{
		abort();
	}
	switch (t->past_data[0]>>6)
	{
		case 0:
			*intout = t->past_data[0]&0x3f;
			break;
		case 1:
			*intout =
				(((uint64_t)t->past_data[0]&0x3f) << 8) |
				 ((uint64_t)t->past_data[1]);
			break;
		case 2:
			*intout =
				(((uint64_t)t->past_data[0]&0x3f) << 24) |
				 (((uint64_t)t->past_data[1]) << 16) |
				 (((uint64_t)t->past_data[2]) << 8) |
				 ((uint64_t)t->past_data[3]);
			break;
		case 3:
			*intout =
				(((uint64_t)t->past_data[0]&0x3f) << 56) |
				 (((uint64_t)t->past_data[1]) << 48) |
				 (((uint64_t)t->past_data[2]) << 40) |
				 (((uint64_t)t->past_data[3]) << 32) |
				 (((uint64_t)t->past_data[4]) << 24) |
				 (((uint64_t)t->past_data[5]) << 16) |
				 (((uint64_t)t->past_data[6]) << 8) |
				 ((uint64_t)t->past_data[7]);
			break;
	}
}
static inline void get_varint(struct quic_ctx *c, struct maypull_ctx *t, uint64_t *intout)
{
	if (!intout)
	{
		return;
	}
	get_varint_slowpath(c, t, intout);
}

int may_pull_varint(struct quic_ctx *c, struct maypull_ctx *t, uint64_t *intout)
{
	uint8_t consumed_cryptostream = c->off - (c->off/16)*16;
	uint8_t change;
	uint8_t cnt;
	uint8_t cntthis;
	uint8_t i;
	int retval = 0;
	if (t->past_data_len >= 8)
	{
		abort();
	}
	if (c->tls_limit <= c->off)
	{
		return -EAGAIN;
	}
	if (t->past_data_len == 0)
	{
		t->past_data[t->past_data_len++] = 
				c->payload[c->off++] ^
				c->cur_cryptostream[consumed_cryptostream + 0];
		t->al_cnt++;
		if (consumed_cryptostream == 15) // after the last line, it's actually 16
		{
			next_iv_and_stream(c);
		}
		consumed_cryptostream = c->off - (c->off/16)*16;
	}
	cnt = 1<<(t->past_data[0]>>6);
	cnt -= t->past_data_len;
	cntthis = cnt;
	if (cntthis > c->tls_limit - c->off)
	{
		cntthis = c->tls_limit - c->off;
		retval = -EAGAIN;
	}
	if (cntthis + consumed_cryptostream < 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			t->past_data[t->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[consumed_cryptostream + i];
			t->al_cnt++;
		}
		cnt -= cntthis;
		if (retval == 0)
		{
			get_varint(c, t, intout);
			t->past_data_len = 0;
		}
		return retval;
	}
	change = 16 - consumed_cryptostream; // consume this
	for (i = 0; i < change; i++)
	{
		t->past_data[t->past_data_len++] =
			c->payload[c->off++] ^
			c->cur_cryptostream[consumed_cryptostream + i];
		t->al_cnt++;
	}
	cntthis -= change;
	cnt -= change;
	next_iv_and_stream(c);
#if 0
	while (cntthis >= 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			t->past_data[t->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
			t->al_cnt++;
		}
		cntthis -= 16;
		cnt -= 16;
		next_iv_and_stream(c);
	}
#endif
	if (cntthis > 0)
	{
		if (cntthis >= 16)
		{
			abort();
		}
		for (i = 0; i < cntthis; i++)
		{
			t->past_data[t->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
			t->al_cnt++;
		}
		cnt -= cntthis;
	}
	if (retval == 0)
	{
		get_varint(c, t, intout);
		t->past_data_len = 0;
	}
	return retval;
}

#if 0
static inline int eat_varint(struct quic_ctx *ctx, uint32_t *poff)
{
	uint32_t off = *poff;
	const uint8_t *data = (const uint8_t*)&ctx->quic_data;
	if (prepare_get_fast(ctx, off+1))
	{
		QD_PRINTF("ENODATA EAT_VARINT 1\n");
		return -ENODATA;
	}
	switch (data[off]>>6)
	{
		case 0:
			off += 1;
			break;
		case 1:
			if (prepare_get_fast(ctx, off+2))
			{
				QD_PRINTF("ENODATA EAT_VARINT 2\n");
				return -ENODATA;
			}
			off += 2;
			break;
		case 2:
			if (prepare_get_fast(ctx, off+4))
			{
				QD_PRINTF("ENODATA EAT_VARINT 3\n");
				return -ENODATA;
			}
			off += 4;
			break;
		case 3:
			if (prepare_get_fast(ctx, off+8))
			{
				QD_PRINTF("ENODATA EAT_VARINT 4\n");
				return -ENODATA;
			}
			off += 8;
			break;
	}
	*poff = off;
	return 0;
}
static inline int read_varint(struct quic_ctx *ctx, uint32_t *poff, uint64_t *p)
{
	uint32_t off = *poff;
	uint64_t val;
	const uint8_t *data = (const uint8_t*)&ctx->quic_data;
	if (prepare_get_fast(ctx, off+1))
	{
		QD_PRINTF("ENODATA EAT_VARINT 1\n");
		return -ENODATA;
	}
	switch (data[off]>>6)
	{
		case 0:
			val = data[off]&0x3f;
			off += 1;
			break;
		case 1:
			if (prepare_get_fast(ctx, off+2))
			{
				QD_PRINTF("ENODATA EAT_VARINT 2\n");
				return -ENODATA;
			}
			val =
				(((uint64_t)data[off]&0x3f) << 8) |
				 ((uint64_t)data[off+1]);
			off += 2;
			break;
		case 2:
			if (prepare_get_fast(ctx, off+4))
			{
				QD_PRINTF("ENODATA EAT_VARINT 3\n");
				return -ENODATA;
			}
			val =
				(((uint64_t)data[off]&0x3f) << 24) |
				 (((uint64_t)data[off+1]) << 16) |
				 (((uint64_t)data[off+2]) << 8) |
				 ((uint64_t)data[off+3]);
			off += 4;
			break;
		case 3:
			if (prepare_get_fast(ctx, off+8))
			{
				QD_PRINTF("ENODATA EAT_VARINT 4\n");
				return -ENODATA;
			}
			val =
				(((uint64_t)data[off]&0x3f) << 56) |
				 (((uint64_t)data[off+1]) << 48) |
				 (((uint64_t)data[off+2]) << 40) |
				 (((uint64_t)data[off+3]) << 32) |
				 (((uint64_t)data[off+4]) << 24) |
				 (((uint64_t)data[off+5]) << 16) |
				 (((uint64_t)data[off+6]) << 8) |
				 ((uint64_t)data[off+7]);
			off += 8;
			break;
	}
	*poff = off;
	*p = val;
	return 0;
}
#endif

int tls_layer(struct quic_ctx *ctx, struct tls_layer *tls, const char **hname, size_t *hlen)
{
	switch (tls->state)
	{
		case 0:
			//quic_al_cnt_reset(ctx);
			break;
		case 1: goto state1;
		case 2: goto state2;
		case 3: goto state3;
		case 4: goto state4;
		case 5: goto state5;
		case 6: goto state6;
		case 7: goto state7;
		case 8: goto state8;
		case 9: goto state9;
		case 10: goto state10;
		case 11: goto state11;
		case 12: goto state12;
		case 13: goto state13;
		case 14: goto state14;
		case 15: goto state15;
		case 16: goto state16;
		default: abort();
	}
	// 1 byte client hello (0x1)
	// 3 bytes len
	// 2 bytes version
	// 32 bytes random
	// 1 bytes session ID length
#if 0
	if (prepare_get_fast(ctx, off+39))
	{
		QD_PRINTF("ENODATA 10\n");
		return -ENODATA;
	}
#endif
state1:
	if (may_pull(ctx, &tls->maypull, 6))
	{
		tls->state = 1;
		return -EAGAIN;
	}
	if (tls->maypull.past_data[0] != 0x1)
	{
		return -ENOMSG;
	}
	tls->tlslen =
		(((uint32_t)tls->maypull.past_data[1])<<16) |
		(((uint32_t)tls->maypull.past_data[2])<<8) |
		tls->maypull.past_data[3];
#if 0
	printf("tlslen %d\n", (int)ctx->tlslen);
	if (ctx->tlslen + 4 > length_in_packet)
	{
		QD_PRINTF("ENODATA 10.5\n");
		return -ENODATA;
	}
#endif
	//tls_start_off = ctx->off;
	quic_al_cnt_reset(tls);
	if (tls->tlslen < 2 + 32 + 1)
	{
		QD_PRINTF("ENODATA 10.6\n");
		return -ENODATA;
	}
	if (tls->maypull.past_data[4] != 0x03 || tls->maypull.past_data[5] != 0x03)
	{
		return -ENOMSG;
	}
	//off += 2;
state2:
	if (ctx_skip(ctx, &tls->maypull, 32))
	{
		tls->state = 2;
		return -EAGAIN;
	}
state3:
	if (may_pull(ctx, &tls->maypull, 1))
	{
		tls->state = 3;
		return -EAGAIN;
	}
	tls->session_id_length = tls->maypull.past_data[0];
	if (tls->maypull.al_cnt + tls->session_id_length + 2 > tls->tlslen)
	{
		QD_PRINTF("ENODATA 10.7\n");
		return -ENODATA;
	}
state4:
	if (ctx_skip(ctx, &tls->maypull, tls->session_id_length))
	{
		tls->state = 4;
		return -EAGAIN;
	}
state5:
	if (may_pull(ctx, &tls->maypull, 2))
	{
		tls->state = 5;
		return -EAGAIN;
	}
	tls->cipher_suites_length = (((uint16_t)tls->maypull.past_data[0])<<8) | tls->maypull.past_data[1];
	if (tls->maypull.al_cnt + tls->cipher_suites_length + 1 > tls->tlslen)
	{
		QD_PRINTF("ENODATA 11.5\n");
		return -ENODATA;
	}
state6:
	if (ctx_skip(ctx, &tls->maypull, tls->cipher_suites_length))
	{
		tls->state = 6;
		return -EAGAIN;
	}
state7:
	if (may_pull(ctx, &tls->maypull, 1))
	{
		tls->state = 7;
		return -EAGAIN;
	}
	tls->compression_methods_length = tls->maypull.past_data[0];
	if (tls->maypull.al_cnt + tls->compression_methods_length + 2 > tls->tlslen)
	{
		QD_PRINTF("ENODATA 12.5\n");
		return -ENODATA;
	}
state8:
	if (ctx_skip(ctx, &tls->maypull, tls->compression_methods_length))
	{
		tls->state = 8;
		return -EAGAIN;
	}
state9:
	if (may_pull(ctx, &tls->maypull, 2))
	{
		tls->state = 9;
		return -EAGAIN;
	}
	tls->extensions_length = (((uint16_t)tls->maypull.past_data[0])<<8) | tls->maypull.past_data[1];
	if (tls->maypull.al_cnt + tls->extensions_length > tls->tlslen)
	{
		QD_PRINTF("Left side: %d\n", (int)(tls->maypull.al_cnt + tls->extensions_length));
		QD_PRINTF("Right side: %d\n", (int)(tls->tlslen));
		QD_PRINTF("ENODATA 13.5\n");
		return -ENODATA;
	}
	tls->ext_start_al_cnt = tls->maypull.al_cnt;
	while (tls->maypull.al_cnt < tls->ext_start_al_cnt + tls->extensions_length)
	{
		if (tls->maypull.al_cnt + 4 > tls->ext_start_al_cnt + tls->extensions_length)
		{
			QD_PRINTF("ENODATA 14.3\n");
			return -ENODATA;
		}
state10:
		if (may_pull(ctx, &tls->maypull, 4))
		{
			tls->state = 10;
			return -EAGAIN;
		}
		tls->ext_type = (((uint16_t)tls->maypull.past_data[0])<<8) | tls->maypull.past_data[1];
		tls->ext_len = (((uint16_t)tls->maypull.past_data[2])<<8) | tls->maypull.past_data[3];
		if (tls->maypull.al_cnt + tls->ext_len > tls->ext_start_al_cnt + tls->extensions_length)
		{
			QD_PRINTF("ENODATA 14.7\n");
			return -ENODATA;
		}
		if (tls->ext_type != 0 || tls->ext_len < 2)
		{
state11:
			if (ctx_skip(ctx, &tls->maypull, tls->ext_len))
			{
				tls->state = 11;
				return -EAGAIN;
			}
			continue;
		}
		tls->ext_data_start_al_cnt = tls->maypull.al_cnt;
state12:
		if (may_pull(ctx, &tls->maypull, 2))
		{
			tls->state = 12;
			return -EAGAIN;
		}
		tls->sname_list_len = (((uint16_t)tls->maypull.past_data[0])<<8) | tls->maypull.past_data[1];
		if (tls->ext_len < tls->sname_list_len + 2)
		{
			QD_PRINTF("ENODATA 16\n");
			return -ENODATA;
		}
		while (tls->maypull.al_cnt < tls->ext_data_start_al_cnt + 2 + tls->sname_list_len)
		{
state13:
			if (may_pull(ctx, &tls->maypull, 1))
			{
				tls->state = 13;
				return -EAGAIN;
			}
			tls->sname_type = tls->maypull.past_data[0];
			if (tls->maypull.al_cnt + 2 > tls->ext_data_start_al_cnt + 2 + tls->sname_list_len)
			{
				QD_PRINTF("ENODATA 17\n");
				return -ENODATA;
			}
state14:
			if (may_pull(ctx, &tls->maypull, 2))
			{
				tls->state = 14;
				return -EAGAIN;
			}
			tls->sname_len = (((uint16_t)tls->maypull.past_data[0])<<8) | tls->maypull.past_data[1];
			if (tls->maypull.al_cnt + tls->sname_len > tls->ext_data_start_al_cnt + 2 + tls->sname_list_len)
			{
				QD_PRINTF("ENODATA 18\n");
				return -ENODATA;
			}
			if (tls->sname_type == 0)
			{
state15:
				if (ctx_getdata(ctx, &tls->maypull, tls->hostname, tls->sname_len > (sizeof(tls->hostname)-1) ? (sizeof(tls->hostname)-1) : tls->sname_len))
				{
					tls->state = 15;
					return -EAGAIN;
				}
				if (tls->sname_len > (sizeof(tls->hostname)-1))
				{
					tls->hostname[sizeof(tls->hostname)-1] = '\0';
					*hname = tls->hostname;
					*hlen = sizeof(tls->hostname)-1;
					return -ENAMETOOLONG;
				}
				tls->hostname[tls->sname_len] = '\0';
				*hname = tls->hostname;
				*hlen = tls->sname_len;
				return 0;
			}
			else
			{
state16:
				if (ctx_skip(ctx, &tls->maypull, tls->sname_len))
				{
					tls->state = 16;
					return -EAGAIN;
				}
			}
		}
	}
#if 0
	for (;;)
	{
		if (prepare_get_fast(ctx, off+1))
		{
			QD_PRINTF("ENODATA 13\n");
			return -ENODATA;
		}
		printf("%.2x ", data[off++]);
	}
#endif

	return -EHOSTUNREACH;
}

// First try: initial_off == 0
int quic_tls_sni_detect(struct aes_initer *in, struct inorder_ctx *inorder, struct quic_ctx *ctx, struct tls_layer *tls, const char **hname, size_t *hlen, uint16_t initial_off, int recursive)
{
	struct quic_ctx *c = ctx;
	const uint8_t *data = (const uint8_t*)ctx->quic_data;
	int ret;
	uint32_t off = ctx->payoff; // uint32_t for safety against overflows
	uint64_t offset_in_packet;
	// Outside CRYPTO frame, there's another length field (ctx->len). If
	// length_in_packet is 512 bytes, and varints are 4 bytes, there's
	// 516 bytes of encrypted data + 16 bytes of AEAD data so
	// 532 bytes total. Outside that, if packet number is 1 byte, it
	// means outside CRYPTO frame length would be 533 bytes.
	// However, it has been checked that there's enough data in packet
	// and prepare_get_fast() tells if we go past this lemgth field
	// outside CRYPTO frame.
	uint64_t length_in_packet;
	// length_in_packet is N bytes smaller than encrypted data (w/o AEAD)
	// where N = length(frame_type) + length(offset) + length(length)
	// - but we should allow length_in_packet smaller than that, not larger
	uint32_t tlslen;
	// tlslen is length of data after type(1 byte) + len(3 bytes), or
	// 4 bytes smaller than length_in_packet
	// - but we should allow tlslen smaller than that, not larger
	uint8_t session_id_length;
	uint16_t cipher_suites_length;
	uint8_t compression_methods_length;
	uint16_t extensions_length;
	uint32_t ext_start_off; // uint32_t for safety against overflows
	uint32_t tls_start_off; // uint32_t for safety against overflows

	c->payload = data + ctx->payoff;
	//c->payload_len = ctx->siz - ctx->payoff - 16;
	c->payload_len = ctx->len - 16 - ctx->pnumlen;
	if (c->payload_len > ctx->siz - ctx->payoff - 16)
	{
		c->payload_len = ctx->siz - ctx->payoff - 16;
	}
	c->off = initial_off;
	if (initial_off != 0)
	{
		next_iv_and_stream(c);
	}

	while (c->off < c->payload_len)
	{
		struct maypull_ctx ts = {};
		struct maypull_ctx *t = &ts;
		ctx->tls_limit = ctx->payload_len;
		// Eat padding, ping and ACK frames away
		for (;;)
		{
			if (may_pull(ctx, t, 1))
			{
				QD_PRINTF("ENODATA 1\n");
				return -ENODATA;
			}
			if (t->past_data[0] == 0x02 || t->past_data[0] == 0x03)
			{
				// ACK frame
				uint64_t ack_range_cnt;
				uint64_t i;
				int contains_ecn = !!(t->past_data[0] == 0x03);
				off++;
				if (may_pull_varint(ctx, t, NULL))
				{
					return -ENODATA;
				}
				if (may_pull_varint(ctx, t, NULL))
				{
					return -ENODATA;
				}
				if (may_pull_varint(ctx, t, &ack_range_cnt))
				{
					return -ENODATA;
				}
				if (may_pull_varint(ctx, t, NULL))
				{
					return -ENODATA;
				}
				for (i = 0; i < ack_range_cnt; i++)
				{
					if (may_pull_varint(ctx, t, NULL))
					{
						return -ENODATA;
					}
					if (may_pull_varint(ctx, t, NULL))
					{
						return -ENODATA;
					}
				}
				if (contains_ecn)
				{
					if (may_pull_varint(ctx, t, NULL))
					{
						return -ENODATA;
					}
					if (may_pull_varint(ctx, t, NULL))
					{
						return -ENODATA;
					}
					if (may_pull_varint(ctx, t, NULL))
					{
						return -ENODATA;
					}
				}
				continue;
			}
			else if (t->past_data[0] == 0x1c)
			{
				// CONNECTION_CLOSE frame
				uint64_t reason_phrase_length;
				off++;
				if (may_pull_varint(ctx, t, NULL)) // error code
				{
					return -ENODATA;
				}
				if (may_pull_varint(ctx, t, NULL)) // frame type
				{
					return -ENODATA;
				}
				if (may_pull_varint(ctx, t, &reason_phrase_length))
				{
					return -ENODATA;
				}
				//if (off + reason_phrase_length > UINT16_MAX)
				if (reason_phrase_length > UINT16_MAX)
				{
					return -ENODATA;
				}
				if (ctx_skip(ctx, t, reason_phrase_length))
				{
					QD_PRINTF("ENODATA 0x1c\n");
					return -ENODATA;
				}
				off += reason_phrase_length;
				continue;
			}
			else if (t->past_data[0] != 0x00 && t->past_data[0] != 0x01)
			{
				break;
			}
			//off++;
		}
		if (t->past_data[0] != 0x06)
		{
			return -ENOMSG;
		}
		//off += 1;
		uint16_t stored_off = c->off - 1; // That 1 char is already read

		if (may_pull_varint(ctx, t, &offset_in_packet))
		{
			QD_PRINTF("ENODATA 2\n");
			return -ENODATA;
		}
#if 0
		if (prepare_get_fast(ctx, off+1))
		{
			QD_PRINTF("ENODATA 2\n");
			return -ENODATA;
		}

		switch (data[off]>>6)
		{
			case 0:
				offset_in_packet = data[off]&0x3f;
				off += 1;
				break;
			case 1:
				if (prepare_get_fast(ctx, off+2))
				{
					QD_PRINTF("ENODATA 3\n");
					return -ENODATA;
				}
				offset_in_packet =
					(((uint64_t)data[off]&0x3f) << 8) |
					 ((uint64_t)data[off+1]);
				off += 2;
				break;
			case 2:
				if (prepare_get_fast(ctx, off+4))
				{
					QD_PRINTF("ENODATA 4\n");
					return -ENODATA;
				}
				offset_in_packet =
					(((uint64_t)data[off]&0x3f) << 24) |
					 (((uint64_t)data[off+1]) << 16) |
					 (((uint64_t)data[off+2]) << 8) |
					 ((uint64_t)data[off+3]);
				off += 4;
				break;
			case 3:
				if (prepare_get_fast(ctx, off+8))
				{
					QD_PRINTF("ENODATA 5\n");
					return -ENODATA;
				}
				offset_in_packet =
					(((uint64_t)data[off]&0x3f) << 56) |
					 (((uint64_t)data[off+1]) << 48) |
					 (((uint64_t)data[off+2]) << 40) |
					 (((uint64_t)data[off+3]) << 32) |
					 (((uint64_t)data[off+4]) << 24) |
					 (((uint64_t)data[off+5]) << 16) |
					 (((uint64_t)data[off+6]) << 8) |
					 ((uint64_t)data[off+7]);
				off += 8;
				break;
		}
#endif
		if (may_pull_varint(ctx, t, &length_in_packet))
		{
			QD_PRINTF("ENODATA 2\n");
			return -ENODATA;
		}

#if 0
		if (prepare_get_fast(ctx, off+1))
		{
			QD_PRINTF("ENODATA 6\n");
			return -ENODATA;
		}

		switch (data[off]>>6)
		{
			case 0:
				length_in_packet = data[off]&0x3f;
				off += 1;
				break;
			case 1:
				if (prepare_get_fast(ctx, off+2))
				{
					QD_PRINTF("ENODATA 7\n");
					return -ENODATA;
				}
				length_in_packet =
					(((uint64_t)data[off]&0x3f) << 8) |
					 ((uint64_t)data[off+1]);
				off += 2;
				break;
			case 2:
				if (prepare_get_fast(ctx, off+4))
				{
					QD_PRINTF("ENODATA 8\n");
					return -ENODATA;
				}
				length_in_packet =
					(((uint64_t)data[off]&0x3f) << 24) |
					 (((uint64_t)data[off+1]) << 16) |
					 (((uint64_t)data[off+2]) << 8) |
					 ((uint64_t)data[off+3]);
				off += 4;
				break;
			case 3:
				if (prepare_get_fast(ctx, off+8))
				{
					QD_PRINTF("ENODATA 9\n");
					return -ENODATA;
				}
				length_in_packet =
					(((uint64_t)data[off]&0x3f) << 56) |
					 (((uint64_t)data[off+1]) << 48) |
					 (((uint64_t)data[off+2]) << 40) |
					 (((uint64_t)data[off+3]) << 32) |
					 (((uint64_t)data[off+4]) << 24) |
					 (((uint64_t)data[off+5]) << 16) |
					 (((uint64_t)data[off+6]) << 8) |
					 ((uint64_t)data[off+7]);
				off += 8;
				break;
		}
#endif
		if (length_in_packet > (uint64_t)UINT16_MAX ||
		    length_in_packet > (uint64_t)INT_MAX)
		{
			QD_PRINTF("ENODATA 9.25\n");
			return -ENODATA;
		}
#if 0
		printf("length_in_packet %d\n", (int)length_in_packet);
		if (((int)off) + ((int)length_in_packet) + 16 > ((int)ctx->payoff) + ((int)ctx->len) - ((int)ctx->pnumlen))
		{
			QD_PRINTF("Left side: %d\n", (int)(off + length_in_packet + 16));
			QD_PRINTF("Right side: %d\n", (int)(ctx->payoff + ctx->len - ctx->pnumlen));
			QD_PRINTF("ENODATA 9.5\n");
			return -ENODATA;
		}
#endif
		if (((int)c->off) + ((int)length_in_packet) > ((int)c->payload_len))
		{
			QD_PRINTF("Left side: %d\n", (int)(c->off + length_in_packet));
			QD_PRINTF("Right side: %d\n", (int)(c->payload_len));
			QD_PRINTF("ENODATA 9.5\n");
			return -ENODATA;
		}
		if (offset_in_packet + length_in_packet <= inorder->cur_off)
		{
			// No useful data at all
			if (ctx_skip(ctx, t, length_in_packet))
			{
				// Shouldn't happen
				return -ENODATA;
			}
			continue;
		}
		if (offset_in_packet > inorder->cur_off)
		{
			// No useful data at all now, but may use in future
			// FIXME uint32 vs 64
			inorder_add_entry(inorder, offset_in_packet, length_in_packet, stored_off, ctx->quic_data_off_in_data0, ctx->pkt);
			if (ctx_skip(ctx, t, length_in_packet))
			{
				// Shouldn't happen
				return -ENODATA;
			}
			continue;
		}
		if (offset_in_packet < inorder->cur_off)
		{
			if (ctx_skip(ctx, t, inorder->cur_off - offset_in_packet))
			{
				// Shouldn't happen
				return -ENODATA;
			}
		}
		//printf("offset_in_packet is %d\n", (int)offset_in_packet);
		if (offset_in_packet == 0 && inorder->cur_off == 0)
		{
			//printf("Initing state to 0\n");
			tls->state = 0;
			tls->maypull.past_data_len = 0;
			tls->maypull.dataop_remain = 0;
		}
#if 0 // For testing
		int old_payload_len = c->payload_len;
		for (c->payload_len = c->off+1; c->payload_len <= old_payload_len; c->payload_len+=1)
		{
			int ret = tls_layer(ctx, hname, hlen);
			if (ret == 0)
			{
				return 0;
			}
			else if (ret != -EAGAIN)
			{
				printf("ret is %d\n", ret);
				return ret;
			}
		}
#else
		// (length_in_packet - (inorder->cur_off - offset_in_packet))
		ctx->tls_limit = ctx->off + length_in_packet;
		ret = tls_layer(ctx, tls, hname, hlen);
		if (ret != -EAGAIN)
		{
			return ret;
		}
		inorder->cur_off += length_in_packet - (inorder->cur_off - offset_in_packet);
		if (recursive == 0)
		{
			for (;;)
			{
				struct quic_ctx ctx2;
				struct inorder_entry *e = inorder_get_entry(inorder);
				int useful_len;
				int ret2;
				if (e == NULL)
				{
					break;
				}
				useful_len = e->crypto_content_len - (inorder->cur_off - e->start_content_off);
				if (useful_len < 0)
				{
					inorder_entry_mfree(e);
					continue;
					// Never happens
					// XXX or could it still happen?
					//abort();
				}
				//quic_init(in, inorder, &ctx2, ctx->data0, ctx->siz0, ctx->quic_data_off_in_data0, ctx->siz);
				ret2 = quic_init(in, inorder, &ctx2, e->pkt->data, e->pkt->sz, e->quic_hdr_start_in_frame_off, e->pkt->sz - e->quic_hdr_start_in_frame_off);
				if (ret2 < 0)
				{
					inorder_entry_mfree(e);
					return ret2;
				}
				ret2 = quic_tls_sni_detect(in, inorder, &ctx2, tls, hname, hlen, e->start_in_frame_off, 1);
				quic_free_after_init(&ctx2);
				inorder_entry_mfree(e);
				if (ret2 != -EAGAIN)
				{
					return ret2;
				}
			}
		}
		else
		{
			// recursive mode: handle only 1 item
			return -EAGAIN;
		}
#endif
	}
	return -EAGAIN;
}

void firefox_test(void)
{
	struct aes_initer in;
	const char *hname;
	size_t hlen;
	struct quic_ctx ctx;
	struct inorder_ctx inorder;
	struct tls_layer tls;
	int ret = 0;
	aes_initer_init(&in);
	inorder_ctx_init(&inorder);
	for (;;)
	{
		printf("FIREFOX ROUND\n");
		quic_init0(&ctx);
		ret = quic_init(&in, &inorder, &ctx, quic_data, sizeof(quic_data), ret, sizeof(quic_data) - ret);
		if (ret < 0)
		{
			printf("Ret %d\n", ret);
			break;
		}
		printf("sz %zu\n", sizeof(official_data));
		printf("Payoff %d\n", (int)ctx.payoff);
		printf("ctx.len %d\n", (int)ctx.len);
		printf("ctx.pnumlen %d\n", (int)ctx.pnumlen);
		//printf("%d\n", prepare_get(&ctx, new_first_nondecrypted_off));
		if (quic_tls_sni_detect(&in, &inorder, &ctx, &tls, &hname, &hlen, 0, 0) == 0)
		{
			size_t j;
			printf("Found SNI: ");
			for (j = 0; j < hlen; j++)
			{
				printf("%c", hname[j]);
			}
			printf("\n");
		}
		quic_free_after_init(&ctx);
		if (ret == 0)
		{
			break;
		}
	}
	inorder_ctx_free(&inorder);
}
void official_test(void)
{
	struct aes_initer in;
	const char *hname;
	size_t hlen;
	struct quic_ctx ctx;
	struct inorder_ctx inorder;
	struct tls_layer tls;
	int ret = 0;
	aes_initer_init(&in);
	inorder_ctx_init(&inorder);
	for (;;)
	{
		printf("OFFICIAL ROUND\n");
		quic_init0(&ctx);
		ret = quic_init(&in, &inorder, &ctx, official_data, sizeof(official_data), ret, sizeof(official_data) - ret);
		if (ret < 0)
		{
			break;
		}
		printf("sz %zu\n", sizeof(official_data));
		printf("Payoff %d\n", (int)ctx.payoff);
		printf("ctx.len %d\n", (int)ctx.len);
		printf("ctx.pnumlen %d\n", (int)ctx.pnumlen);
		//printf("%d\n", prepare_get(&ctx, new_first_nondecrypted_off));
		if (quic_tls_sni_detect(&in, &inorder, &ctx, &tls, &hname, &hlen, 0, 0) == 0)
		{
			size_t j;
			printf("Found SNI: ");
			for (j = 0; j < hlen; j++)
			{
				printf("%c", hname[j]);
			}
			printf("\n");
		}
		quic_free_after_init(&ctx);
		if (ret == 0)
		{
			break;
		}
	}
	inorder_ctx_free(&inorder);
}


/*
 * The first packet sent by a client always includes a CRYPTO frame that
 * contains the start or all of the first cryptographic handshake message. The
 * first CRYPTO frame sent always begins at an offset of 0; see Section 7.
 *
 * TODO / FIXME: verify offset, only start at offset == 0
 *
 * If the ClientHello spans multiple Initial packets, such servers would need
 * to buffer the first received fragments, which could consume excessive
 * resources if the client's address has not yet been validated.
 *
 * TODO / FIXME: "start or all" -- can it continue on other frames?
 *
 * frame / packet / datagram
 * - packet contains 1 or many frames
 * - A UDP datagram can include one or more QUIC packets.
 *
 * Frames always fit within a single QUIC packet and cannot span multiple
 * packets.
 *
 * Senders MUST NOT coalesce QUIC packets with different connection IDs into a
 * single UDP datagram. Receivers SHOULD ignore any subsequent packets with a
 * different Destination Connection ID than the first packet in the datagram.
 *
 * Datagrams that contain an Initial packet (Client Initial, Server Initial,
 * and some Client Completion) contain at least 1200 octets of UDP payload.
 * This protects against amplification attacks and verifies that the network
 * path meets the requirements for the minimum QUIC IP packet size; see Section
 * 14 of [QUIC-TRANSPORT]. This is accomplished by either adding PADDING frames
 * within the Initial packet, coalescing other packets with the Initial packet,
 * or leaving unused payload in the UDP packet after the Initial packet.
 *
 * Implementations MUST support buffering at least 4096 bytes of data
 * received in out-of-order CRYPTO frames. Endpoints MAY choose to
 * allow more data to be buffered during the handshake. A larger limit
 * during the handshake could allow for larger keys or credentials to be
 * exchanged. And endpoint's buffer size does not need to remain
 * constant during the life of the connection.
 *
 * The payload of an Initial packet includes a CRYPTO frame (or frames)
 * containing a cryptographic handshake message, ACK frames, or both.
 * PING, PADDING, and CONNECTION_CLOSE frames of type 0x1c are also
 * permitted.  An endpoint that receives an Initial packet containing
 * other frames can either discard the packet as spurious or treat it as
 * a connection error.
 *
 * TODO / FIXME: PING, CONNECTION_CLOSE(0x1c), ACK
 *
 * ACK:
 * type = 0x02 (no ECN) or 0x03 (yes ECN)
 * two varints, discard
 * one varint, ack range count (does not include "first ack range" in it)
 * first ack range varint, discard
 * ack ranges
 * - each ack range contains two varints, discard
 * ecn counts, if type 0x03, then three varints, discard
 *
 * PING:
 * type = 0x01, no content
 *
 * CONNECTION_CLOSE(0x1c):
 */

// FIXME check that all packets belong to same connection id

/*
 * Note that subsequent Initial packets might contain a Destination Connection
 * ID other than the one used to generate the Initial secret. Therefore,
 * attempts to decrypt these packets using the procedure above might fail
 * unless the Initial secret is retained by the observer.
 */

/*
 * TODO NAT:
 * - client's IP address can change and QUIC tolerates that, AL-NAT should
 */


/*
 * When an Initial packet is sent by a client that has not previously
 * received an Initial or Retry packet from the server, the client populates
 * the Destination Connection ID field with an unpredictable value.  This
 * Destination Connection ID MUST be at least 8 bytes in length.  Until a
 * packet is received from the server, the client MUST use the same Destination
 * Connection ID value on all packets in this connection.
 *
 * Destination connection ID length maximum: 20
 * Source connection ID length maximum: 20
 *
 * Senders MUST NOT coalesce QUIC packets with different connection IDs into a
 * single UDP datagram. Receivers SHOULD ignore any subsequent packets with a
 * different Destination Connection ID than the first packet in the datagram.
 *
 * - TODO: handle these
 */

int main(int argc, char **argv)
{
	struct quic_ctx ctx;
	struct tls_layer tls;
	int i;
	int cnt = 0;
	int new_first_nondecrypted_off;
	struct aes_initer in;
	struct inorder_ctx inorder;
	const char *hname;
	size_t hlen;
	aes_initer_init(&in);
	inorder_ctx_init(&inorder);
	quic_init0(&ctx);
	printf("%d\n", quic_init(&in, &inorder, &ctx, quic_data, sizeof(quic_data), 0, sizeof(quic_data)));
	printf("sz %zu\n", sizeof(quic_data));
	printf("Payoff %d\n", (int)ctx.payoff);
	printf("ctx.len %d\n", (int)ctx.len);
	printf("ctx.pnumlen %d\n", (int)ctx.pnumlen);
	new_first_nondecrypted_off = ((int)ctx.payoff) + ((int)ctx.len) - ((int)ctx.pnumlen);
	//printf("%d\n", prepare_get(&ctx, new_first_nondecrypted_off));
	if (quic_tls_sni_detect(&in, &inorder, &ctx, &tls, &hname, &hlen, 0, 0) == 0)
	{
		size_t j;
		printf("Found SNI: ");
		for (j = 0; j < hlen; j++)
		{
			printf("%c", hname[j]);
		}
		printf("\n");
	}
	//printf("State %d\n", tls.state);
	//for (i = ctx.payoff; i < new_first_nondecrypted_off; i++)
	for (i = ctx.payoff; i < ctx.payoff+16; i++)
	{
		printf("%.2x ", ctx.quic_data[i]);
		cnt++;
		if ((cnt % 16) == 0 && i != ctx.payoff+16-1)
		{
			printf("\n");
		}
	}
	printf("\n");
	if (memmem(ctx.quic_data+ctx.payoff, ctx.len-ctx.pnumlen, "www.google.com", strlen("www.google.com")) != 0)
	{
		printf("Found SNI!\n");
	}
	//printf("Expected: 06 00 40 f1 01 00 00 ed 03 03 eb f8 fa 56 f1 29 ..\n");
	inorder_ctx_free(&inorder);
	quic_free_after_init(&ctx);
	
	official_test();
	firefox_test();

	// 5.2 s per 1M packets (SHA256 high performance), prepare_get
	// 5.5 s per 1M packets (SHA256 public domain), prepare_get
	// 5.0 s per 1M packets (SHA256 public domain), quic_tls_sni_detect
	//
	// Initial packet: at least 1200 bytes, this is UDP payload
	// 1200+8+20+14 = 1242 bytes, 9936 bits, 1.99 Gbps
	// Ethernet preamble: 7 bytes
	// Ethernet frame start delimiter: 1 bytes
	// Ethernet frame check sequence: 4 bytes
	// Ethernet interpacket gap: 12 bytes
	// So with these:
	// 7+1+14+20+8+1200+4+12 = 1266 bytes, 10128 bits, 2.03 Gbps
	for (i = 0; i < 1000*1000; i++)
	{
		inorder_ctx_init(&inorder);
		quic_init0(&ctx);
		quic_init(&in, &inorder, &ctx, quic_data, sizeof(quic_data), 0, sizeof(quic_data));
		quic_tls_sni_detect(&in, &inorder, &ctx, &tls, &hname, &hlen, 0, 0);
		//prepare_get(&ctx, new_first_nondecrypted_off);
		inorder_ctx_free(&inorder);
		quic_free_after_init(&ctx);
	}
	return 0;
}

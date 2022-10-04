#include <stddef.h>
#include <stdio.h>
#include "rbtree.h"
#include "linkedlist.h"
#include "containerof.h"
#include <stdlib.h>
#include <stdint.h>

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
			rb_tree_nocmp_delete(&ctx->tree, &e->node);
			inorder_entry_mfree(e);
			ret = rb_tree_nocmp_insert_nonexist(&ctx->tree, cmp, NULL, &e->node);
			if (ret != 0)
			{
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

int main(int argc, char **argv)
{
	struct inorder_ctx ctx;
	inorder_ctx_init(&ctx);
	for (;;)
	{
		uint32_t start;
		uint32_t len;
		if (rand()%2)
		{
			if (ctx.cur_off < 16)
			{
				start = 0;
			}
			else
			{
				start = ctx.cur_off - 16;
			}
		}
		else if (rand()%2)
		{
			start = ctx.cur_off;
		}
		else
		{
			start = ctx.cur_off + rand()%64;
		}
		len = rand()%64;
		if (start <= ctx.cur_off)
		{
			int useful_len = len - (ctx.cur_off - start);
			printf("immediate: start %d len %d end %d\n", (int)ctx.cur_off, useful_len, (int)ctx.cur_off+useful_len);
			//ctx.cur_off += useful_len;
		}
		else
		{
			inorder_add_entry(&ctx, start, len, 0, 0, NULL);
		}
		for (;;)
		{
			struct inorder_entry *e = inorder_get_entry(&ctx);
			int useful_len;
			if (e == NULL)
			{
				break;
			}
			useful_len = e->crypto_content_len - (ctx.cur_off - e->start_content_off);
			printf("delayed: start %d len %d end %d\n", (int)ctx.cur_off, useful_len, (int)ctx.cur_off+useful_len);
			//ctx.cur_off += useful_len;
		}
		printf("iter\n");
	}
}

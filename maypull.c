#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

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
};

void next_iv(struct ctx *c)
{
	int i;
	for (i = 15; i >= 12; i--) // increment counter
	{
		c->cur_iv[i]++;
		if (c->cur_iv[i] != 0)
		{
			break;
		}
	}
}

void calc_stream(struct ctx *c)
{
}

void next_iv_and_stream(struct ctx *c)
{
	next_iv(c);
	calc_stream(c);
}

int ctx_skip(struct ctx *c, uint16_t cnt)
{
	uint8_t consumed_cryptostream = c->off - (c->off/16)*16;
	uint8_t change;
	uint16_t cntthis;
	int retval = 0;
	if (c->dataop_remain == 0)
	{
		c->dataop_remain = cnt;
	}
	else
	{
		cnt = c->dataop_remain;
	}
	cntthis = cnt;
	if (cntthis > c->payload_len - c->off)
	{
		cntthis = c->payload_len - c->off;
		retval = -EAGAIN;
	}
	if (cntthis + consumed_cryptostream < 16)
	{
		c->off += cntthis;
		cnt -= cntthis;
		c->dataop_remain = cnt;
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
	c->dataop_remain = cnt;
	return retval;
}

int ctx_getdata(struct ctx *c, void *out, uint16_t cnt)
{
	uint8_t *uout = (uint8_t*)out;
	uint16_t outoff = 0;
	uint8_t consumed_cryptostream = c->off - (c->off/16)*16;
	uint8_t change;
	uint16_t cntthis;
	int retval = 0;
	uint16_t i;
	if (c->dataop_remain == 0)
	{
		c->dataop_remain = cnt;
		c->dataop_outoff = outoff;
	}
	else
	{
		cnt = c->dataop_remain;
		outoff = c->dataop_outoff;
	}
	cntthis = cnt;
	if (cntthis > c->payload_len - c->off)
	{
		cntthis = c->payload_len - c->off;
		retval = -EAGAIN;
	}
	if (cntthis + consumed_cryptostream < 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			uout[outoff++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[consumed_cryptostream + i];
		}
		cnt -= cntthis;
		c->dataop_remain = cnt;
		return retval;
	}
	change = 16 - consumed_cryptostream; // consume this
	for (i = 0; i < change; i++)
	{
		uout[outoff++] =
			c->payload[c->off++] ^
			c->cur_cryptostream[consumed_cryptostream + i];
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
		}
		cnt -= cntthis;
	}
	c->dataop_remain = cnt;
	c->dataop_outoff = outoff;
	return retval;
}

// FIXME incremental getdata
int ctx_getdata_nonincremental(struct ctx *c, void *out, uint16_t cnt)
{
	uint8_t *uout = (uint8_t*)out;
	uint8_t consumed_cryptostream = c->off - (c->off/16)*16;
	uint8_t change;
	uint8_t i;
	if (((uint32_t)c->off) + ((uint32_t)cnt) > (uint32_t)c->payload_len)
	{
		return -ENODATA;
	}
	if (cnt + consumed_cryptostream < 16)
	{
		for (i = 0; i < cnt; i++)
		{
			*uout++ =
				c->payload[c->off++] ^
				c->cur_cryptostream[consumed_cryptostream + i];
		}
		return 0;
	}
	change = 16 - consumed_cryptostream; // consume this
	for (i = 0; i < change; i++)
	{
		*uout++ =
			c->payload[c->off++] ^
			c->cur_cryptostream[consumed_cryptostream + i];
	}
	cnt -= change;
	next_iv_and_stream(c);
	while (cnt >= 16)
	{
		for (i = 0; i < 16; i++)
		{
			*uout++ =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
		}
		cnt -= 16;
		next_iv_and_stream(c);
	}
	if (cnt > 0)
	{
		for (i = 0; i < cnt; i++)
		{
			*uout++ =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
		}
	}
	return 0;
}

int may_pull(struct ctx *c, uint8_t cnt)
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
	if (c->past_data_len >= cnt)
	{
		abort();
	}
	cnt -= c->past_data_len;
	cntthis = cnt;
	if (cntthis > c->payload_len - c->off)
	{
		cntthis = c->payload_len - c->off;
		retval = -EAGAIN;
	}
	if (cntthis + consumed_cryptostream < 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			c->past_data[c->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[consumed_cryptostream + i];
		}
		cnt -= cntthis;
		if (retval == 0)
		{
			c->past_data_len = 0;
		}
		return retval;
	}
	change = 16 - consumed_cryptostream; // consume this
	for (i = 0; i < change; i++)
	{
		c->past_data[c->past_data_len++] =
			c->payload[c->off++] ^
			c->cur_cryptostream[consumed_cryptostream + i];
	}
	cntthis -= change;
	cnt -= change;
	next_iv_and_stream(c);
#if 0
	while (cntthis >= 16)
	{
		for (i = 0; i < cntthis; i++)
		{
			c->past_data[c->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
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
			c->past_data[c->past_data_len++] =
				c->payload[c->off++] ^
				c->cur_cryptostream[i];
		}
		cnt -= cntthis;
	}
	if (retval == 0)
	{
		c->past_data_len = 0;
	}
	return retval;
}

int main(int argc, char **argv)
{
}

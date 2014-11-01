/*
 * pgp-info.c
 *	  Provide info about PGP data.
 *
 * Copyright (c) 2005 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * contrib/pgcrypto/pgp-info.c
 */
#include "postgres.h"

#include "px.h"
#include "mbuf.h"
#include "pgp.h"

static int
read_pubkey_keyid(PullFilter *pkt, uint8 *keyid_buf)
{
	int			res;
	PGP_PubKey *pk = NULL;

	res = _pgp_read_public_key(pkt, &pk);
	if (res < 0)
		goto err;

	/* skip secret key part, if it exists */
	res = pgp_skip_packet(pkt);
	if (res < 0)
		goto err;

	switch (pk->algo)
	{
		case PGP_PUB_ELG_ENCRYPT:
		case PGP_PUB_RSA_ENCRYPT:
		case PGP_PUB_RSA_ENCRYPT_SIGN:
		case PGP_PUB_RSA_SIGN:
		case PGP_PUB_DSA_SIGN:
			memcpy(keyid_buf, pk->key_id, 8);
			res = 1;
			break;
		default:
			res = PXE_PGP_UNSUPPORTED_PUBALGO;
	}

err:
	pgp_key_free(pk);
	return res;
}

static int
read_pubenc_keyid(PullFilter *pkt, uint8 *keyid_buf)
{
	uint8		ver;
	int			res;

	GETBYTE(pkt, ver);
	if (ver != 3)
		return -1;

	res = pullf_read_fixed(pkt, 8, keyid_buf);
	if (res < 0)
		return res;

	return pgp_skip_packet(pkt);
}

static const char hextbl[] = "0123456789ABCDEF";

static int
print_key(uint8 *keyid, char *dst)
{
	int			i;
	unsigned	c;

	for (i = 0; i < 8; i++)
	{
		c = keyid[i];
		*dst++ = hextbl[(c >> 4) & 0x0F];
		*dst++ = hextbl[c & 0x0F];
	}
	*dst = 0;
	return 8 * 2;
}

typedef int (*signature_cb_type)(void *opaque, PGP_Signature *sig);

static int
extract_signatures(PGP_Context *ctx, PullFilter *src, void *opaque,
				   signature_cb_type sig_cb,
				   int extract_details,
				   int need_mdc,
				   int allow_compr);


static int
read_signatures_from_compressed_data(PGP_Context *ctx, PullFilter *pkt,
									 void *opaque, signature_cb_type sig_key_cb,
									 int extract_details)
{
	int res;
	uint8 type;
	PullFilter *pf_decompr;

	GETBYTE(pkt, type);

	ctx->compress_algo = type;
	switch (type)
	{
		case PGP_COMPR_NONE:
			res = extract_signatures(ctx, pkt, opaque,
									 sig_key_cb, extract_details, 0, 0);
			break;

		case PGP_COMPR_ZIP:
		case PGP_COMPR_ZLIB:
			res = pgp_decompress_filter(&pf_decompr, ctx, pkt);
			if (res >= 0)
			{
				res = extract_signatures(ctx, pf_decompr, opaque,
										 sig_key_cb, extract_details, 0, 0);
				pullf_free(pf_decompr);
			}
			break;

		case PGP_COMPR_BZIP2:
			px_debug("read_signatures_from_compressed_data: bzip2 unsupported");
			res = PXE_PGP_UNSUPPORTED_COMPR;
			break;

		default:
			px_debug("read_signatures_from_compressed_data: unknown compr type");
			res = PXE_PGP_CORRUPT_DATA;
	}

	return res;
}

// "Context length" type packet
#define PKT_CONTEXT 3

static int
extract_signatures(PGP_Context *ctx, PullFilter *src, void *opaque,
				   signature_cb_type sig_cb,
				   int extract_details,
				   int need_mdc,
				   int allow_compr)
{
	int			res;
	int			len;
	uint8		tag;
	int			done  = 0;
	PullFilter *pkt = NULL;
	PGP_Signature *sig = NULL;

	while (1)
	{
		res = pgp_parse_pkt_hdr(src, &tag, &len, 1);
		if (res <= 0)
			break;

		/* context length inside SYMENC_MDC needs special handling */
		if (need_mdc && res == PKT_CONTEXT)
			res = pullf_create(&pkt, &pgp_mdcbuf_filter, ctx, src);
		else
			res = pgp_create_pkt_reader(&pkt, src, len, res, NULL);
		if (res < 0)
			break;

		switch (tag)
		{
			case PGP_PKT_SIGNATURE:
				res = pgp_parse_signature(ctx, &sig, pkt, NULL);
				if (res >= 0)
					res = sig_cb(opaque, sig);
				break;
			case PGP_PKT_ONEPASS_SIGNATURE:
				res = pgp_parse_onepass_signature(ctx, &sig, pkt);
				if (res >= 0)
					res = sig_cb(opaque, sig);
				break;
			case PGP_PKT_COMPRESSED_DATA:
				if (!allow_compr)
				{
					px_debug("extract_signature_keys: unexpected compression");
					res = PXE_PGP_CORRUPT_DATA;
				}
				else
					res = read_signatures_from_compressed_data(ctx, pkt, opaque,
															   sig_cb, extract_details);
				/*
				 * We're assuming that there will only ever be a single data
				 * packet, compressed or otherwise.
				 */
				if (!extract_details)
					done = 1;
				break;
			case PGP_PKT_LITERAL_DATA:
			case PGP_PKT_MDC:
				/*
				 * If extract_details is not specified, we never look for
				 * signatures beyond the data as the decryption code doesn't,
				 * either.
				 */
				if (!extract_details)
					done = 1;
				else
					res = pgp_skip_packet(pkt);
				break;

			case PGP_PKT_TRUST:
				res = pgp_skip_packet(pkt);
				break;
			default:
				px_debug("extract_signatures: unexpected tag %d", tag);
				res = PXE_PGP_CORRUPT_DATA;
		}

		if (pkt)
			pullf_free(pkt);
		pkt = NULL;
		if (sig)
			pgp_sig_free(sig);
		sig = NULL;

		if (res < 0 || done)
			break;
	}

	return res;
}


/*
 * Set up everything needed to decrypt the data and extract information about
 * the signatures.
 */
static int
read_signatures_from_data(PGP_Context *ctx, PullFilter *pkt, int tag, void *opaque,
						  signature_cb_type sig_key_cb,
						  int extract_details)
{
	int			res;
	int			resync;
	PGP_CFB	   *cfb = NULL;
	PullFilter *pf_decrypt = NULL;
	PullFilter *pf_prefix = NULL;
	PullFilter *pf_mdc = NULL;
	PullFilter *chain_head;
	int			need_mdc = (tag == PGP_PKT_SYMENCRYPTED_DATA_MDC);

	if (need_mdc)
	{
		uint8 ver;

		GETBYTE(pkt, ver);
		if (ver != 1)
		{
			px_debug("read_signature_from_data: pkt ver != 1");
			return PXE_PGP_CORRUPT_DATA;
		}
		resync = 0;
	}
	else
		resync = 1;

	res = pgp_cfb_create(&cfb, ctx->cipher_algo,
						 ctx->sess_key, ctx->sess_key_len, resync, NULL);
	if (res < 0)
		goto out;

	res = pullf_create(&pf_decrypt, &pgp_decrypt_filter, cfb, pkt);
	if (res < 0)
		goto out;

	if (need_mdc)
	{
		res = pullf_create(&pf_mdc, &pgp_mdc_filter, ctx, pf_decrypt);
		if (res < 0)
			goto out;
		chain_head = pf_mdc;
	}
	else
		chain_head = pf_decrypt;

	res = pullf_create(&pf_prefix, &pgp_prefix_filter, ctx, chain_head);
	if (res < 0)
		goto out;

	res = extract_signatures(ctx, pf_prefix, opaque, sig_key_cb, extract_details, need_mdc, 1);

out:
	if (pf_prefix)
		pullf_free(pf_prefix);
	if (pf_mdc)
		pullf_free(pf_mdc);
	if (pf_decrypt)
		pullf_free(pf_decrypt);
	if (cfb)
		pgp_cfb_free(cfb);

	return res;
}

static int
get_key_information(PGP_Context *ctx, MBuf *pgp_data, int want_main_key,
					void *opaque,
					int (*key_cb)(void *opaque, uint8 keyid[8]),
					signature_cb_type sig_cb,
					int extract_details)
{
	int			res;
	PullFilter *src;
	PullFilter *pkt = NULL;
	int			len;
	uint8		tag;
	int			got_pub_key = 0,
				got_symenc_key = 0,
				got_pubenc_key = 0;
	int			got_data = 0;
	uint8		keyid_buf[8];
	int			got_main_key = 0;
	PGP_Signature *sig = NULL;


	res = pullf_create_mbuf_reader(&src, pgp_data);
	if (res < 0)
		return res;

	while (1)
	{
		res = pgp_parse_pkt_hdr(src, &tag, &len, 0);
		if (res <= 0)
			break;
		res = pgp_create_pkt_reader(&pkt, src, len, res, NULL);
		if (res < 0)
			break;

		switch (tag)
		{
			case PGP_PKT_SECRET_KEY:
			case PGP_PKT_PUBLIC_KEY:
				if (got_main_key)
					res = PXE_PGP_MULTIPLE_KEYS;
				else
				{
					got_main_key = 1;
					if (want_main_key)
						res = read_pubkey_keyid(pkt, keyid_buf);
					else
						res = pgp_skip_packet(pkt);
				}
				break;
			case PGP_PKT_SECRET_SUBKEY:
			case PGP_PKT_PUBLIC_SUBKEY:
				if (want_main_key)
					res = pgp_skip_packet(pkt);
				else
				{
					res = read_pubkey_keyid(pkt, keyid_buf);
					if (res > 0)
						got_pub_key++;
				}
				break;
			case PGP_PKT_SYMENCRYPTED_SESSKEY:
				got_symenc_key++;
				if (sig_cb)
					res = pgp_parse_symenc_sesskey(ctx, pkt);
				else
					res = pgp_skip_packet(pkt);
				break;
			case PGP_PKT_PUBENCRYPTED_SESSKEY:
				got_pubenc_key++;
				if (sig_cb)
					res = pgp_parse_pubenc_sesskey(ctx, pkt);
				else
					res = read_pubenc_keyid(pkt, keyid_buf);
				break;
			case PGP_PKT_SYMENCRYPTED_DATA:
			case PGP_PKT_SYMENCRYPTED_DATA_MDC:
				/*
				 * If there's a key callback, read all the keys from the
				 * encrypted data.  Otherwise we're done.
				 */
				got_data = 1;
				if (sig_cb)
					res = read_signatures_from_data(ctx, pkt, tag, opaque, sig_cb, extract_details);
				break;
			case PGP_PKT_SIGNATURE:
				/*
				 * We ignore signatures not part of the encrypted data since we
				 * won't use them anyway.
				 */
			case PGP_PKT_MARKER:
			case PGP_PKT_TRUST:
			case PGP_PKT_USER_ID:
			case PGP_PKT_USER_ATTR:
			case PGP_PKT_PRIV_61:
				res = pgp_skip_packet(pkt);
				break;
			default:
				res = PXE_PGP_CORRUPT_DATA;
		}

		if (pkt)
			pullf_free(pkt);
		pkt = NULL;
		if (sig)
			pgp_sig_free(sig);
		sig = NULL;

		if (res < 0 || got_data)
			break;
	}

	pullf_free(src);
	if (pkt)
		pullf_free(pkt);

	if (res < 0)
		return res;

	/* now check sanity */
	if (got_pub_key && got_pubenc_key)
		res = PXE_PGP_CORRUPT_DATA;

	if (got_pub_key > 1)
		res = PXE_PGP_MULTIPLE_KEYS;

	if (got_pubenc_key > 1)
		res = PXE_PGP_MULTIPLE_KEYS;

	/*
	 * if still ok, look what we got
	 */
	if (res < 0)
		return res;

	if (key_cb)
	{
		if (want_main_key)
		{
			if (got_main_key)
				res = key_cb(opaque, keyid_buf);
			else
				res = PXE_PGP_NO_SIGN_KEY;
		}
		else
		{
			if (got_pubenc_key || got_pub_key)
				res = key_cb(opaque, keyid_buf);
			else if (got_symenc_key)
				res = key_cb(opaque, NULL);
			else
				res = PXE_PGP_NO_USABLE_KEY;
		}
	}

	return res;
}

static const uint8 any_key[] =
{0, 0, 0, 0, 0, 0, 0, 0};

static int
get_keyid_cb(void *opaque, uint8 keyid[8])
{
	char *dst = (char *) opaque;
	if (keyid == NULL)
	{
		memcpy(dst, "SYMKEY", 7);
		return 6;
	}
	else if (memcmp(keyid, any_key, 8) == 0)
	{
		memcpy(dst, "ANYKEY", 7);
		return 6;
	}
	else
		return print_key(keyid, dst);
}

/*
 * dst should have room for 17 bytes
 */
int
pgp_get_keyid(int want_main_key, MBuf *pgp_data, char *dst)
{
	return get_key_information(NULL, pgp_data, want_main_key, dst, get_keyid_cb, NULL, 0);
}

struct GetSignatureInfoCtx
{
	int   (*cb)(void *opaque, PGP_Signature *sig, char *keyid);
	void   *opaque;
	int		extract_details;
};

static int
get_signature_info_cb(void *opaque, PGP_Signature *sig)
{
	char keyid[17];
	struct GetSignatureInfoCtx *ctx = opaque;

	/* ignore signatures not used for literal data */
	if (sig->type != PGP_SIGTYP_BINARY &&
		sig->type != PGP_SIGTYP_TEXT)
		return 0;

	/*
	 * Also skip one-pass signatures if we're extracting details; there should
	 * be a corresponding signature packet after the data with all the details.
	 */
	if (sig->onepass && ctx->extract_details)
		return 0;

	if (memcmp(sig->keyid, any_key, 8) == 0)
		memcpy(keyid, "ANYKEY", 7);
	else
		print_key(sig->keyid, keyid);
	return ctx->cb(ctx->opaque, sig, keyid);
}

int
pgp_get_signatures(PGP_Context *ctx, MBuf *pgp_data, void *opaque,
				   int (*cb)(void *opaque, PGP_Signature *sig, char *keyid),
				   int extract_details)
{
	struct GetSignatureInfoCtx cbctx;

	memset(&cbctx, 0, sizeof(cbctx));
	cbctx.cb = cb;
	cbctx.opaque = opaque;
	cbctx.extract_details = extract_details;
	return get_key_information(ctx, pgp_data, 0, &cbctx, NULL,
							   get_signature_info_cb, extract_details);
}


/*
 * pgp-sig.c
 *	  Creating and verifying signatures.
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
 * contrib/pgcrypto/pgp-sig.c
 */
#include "postgres.h"
#include "c.h"

#include <time.h>

#include "px.h"
#include "pgp.h"


#define HASHED_SUBPKT_LENGTH		8
#define SIGNATURE_PKT_HEADER_LENGTH 4

/*
 * padded msg: 01 || padded bytes (FF) || 00 || msg
 */
static int
pad_emsa_pkcs1_v15(uint8 *data, int data_len, int res_len, uint8 **res_p)
{
	uint8	   *buf;
	int			pad_len = res_len - 2 - data_len;

	if (pad_len < 8)
		return PXE_BUG;

	buf = px_alloc(res_len);
	buf[0] = 0x01;
	memset(buf+1, 0xFF, pad_len);
	buf[pad_len + 1] = 0;
	memcpy(buf + pad_len + 2, data, data_len);
	*res_p = buf;

	return 0;
}

/*
 * padded msg = 01 || PS || 00 || M
 * PS - pad bytes (FF)
 * M - msg
 */
static uint8 *
check_emsa_pkcs1_v15(uint8 *data, int len)
{
	uint8	   *data_end = data + len;
	uint8	   *p = data;
	int			pad = 0;

	if (len < 1 + 8 + 1)
		return NULL;

	if (*p++ != 1)
		return NULL;

	while (p < data_end && *p == 0xFF)
	{
		p++;
		pad++;
	}

	if (p == data_end)
		return NULL;
	if (*p != 0)
		return NULL;
	if (pad < 8)
		return NULL;
	return p + 1;
}

static int
create_signature_vessel(PGP_Context *ctx, uint8 *data, int klen, PGP_MPI **msg_p, int full_bytes)
{
	uint8 asn1_prefix[PGP_MAX_DIGEST_ASN1_PREFIX];
	int prefix_len;
	uint8 *vessel;
	uint8 *padded = NULL;
	int res;
	PGP_MPI *m = NULL;

	prefix_len = pgp_get_digest_asn1_prefix(ctx->digest_algo, asn1_prefix);
	/* sanity check; this should have been checked already */
	if (prefix_len < 0)
		/* WTF */
		//return prefix_len;
		return PXE_BUG;

	vessel = px_alloc(klen + prefix_len);

	memcpy(vessel, asn1_prefix, prefix_len);
	memcpy(vessel + prefix_len, data, klen);

	res = pad_emsa_pkcs1_v15(vessel, klen + prefix_len, full_bytes, &padded);
	if (res >= 0)
	{
		int full_bits = full_bytes * 8 - 7;
		res = pgp_mpi_create(padded, full_bits, &m);
	}
	if (padded)
	{
		px_memset(padded, 0, full_bytes);
		px_free(padded);
	}
	px_memset(vessel, 0, klen + 1);
	px_free(vessel);

	if (res >= 0)
		*msg_p = m;

	return res;
}

static int
sign_and_write_dsa(PGP_Context *ctx, uint8 *digest, int digest_len, PGP_PubKey *pk, PushFilter *pkt)
{
	int			res;
	PGP_MPI	   *m = NULL,
			   *c = NULL;

	/* create padded msg */
	res = create_signature_vessel(ctx, digest, digest_len, &m, pk->pub.rsa.n->bytes - 1);
	if (res < 0)
		goto err;

	/* sign it */
	res = pgp_rsa_decrypt(pk, m, &c);
	if (res < 0)
		goto err;

	/* write out */
	res = pgp_mpi_write(pkt, c);

err:
	pgp_mpi_free(m);
	pgp_mpi_free(c);
	return res;
}


static int
sign_and_write_rsa(PGP_Context *ctx, uint8 *digest, int digest_len, PGP_PubKey *pk, PushFilter *pkt)
{
	int			res;
	PGP_MPI	   *m = NULL,
			   *c = NULL;

	/* create padded msg */
	res = create_signature_vessel(ctx, digest, digest_len, &m, pk->pub.rsa.n->bytes - 1);
	if (res < 0)
		goto err;

	/* sign it */
	res = pgp_rsa_decrypt(pk, m, &c);
	if (res < 0)
		goto err;

	/* write out */
	res = pgp_mpi_write(pkt, c);

err:
	pgp_mpi_free(m);
	pgp_mpi_free(c);
	return res;
}

static int
decrypt_rsa_signature(PGP_PubKey *pk, PullFilter *pkt, PGP_MPI **m_p)
{
	int			res;
	PGP_MPI	*c;

	if (pk->algo != PGP_PUB_RSA_ENCRYPT_SIGN
		&& pk->algo != PGP_PUB_RSA_SIGN)
		return PXE_PGP_WRONG_KEY;

	/* read rsa encrypted data */
	res = pgp_mpi_read(pkt, &c);
	if (res < 0)
		return res;

	/* encrypted using a private key */
	res = pgp_rsa_encrypt(pk, c, m_p);

	pgp_mpi_free(c);
	return res;
}


/*
 * Writes both the hashed and unhashed subpackets of the signature packet into
 * pkt, and updates md accordingly.
 */
static int
write_signature_subpackets(PGP_Context *ctx, PX_MD *md, PushFilter *pkt)
{
	uint32	  t;
	uint8 hashed[HASHED_SUBPKT_LENGTH];
	uint8 unhashed_hdr[4];
	int res;

	/* hashed subpkt length, two octets */
	hashed[0] = 0x00;
	hashed[1] = 0x06;
	/* header: length 5, type Signature Creation Time */
	hashed[2] = 0x05;
	hashed[3] = 2;
	/* creation time */
	t = (uint32) time(NULL);
	hashed[4] = (t >> 24) & 255;
	hashed[5] = (t >> 16) & 255;
	hashed[6] = (t >> 8) & 255;
	hashed[7] = t & 255;

	res = pushf_write(pkt, hashed, sizeof(hashed));
	if (res < 0)
		return res;
	px_md_update(md, hashed, sizeof(hashed));

	/* unhashed subpackets below; not part of the signature hash */

	/* length, two octets */
	unhashed_hdr[0] = 0x00;
	unhashed_hdr[1] = 0x0A;
	/* length 9, type Issuer */
	unhashed_hdr[2] = 0x09;
	unhashed_hdr[3] = 16;
	res = pushf_write(pkt, unhashed_hdr, sizeof(unhashed_hdr));
	if (res < 0)
		return res;
	return pushf_write(pkt, ctx->sig_key->key_id, 8);
}

/* Hashes the signature with the v4 "final trailer" */
static void
digest_v4_final_trailer(PX_MD *md, int trailer_len)
{
	uint8 b;

	/* two magic octets, per spec */
	b = 0x04;
	px_md_update(md, &b, 1);
	b = 0xFF;
	px_md_update(md, &b, 1);

	/* length of trailer, four octets in big endian */
	b = (trailer_len >> 24);
	px_md_update(md, &b, 1);
	b = (trailer_len >> 16) & 0xFF;
	px_md_update(md, &b, 1);
	b = (trailer_len >> 8) & 0xFF;
	px_md_update(md, &b, 1);
	b = trailer_len & 0xFF;
	px_md_update(md, &b, 1);
}

int
pgp_write_signature(PGP_Context *ctx, PushFilter *dst)
{
	int			res;
	PGP_PubKey  *pk = ctx->sig_key;
	uint8		ver = 4;
	uint8	   digest[PGP_MAX_DIGEST];
	int		 digest_len;

	uint8 hdr[SIGNATURE_PKT_HEADER_LENGTH];

	if (pk == NULL)
	{
		px_debug("no private key?\n");
		return PXE_BUG;
	}
	else if (ctx->sig_digest_ctx == NULL)
	{
		px_debug("no sig ctx?\n");
		return PXE_BUG;
	}

	hdr[0] = ver;
	hdr[1] = 0x00; /* TODO ? */
	hdr[2] = pk->algo;
	hdr[3] = ctx->digest_algo;
	res = pushf_write(dst, hdr, sizeof(hdr));
	if (res < 0)
		goto err;
	px_md_update(ctx->sig_digest_ctx, hdr, sizeof(hdr));

	res = write_signature_subpackets(ctx, ctx->sig_digest_ctx, dst);
	if (res < 0)
		goto err;

	digest_v4_final_trailer(ctx->sig_digest_ctx,
							SIGNATURE_PKT_HEADER_LENGTH + HASHED_SUBPKT_LENGTH);

	px_md_finish(ctx->sig_digest_ctx, digest);
	digest_len = px_md_result_size(ctx->sig_digest_ctx);

	/* write out the first two bytes of the digest */
	res = pushf_write(dst, digest, 2);
	if (res < 0)
		goto err;

	switch (pk->algo)
	{
		case PGP_PUB_RSA_ENCRYPT_SIGN:
		case PGP_PUB_RSA_SIGN:
			res = sign_and_write_rsa(ctx, digest, digest_len, pk, dst);
			break;
		case PGP_PUB_DSA_SIGN:
			res = sign_and_write_dsa(ctx, digest, digest_len, pk, dst);
			break;
		default:
			res = PXE_PGP_UNKNOWN_PUBALGO;
	}
	if (res < 0)
		goto err;

err:

	return res;
}

/*
 * Parses a one, two or five-octet length from a packet.  Partial Body Lengths
 * are not supported.  Returns 0 if EOF was reached when trying to read the
 * first byte, 1 if the length was read successfully, or < 0 if something went
 * wrong.
 */
static int
parse_packet_len(PullFilter *src, int *len_p)
{
	uint8		b;
	uint8	  *tmpbuf;
	int			len;
	int		 res;

	res = pullf_read(src, 1, &tmpbuf);
	if (res <= 0)
		return res;
	b = *tmpbuf;
	if (b <= 191)
		len = b;
	else if (b >= 192 && b < 255)
	{
		len = ((unsigned) (b) - 192) << 8;
		GETBYTE(src, b);
		len += 192 + b;
	}
	else
	{
		/* b == 255 */
		GETBYTE(src, b);
		len = b;
		GETBYTE(src, b);
		len = (len << 8) | b;
		GETBYTE(src, b);
		len = (len << 8) | b;
		GETBYTE(src, b);
		len = (len << 8) | b;
	}

	*len_p = len;
	return 1;
}

struct SigSubPktParserState {
	bool hashed_done;
	bool done;
	int lr_len;
	PullFilter *lr;
	PullFilter *hashed_src;
	PullFilter *unhashed_src;
};

struct SigSubPkt {
	int len;
	int type;
	bool hashed;
	PullFilter *body;
};

static int
start_section(struct SigSubPktParserState *pstate, bool hashed)
{
	int res;
	int len;
	PullFilter *src;
	uint8 b;

	if (hashed)
		src = pstate->hashed_src;
	else
		src = pstate->unhashed_src;

	/* read the length of the section; two-octet big endian */
	GETBYTE(src, b);
	len = b;
	GETBYTE(src, b);
	len = (len << 8) | b;

	/* hashed section MUST be present */
	if (hashed && len == 0)
		return PXE_PGP_CORRUPT_DATA;
	pstate->lr_len = len;
	res = pullf_create_limited_reader(&pstate->lr, src, &pstate->lr_len);
	if (res < 0)
		return res;
	return 0;
}

/*
 * Initializes a parser for parsing the subpackets in a version 4 signature
 * packet.  hashed_src is used for parsing the hashed subpackets, and
 * unhashed_src is used for reading the unhashed ones.  Returns < 0 on failure.
 * The caller never has to worry about releasing the parse state.
 */
static int
init_sigsubpkt_parser(PullFilter *hashed_src, PullFilter *unhashed_src, struct SigSubPktParserState *pstate)
{
	pstate->hashed_done = false;
	pstate->done = false;
	pstate->lr = NULL;
	pstate->hashed_src = hashed_src;
	pstate->unhashed_src = unhashed_src;

	return start_section(pstate, true);
}

/*
 * Releases any memory allocated by the signature subpacket parser.  You only
 * need to call this function if you want to stop reading before you've reached
 * the last subpacket.
 */
static void
destroy_sigsubpkt_parser(struct SigSubPktParserState *pstate)
{
	if (pstate->lr)
	{
		pullf_free(pstate->lr);
		pstate->lr = NULL;
	}
}

/*
 * Reads the next subpacket's header from state to subpkt.  Returns 1 if a
 * packet was read, 0 if all subpackets have been successfully read from the
 * signature packet, or < 0 on error.
 */
static int
sigsubpkt_parser_next(struct SigSubPktParserState *pstate, struct SigSubPkt *subpkt)
{
	uint8 typ;
	int len;
	int res;

	if (pstate->done || pstate->lr == NULL)
		return PXE_BUG;

again:
	res = parse_packet_len(pstate->lr, &len);
	if (res < 0)
		goto err;
	else if (res == 0)
	{
		/* no more subpackets in this section */

		if (pstate->hashed_done)
		{
			pstate->done = true;
			pullf_free(pstate->lr);
			pstate->lr = NULL;
			return 0;
		}
		pstate->hashed_done = true;
		res = start_section(pstate, false);
		if (res < 0)
			goto err;
		else
		{
			/* read the first packet of the unhashed section */
			goto again;
		}
	}

	res = pullf_read_fixed(pstate->lr, 1, &typ);
	if (res < 0)
		goto err;
	len--;

	/* done; let the caller read the data */
	subpkt->len = len;
	subpkt->type = typ;
	subpkt->hashed = !pstate->hashed_done;
	subpkt->body = pstate->lr;

err:
	if (res < 0)
	{
		pullf_free(pstate->lr);
		pstate->lr = NULL;
		return res;
	}
	return 1;
}

static int
parse_v3_signature_header(PGP_Context *ctx, PullFilter *pkt, PGP_Signature *sig)
{
	elog(ERROR, "TODO");
}

static int
parse_v4_signature_header(PGP_Context *ctx, PullFilter *pkt, PGP_Signature *sig)
{
	int res;
	uint8 version;

	struct SigSubPktParserState pstate;
	bool found_creation_time = false;
	bool found_issuer = false;
	PullFilter  *tr = NULL;

	/*
	 * In a V4 header, we need to store the everything up to the end of the
	 * hashed subpackets for the hash trailer.
	 */
	version = 4;
	mbuf_append(sig->trailer, &version, 1);
	res = pullf_create_tee_reader(&tr, pkt, sig->trailer);
	if (res < 0)
		return res;

	res = pullf_read_fixed(tr, 1, &sig->type);
	if (res < 0)
		goto err;
	res = pullf_read_fixed(tr, 1, &sig->algo);
	if (res < 0)
		goto err;
	res = pullf_read_fixed(tr, 1, &sig->digest_algo);
	if (res < 0)
		goto err;

	res = init_sigsubpkt_parser(tr, pkt, &pstate);
	if (res < 0)
		goto err;

	for (;;)
	{
		struct SigSubPkt subpkt;

		res = sigsubpkt_parser_next(&pstate, &subpkt);
		if (res < 0)
			goto err;
		else if (res == 0)
			break;

		if (subpkt.hashed && subpkt.type == PGP_SIGNATURE_CREATION_TIME)
		{
			if (found_creation_time || subpkt.len != 4)
			{
				res = PXE_PGP_CORRUPT_DATA;
				goto err;
			}
			found_creation_time = true;
			res = pullf_read_fixed(subpkt.body, 4, sig->creation_time);
			if (res < 0)
				goto err;
		}
		else if (subpkt.type == PGP_ISSUER_ID)
		{
			if (found_issuer || subpkt.len != 8)
			{
				res = PXE_PGP_CORRUPT_DATA;
				goto err;
			}
			found_issuer = true;
			res = pullf_read_fixed(subpkt.body, 8, sig->keyid);
			if (res < 0)
				goto err;
		}
		else
		{
			/* unknown subpacket; skip over the data */
			res = pullf_discard(subpkt.body, subpkt.len);
			if (res < 0)
				goto err;
		}
	}

	if (!found_creation_time)
	{
		res = PXE_PGP_CORRUPT_DATA;
		goto err;
	}

	res = pullf_read_fixed(pkt, 2, sig->expected_digest_l16);

err:
	destroy_sigsubpkt_parser(&pstate);
	if (tr)
		pullf_free(tr);
	if (res < 0)
		return res;

	return 0;
}


static int
parse_signature_payload(PGP_Context *ctx, PullFilter *pkt, PGP_Signature *sig)
{
	int res;
	PGP_PubKey *pk = ctx->sig_key;
	PGP_MPI	*m;
	uint8	   *msg;
	int			msglen;
	uint8 asn1_prefix[PGP_MAX_DIGEST_ASN1_PREFIX];
	int prefix_len;


	if (pk == NULL)
	{
		px_debug("no pubkey?");
		return PXE_BUG;
	}

	switch (pk->algo)
	{
        case PGP_PUB_RSA_SIGN:
		case PGP_PUB_RSA_ENCRYPT_SIGN:
			res = decrypt_rsa_signature(pk, pkt, &m);
			break;
		default:
			/* TODO */
			res = PXE_PGP_UNKNOWN_PUBALGO;
	}
	if (res < 0)
		return res;

	/*
	 * extract message
	 */
	msg = check_emsa_pkcs1_v15(m->data, m->bytes);
	if (msg == NULL)
	{
		px_debug("check_emsa_pkcs1_v15 failed");
		res = PXE_PGP_WRONG_KEY;
		goto out;
	}
	msglen = m->bytes - (msg - m->data);

	prefix_len = pgp_get_digest_asn1_prefix(sig->digest_algo, asn1_prefix);
	/* should have been checked already */
	if (prefix_len < 0)
	{
		res = PXE_BUG;
		goto out;
	}
	if (msglen < prefix_len ||
		memcmp(msg, asn1_prefix, prefix_len) != 0)
	{
		res = PXE_PGP_WRONG_KEY;
		goto out;
	}
	msglen -= prefix_len;
	if (msglen > PGP_MAX_DIGEST)
	{
		res = PXE_PGP_WRONG_KEY;
		goto out;
	}
	memcpy(sig->expected_digest, msg + prefix_len, msglen);

out:
	pgp_mpi_free(m);
	if (res < 0)
		return res;
	return pgp_expect_packet_end(pkt);
}

int
pgp_parse_onepass_signature(PGP_Context *ctx, PGP_Signature **sig_p, PullFilter *pkt)
{
    PGP_Signature *sig;
	uint8		version;
	uint8		type;
	uint8		digestalgo;
	uint8		pubkeyalgo;
	uint8		last;
    uint8       keyid[8];
	int         res;

	GETBYTE(pkt, version);
	GETBYTE(pkt, type);
	GETBYTE(pkt, digestalgo);
	GETBYTE(pkt, pubkeyalgo);
	res = pullf_read_fixed(pkt, 8, keyid);
	if (res < 0)
		return res;
	GETBYTE(pkt, last);

    res = pgp_sig_create(&sig);
    if (res < 0)
        return res;

    sig->onepass = 1;
    memcpy(sig->keyid, keyid, 8);
    sig->version = version;
    sig->type = type;
    sig->digest_algo = digestalgo;
    sig->algo = pubkeyalgo;
    *sig_p = sig;
    return 0;
}

int
pgp_parse_signature(PGP_Context *ctx, PGP_Signature **sig_p, PullFilter *pkt, uint8 *expected_keyid)
{
	int		version;
	int		res;
	PGP_Signature *sig;

	GETBYTE(pkt, version);

	res = pgp_sig_create(&sig);
	if (res < 0)
		goto err;
	sig->version = version;
	if (version == 3)
		res = parse_v3_signature_header(ctx, pkt, sig);
	else if (version == 4)
		res = parse_v4_signature_header(ctx, pkt, sig);
	else
		res = PXE_PGP_CORRUPT_DATA;

	if (res < 0)
		goto err;

    if (expected_keyid &&
        memcmp(expected_keyid, sig->keyid, 8) == 0)
		res = parse_signature_payload(ctx, pkt, sig);
    else
		res = pullf_discard(pkt, -1);

err:
	if (res < 0)
		pgp_sig_free(sig);
	else
		*sig_p = sig;
	return res;
}


int
pgp_verify_signature(PGP_Context *ctx)
{
	int len;
	uint8 *trailer;
	uint8 digest[PGP_MAX_DIGEST];
	PX_MD *md = ctx->sig_digest_ctx;
	PGP_Signature *sig = ctx->sig_expected;

	/* TODO ? */
	if (!ctx->sig_onepass || !ctx->sig_digest_ctx)
		return PXE_PGP_NO_USABLE_SIGNATURE;
	if (!sig)
		return PXE_BUG;
	if (sig->version != 3 && sig->version != 4)
		return PXE_BUG;
	if (!sig->trailer)
		return PXE_BUG;

	len = mbuf_grab(sig->trailer, mbuf_avail(sig->trailer), &trailer);
	px_md_update(md, trailer, len);
	if (sig->version == 4)
		digest_v4_final_trailer(md, len);
	px_md_finish(md, digest);

	if (memcmp(digest, sig->expected_digest, px_md_result_size(md)) != 0)
		return PXE_PGP_INVALID_SIGNATURE;

	return 0;
}


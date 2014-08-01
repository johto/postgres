/*
 * pgp-pubenc.c
 *	  Encrypt session key with public key.
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
 * contrib/pgcrypto/pgp-pubenc.c
 */
#include "postgres.h"
#include "c.h"

#include "px.h"
#include "pgp.h"


#define HASHED_SUBPKT_LENGTH		8
#define SIGNATURE_PKT_HEADER_LENGTH 4


/*
 * padded msg: 02 || non-zero pad bytes || 00 || msg
 */
static int
pad_eme_pkcs1_v15(uint8 *data, int data_len, int res_len, uint8 **res_p)
{
	int			res;
	uint8	   *buf,
			   *p;
	int			pad_len = res_len - 2 - data_len;

	if (pad_len < 8)
		return PXE_BUG;

	buf = px_alloc(res_len);
	buf[0] = 0x02;
	res = px_get_random_bytes(buf + 1, pad_len);
	if (res < 0)
	{
		px_free(buf);
		return res;
	}

	/* pad must not contain zero bytes */
	p = buf + 1;
	while (p < buf + 1 + pad_len)
	{
		if (*p == 0)
		{
			res = px_get_random_bytes(p, 1);
			if (res < 0)
				break;
		}
		if (*p != 0)
			p++;
	}

	if (res < 0)
	{
		px_memset(buf, 0, res_len);
		px_free(buf);
		return res;
	}

	buf[pad_len + 1] = 0;
	memcpy(buf + pad_len + 2, data, data_len);
	*res_p = buf;

	return 0;
}

static int
create_secmsg(PGP_Context *ctx, PGP_MPI **msg_p, int full_bytes)
{
	uint8	   *secmsg;
	int			res,
				i;
	unsigned	cksum = 0;
	int		 klen = ctx->sess_key_len;
	uint8	   *padded = NULL;
	PGP_MPI	*m = NULL;

	/* calc checksum */
	for (i = 0; i < klen; i++)
		cksum += ctx->sess_key[i];

	/*
	 * create "secret message"
	 */
	secmsg = px_alloc(klen + 3);
	secmsg[0] = ctx->cipher_algo;
	memcpy(secmsg + 1, ctx->sess_key, klen);
	secmsg[klen + 1] = (cksum >> 8) & 0xFF;
	secmsg[klen + 2] = cksum & 0xFF;

	/*
	 * now create a large integer of it
	 */
	res = pad_eme_pkcs1_v15(secmsg, klen + 3, full_bytes, &padded);
	if (res >= 0)
	{
		/* first byte will be 0x02 */
		int			full_bits = full_bytes * 8 - 6;

		res = pgp_mpi_create(padded, full_bits, &m);
	}

	if (padded)
	{
		px_memset(padded, 0, full_bytes);
		px_free(padded);
	}
	px_memset(secmsg, 0, klen + 3);
	px_free(secmsg);

	if (res >= 0)
		*msg_p = m;

	return res;
}

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
encrypt_and_write_elgamal(PGP_Context *ctx, PGP_PubKey *pk, PushFilter *pkt)
{
	int			res;
	PGP_MPI	*m = NULL,
			   *c1 = NULL,
			   *c2 = NULL;

	/* create padded msg */
	res = create_secmsg(ctx, &m, pk->pub.elg.p->bytes - 1);
	if (res < 0)
		goto err;

	/* encrypt it */
	res = pgp_elgamal_encrypt(pk, m, &c1, &c2);
	if (res < 0)
		goto err;

	/* write out */
	res = pgp_mpi_write(pkt, c1);
	if (res < 0)
		goto err;
	res = pgp_mpi_write(pkt, c2);

err:
	pgp_mpi_free(m);
	pgp_mpi_free(c1);
	pgp_mpi_free(c2);
	return res;
}

static int
sign_and_write_rsa(PGP_Context *ctx, uint8 *digest, int digest_len, PGP_PubKey *pk, PushFilter *pkt)
{
	int			res;
	PGP_MPI	*m = NULL,
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
encrypt_and_write_rsa(PGP_Context *ctx, PGP_PubKey *pk, PushFilter *pkt)
{
	int			res;
	PGP_MPI	*m = NULL,
			   *c = NULL;

	/* create padded msg */
	res = create_secmsg(ctx, &m, pk->pub.rsa.n->bytes - 1);
	if (res < 0)
		goto err;

	/* encrypt it */
	res = pgp_rsa_encrypt(pk, m, &c);
	if (res < 0)
		goto err;

	/* write out */
	res = pgp_mpi_write(pkt, c);

err:
	pgp_mpi_free(m);
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
static int
digest_signature_final_trailer(PGP_Context *ctx, PX_MD *md)
{
	uint8 sig_hashed_len;
	uint8 data[6];

	/* two magic octets, per spec */
	data[0] = 0x04;
	data[1] = 0xFF;

	/* length of the hashed part from the signature (big endian) */
	StaticAssertExpr((SIGNATURE_PKT_HEADER_LENGTH + HASHED_SUBPKT_LENGTH) < 0xFF,
					 "unexpected length of hashed data in signature's final trailer");
	sig_hashed_len = SIGNATURE_PKT_HEADER_LENGTH + HASHED_SUBPKT_LENGTH;
	data[2] = 0x00;
	data[3] = 0x00;
	data[4] = 0x00;
	data[5] = sig_hashed_len;
	px_md_update(ctx->sig_digest_ctx, data, sizeof(data));

	return 0;
}

int
pgp_write_pubenc_signature(PGP_Context *ctx, PushFilter *dst)
{
	int			res;
	PGP_PubKey  *pk = ctx->sig_key;
	uint8		ver = 4;
	uint8	   digest[PGP_MAX_DIGEST];
	int		 digest_len;

	uint8 hdr[SIGNATURE_PKT_HEADER_LENGTH];

	if (pk == NULL)
	{
		px_debug("no public key?\n");
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
	res = digest_signature_final_trailer(ctx, ctx->sig_digest_ctx);
	if (res < 0)
		goto err;

	px_md_finish(ctx->sig_digest_ctx, digest);
	digest_len = px_md_result_size(ctx->sig_digest_ctx);

	/* write out the first two bytes of the digest */
	res = pushf_write(dst, digest, 2);
	if (res < 0)
		goto err;

	res = sign_and_write_rsa(ctx, digest, digest_len, pk, dst);
	if (res < 0)
		goto err;

err:

	return res;
}

int
pgp_write_pubenc_sesskey(PGP_Context *ctx, PushFilter *dst)
{
	int			res;
	PGP_PubKey *pk = ctx->pub_key;
	uint8		ver = 3;
	PushFilter *pkt = NULL;
	uint8		algo;

	if (pk == NULL)
	{
		px_debug("no pubkey?\n");
		return PXE_BUG;
	}

	algo = pk->algo;

	/*
	 * now write packet
	 */
	res = pgp_create_pkt_writer(dst, PGP_PKT_PUBENCRYPTED_SESSKEY, &pkt);
	if (res < 0)
		goto err;
	res = pushf_write(pkt, &ver, 1);
	if (res < 0)
		goto err;
	res = pushf_write(pkt, pk->key_id, 8);
	if (res < 0)
		goto err;
	res = pushf_write(pkt, &algo, 1);
	if (res < 0)
		goto err;

	switch (algo)
	{
		case PGP_PUB_ELG_ENCRYPT:
			res = encrypt_and_write_elgamal(ctx, pk, pkt);
			break;
		case PGP_PUB_RSA_ENCRYPT:
		case PGP_PUB_RSA_ENCRYPT_SIGN:
			res = encrypt_and_write_rsa(ctx, pk, pkt);
			break;
	}
	if (res < 0)
		goto err;

	/*
	 * done, signal packet end
	 */
	res = pushf_flush(pkt);
err:
	if (pkt)
		pushf_free(pkt);

	return res;
}

/* contrib/pgcrypto/pgcrypto--1.1--1.2.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pgcrypto UPDATE TO '1.2'" to load this file. \quit

--
-- pgp_sym_encrypt_sign(data, key, sigkey)
--
CREATE FUNCTION pgp_sym_encrypt_sign(text, text, bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_encrypt_sign_text'
LANGUAGE C STRICT;

CREATE FUNCTION pgp_sym_encrypt_sign_bytea(bytea, text, bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_encrypt_sign_bytea'
LANGUAGE C STRICT;

--
-- pgp_sym_encrypt_sign(data, key, sigkey, psw)
--
CREATE FUNCTION pgp_sym_encrypt_sign(text, text, bytea, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_encrypt_sign_text'
LANGUAGE C STRICT;

CREATE FUNCTION pgp_sym_encrypt_sign_bytea(bytea, text, bytea, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_encrypt_sign_bytea'
LANGUAGE C STRICT;

--
-- pgp_sym_encrypt_sign(data, key, sigkey, psw, args)
--
CREATE FUNCTION pgp_sym_encrypt_sign(text, text, bytea, text, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_encrypt_sign_text'
LANGUAGE C STRICT;

CREATE FUNCTION pgp_sym_encrypt_sign_bytea(bytea, text, bytea, text, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_encrypt_sign_bytea'
LANGUAGE C STRICT;

--
-- pgp_sym_decrypt_verify(data, key, sigkey)
--
CREATE FUNCTION pgp_sym_decrypt_verify(bytea, text, bytea)
RETURNS text
AS 'MODULE_PATHNAME', 'pgp_sym_decrypt_verify_text'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgp_sym_decrypt_verify_bytea(bytea, text, bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_decrypt_verify_bytea'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_sym_decrypt_verify(data, key, sigkey, psw)
--
CREATE FUNCTION pgp_sym_decrypt_verify(bytea, text, bytea, text)
RETURNS text
AS 'MODULE_PATHNAME', 'pgp_sym_decrypt_verify_text'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgp_sym_decrypt_verify_bytea(bytea, text, bytea, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_decrypt_verify_bytea'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_sym_decrypt_verify(data, key, sigkey, psw, args)
--
CREATE FUNCTION pgp_sym_decrypt_verify(bytea, text, bytea, text, text)
RETURNS text
AS 'MODULE_PATHNAME', 'pgp_sym_decrypt_verify_text'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgp_sym_decrypt_verify_bytea(bytea, text, bytea, text, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_sym_decrypt_verify_bytea'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_pub_encrypt_sign(data, key, sigkey)
--
CREATE FUNCTION pgp_pub_encrypt_sign(text, bytea, bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_encrypt_sign_text'
LANGUAGE C STRICT;

CREATE FUNCTION pgp_pub_encrypt_sign_bytea(bytea, bytea, bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_encrypt_sign_bytea'
LANGUAGE C STRICT;

--
-- pgp_pub_encrypt_sign(data, key, sigkey, psw)
--
CREATE FUNCTION pgp_pub_encrypt_sign(text, bytea, bytea, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_encrypt_sign_text'
LANGUAGE C STRICT;

CREATE FUNCTION pgp_pub_encrypt_sign_bytea(bytea, bytea, bytea, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_encrypt_sign_bytea'
LANGUAGE C STRICT;

--
-- pgp_pub_encrypt_sign(data, key, sigkey, psw, args)
--
CREATE FUNCTION pgp_pub_encrypt_sign(text, bytea, bytea, text, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_encrypt_sign_text'
LANGUAGE C STRICT;

CREATE FUNCTION pgp_pub_encrypt_sign_bytea(bytea, bytea, bytea, text, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_encrypt_sign_bytea'
LANGUAGE C STRICT;

--
-- pgp_pub_decrypt_verify(data, key, sigkey)
--
CREATE FUNCTION pgp_pub_decrypt_verify(bytea, bytea, bytea)
RETURNS text
AS 'MODULE_PATHNAME', 'pgp_pub_decrypt_verify_text'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgp_pub_decrypt_verify_bytea(bytea, bytea, bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_decrypt_verify_bytea'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_pub_decrypt_verify(data, key, sigkey, psw)
--
CREATE FUNCTION pgp_pub_decrypt_verify(bytea, bytea, bytea, text)
RETURNS text
AS 'MODULE_PATHNAME', 'pgp_pub_decrypt_verify_text'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgp_pub_decrypt_verify_bytea(bytea, bytea, bytea, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_decrypt_verify_bytea'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_pub_decrypt_verify(data, key, sigkey, psw, arg)
--
CREATE FUNCTION pgp_pub_decrypt_verify(bytea, bytea, bytea, text, text)
RETURNS text
AS 'MODULE_PATHNAME', 'pgp_pub_decrypt_verify_text'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgp_pub_decrypt_verify_bytea(bytea, bytea, bytea, text, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pgp_pub_decrypt_verify_bytea'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_main_key_id(key)
--
CREATE FUNCTION pgp_main_key_id(bytea)
RETURNS text
AS 'MODULE_PATHNAME', 'pgp_main_key_id_w'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_sym_signature_keys(data, psw)
--
CREATE FUNCTION pgp_sym_signature_keys(bytea, text)
RETURNS TABLE (keyid text, digest text, pubkeyalgo text)
AS 'MODULE_PATHNAME', 'pgp_sym_signature_keys_w'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_pub_signature_keys(data, key)
--
CREATE FUNCTION pgp_pub_signature_keys(bytea, bytea)
RETURNS TABLE (keyid text, digest text, pubkeyalgo text)
AS 'MODULE_PATHNAME', 'pgp_pub_signature_keys_w'
LANGUAGE C IMMUTABLE STRICT;

--
-- pgp_pub_signature_keys(data, key, psw)
--
CREATE FUNCTION pgp_pub_signature_keys(bytea, bytea, text)
RETURNS TABLE (keyid text, digest text, pubkeyalgo text)
AS 'MODULE_PATHNAME', 'pgp_pub_signature_keys_w'
LANGUAGE C IMMUTABLE STRICT;

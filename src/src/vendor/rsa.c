// Copyright (C) 2010 The Chromium OS Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "common.h"
#include "stdlib.h"
#include "rsa.h"
#include "sha256.h"

/**
 * a[] -= mod
 */
static void sub_mod(const struct rsa_public_key *key, u32 *a)
{
    s64 A = 0;
    u32 i;
    for (i = 0; i < RSANUMWORDS; ++i)
    {
        A += (u64)a[i] - key->n[i];
        a[i] = (u32)A;
        A >>= 32;
    }
}

/**
 * Return a[] >= mod
 */
static int ge_mod(const struct rsa_public_key *key, const u32 *a)
{
    u32 i;
    for (i = RSANUMWORDS; i;)
    {
        --i;
        if (a[i] < key->n[i])
            return 0;
        if (a[i] > key->n[i])
            return 1;
    }
    return 1; /* equal */
}

/**
 * Montgomery c[] += a * b[] / R % mod
 */
static void mont_mul_add(const struct rsa_public_key *key,
                         u32 *c,
                         const u32 a,
                         const u32 *b)
{
    u64 A = (u64)a * b[0] + c[0];
    u32 d0 = (u32)A * key->n0inv;
    u64 B = (u64)d0 * key->n[0] + (u32)A;
    u32 i;

    for (i = 1; i < RSANUMWORDS; ++i)
    {
        A = (A >> 32) + (u64)a * b[i] + c[i];
        B = (B >> 32) + (u64)d0 * key->n[i] + (u32)A;
        c[i - 1] = (u32)B;
    }

    A = (A >> 32) + (B >> 32);

    c[i - 1] = (u32)A;

    if (A >> 32)
        sub_mod(key, c);
}

/**
 * Montgomery c[] = a[] * b[] / R % mod
 */
static void mont_mul(const struct rsa_public_key *key,
                     u32 *c,
                     const u32 *a,
                     const u32 *b)
{
    u32 i;
    for (i = 0; i < RSANUMWORDS; ++i)
        c[i] = 0;

    for (i = 0; i < RSANUMWORDS; ++i)
        mont_mul_add(key, c, a[i], b);
}

/**
 * In-place public exponentiation.
 * Exponent depends on the configuration (65537 (default), or 3).
 *
 * @param key       Key to use in signing
 * @param inout     Input and output big-endian byte array
 */
static void mod_pow(const struct rsa_public_key *key, u8 *inout)
{
    u32 a[RSANUMWORDS];
    u32 a_r[RSANUMWORDS];
    u32 aa_r[RSANUMWORDS];
    u32 *aaa = aa_r; /* Re-use location. */
    int i;

    /* Convert from big endian byte array to little endian word array. */
    for (i = 0; i < RSANUMWORDS; ++i)
    {
        u32 tmp =
            (inout[((RSANUMWORDS - 1 - i) * 4) + 0] << 24) |
            (inout[((RSANUMWORDS - 1 - i) * 4) + 1] << 16) |
            (inout[((RSANUMWORDS - 1 - i) * 4) + 2] << 8) |
            (inout[((RSANUMWORDS - 1 - i) * 4) + 3] << 0);
        a[i] = tmp;
    }

    /* TODO(drinkcat): This operation could be precomputed to save time. */
    mont_mul(key, a_r, a, key->rr); /* a_r = a * RR / R mod M */

    /* Exponent 65537 */
    for (i = 0; i < 16; i += 2)
    {
        mont_mul(key, aa_r, a_r, a_r);  /* aa_r = a_r * a_r / R mod M */
        mont_mul(key, a_r, aa_r, aa_r); /* a_r = aa_r * aa_r / R mod M */
    }
    mont_mul(key, aaa, a_r, a); /* aaa = a_r * a / R mod M */

    /* Make sure aaa < mod; aaa is at most 1x mod too large. */
    if (ge_mod(key, aaa))
        sub_mod(key, aaa);

    /* Convert to bigendian byte array */
    for (i = RSANUMWORDS - 1; i >= 0; --i)
    {
        u32 tmp = aaa[i];
        *inout++ = (u8)(tmp >> 24);
        *inout++ = (u8)(tmp >> 16);
        *inout++ = (u8)(tmp >> 8);
        *inout++ = (u8)(tmp >> 0);
    }
}

/*
 * PKCS#1 padding (from the RSA PKCS#1 v2.1 standard)
 *
 * The DER-encoded padding is defined as follows :
 * 0x00 || 0x01 || PS || 0x00 || T
 *
 * T: DER Encoded DigestInfo value which depends on the hash function used,
 * for SHA-256:
 * (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
 *
 * Length(T) = 51 octets for SHA-256
 *
 * PS: octet string consisting of {Length(RSA Key) - Length(T) - 3} 0xFF
 */
static const u8 sha256_tail[] = {
    0x00, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20};

#define PKCS_PAD_SIZE (RSANUMBYTES - SHA256_DIGEST_SIZE)

/**
 * Check PKCS#1 padding bytes
 *
 * @param sig  Signature to verify
 * @return 0 if the padding is correct.
 */
static int check_padding(const u8 *sig)
{
	u8 *ptr = (u8 *)sig;
	int result = 0;
	int i;

	/* First 2 bytes are always 0x00 0x01 */
	result |= *ptr++ ^ 0x00;
	result |= *ptr++ ^ 0x01;

	/* Then 0xff bytes until the tail */
	for (i = 0; i < PKCS_PAD_SIZE - sizeof(sha256_tail) - 2; i++)
		result |= *ptr++ ^ 0xff;

	/* Check the tail. */
	result |= memcmp(ptr, sha256_tail, sizeof(sha256_tail));

	return !!result;
}

/*
 * Verify a SHA256WithRSA PKCS#1 v1.5 signature against an expected
 * SHA256 hash.
 *
 * @param key           RSA public key
 * @param signature     RSA signature
 * @param sha           SHA-256 digest of the content to verify
 * @param workbuf32     Work buffer; caller must verify this is
 *                      3 x RSANUMWORDS elements long.
 * @return 0 on failure, 1 on success.
 */
int rsa_verify(const struct rsa_public_key *key, const u8 *signature, const u8 *sha)
{
    u8 buf[RSANUMBYTES];

    /* Copy input to local workspace. */
    memcpy(buf, signature, RSANUMBYTES);

    mod_pow(key, buf); /* In-place exponentiation. */

    int result = 0;
    int i = 0;

    // Check PKCS#1 padding bytes
    // First 2 bytes are always 0x00 0x01
    result |= buf[i++] ^ 0x00;
    result |= buf[i++] ^ 0x01;

    // Then 0xFF bytes until the tail
    for (u32 j = 0; j < PKCS_PAD_SIZE - sizeof(sha256_tail) - 2; j++) {
        result |= buf[i++] ^ 0xFF;
    }

    // Check the tail
    result |= memcmp(buf + i, sha256_tail, sizeof(sha256_tail));

    if (result != 0) {
        return 0; // Failure
    }

    // Check the digest
    if (memcmp(buf + PKCS_PAD_SIZE, sha, SHA256_DIGEST_SIZE) != 0) {
        return 0; // Failure
    }

    return 1; // Success
}

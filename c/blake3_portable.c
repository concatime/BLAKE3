#include "blake3_impl.h"
#include <stdint.h>
#include <string.h> /* memcpy */

/******************************************************************************/

typedef struct {
	uint32_t v[4];
} r128_t;

static const r128_t IVV[2] = {
    {{0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL}},
    {{0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL}}};

static const uint8_t S[7][4][4] = {
    {{0, 2, 4, 6}, {1, 3, 5, 7}, {8, 10, 12, 14}, {9, 11, 13, 15}},
    {{2, 3, 7, 4}, {6, 10, 0, 13}, {1, 12, 9, 15}, {11, 5, 14, 8}},
    {{3, 10, 13, 7}, {4, 12, 2, 14}, {6, 9, 11, 8}, {5, 0, 15, 1}},
    {{10, 12, 14, 13}, {7, 9, 3, 15}, {4, 11, 5, 1}, {0, 2, 8, 6}},
    {{12, 9, 15, 14}, {13, 11, 10, 8}, {7, 5, 0, 6}, {2, 3, 1, 4}},
    {{9, 11, 8, 15}, {14, 5, 12, 1}, {13, 0, 2, 4}, {3, 10, 6, 7}},
    {{11, 5, 1, 8}, {15, 0, 9, 6}, {14, 2, 3, 7}, {10, 12, 4, 13}},
};

/******************************************************************************/

INLINE uint32_t rotr32(uint32_t w, uint32_t c) {
	return (w >> c) | (w << (32 - c));
}

/******************************************************************************/

INLINE void r128_rl1(r128_t *r) {
	uint32_t t = r->v[0];
	r->v[0] = r->v[1], r->v[1] = r->v[2], r->v[2] = r->v[3], r->v[3] = t;
}

INLINE void r128_rr1(r128_t *r) {
	uint32_t t = r->v[3];
	r->v[3] = r->v[2], r->v[2] = r->v[1], r->v[1] = r->v[0], r->v[0] = t;
}

INLINE void r128_rr2(r128_t *r) {
	uint32_t t1 = r->v[0], t2 = r->v[1];
	r->v[0] = r->v[2], r->v[1] = r->v[3], r->v[2] = t1, r->v[3] = t2;
}

INLINE void r128_add(r128_t *r, const r128_t *a) {
	r->v[0] += a->v[0];
	r->v[1] += a->v[1];
	r->v[2] += a->v[2];
	r->v[3] += a->v[3];
}

INLINE void r128_xor(r128_t *r, const r128_t *a) {
	r->v[0] ^= a->v[0];
	r->v[1] ^= a->v[1];
	r->v[2] ^= a->v[2];
	r->v[3] ^= a->v[3];
}

INLINE void r128_rotr32(r128_t *r, uint32_t c) {
	r->v[0] = rotr32(r->v[0], c);
	r->v[1] = rotr32(r->v[1], c);
	r->v[2] = rotr32(r->v[2], c);
	r->v[3] = rotr32(r->v[3], c);
}

INLINE r128_t r128_ld(const uint32_t d[4]) {
	return (r128_t){{d[0], d[1], d[2], d[3]}};
}

INLINE void r128_st(const r128_t *r, uint32_t d[4]) {
	d[0] = r->v[0];
	d[1] = r->v[1];
	d[2] = r->v[2];
	d[3] = r->v[3];
}

INLINE r128_t r128_ld2(const uint32_t d[16], const uint8_t i[4]) {
	return (r128_t){{d[i[0]], d[i[1]], d[i[2]], d[i[3]]}};
}

/******************************************************************************/

INLINE void H(r128_t v[4], const r128_t *m0, const r128_t *m1) {
	r128_t *a = &v[0], *b = &v[1], *c = &v[2], *d = &v[3];

	// m0, 16, 12
	r128_add(a, b), r128_add(a, m0);    // a = (a + b) + m0
	r128_xor(d, a), r128_rotr32(d, 16); // d = (d ^ a) >>> 16
	r128_add(c, d);                     // c = c + d
	r128_xor(b, c), r128_rotr32(b, 12); // b = (b ^ c) >>> 12

	// m1, 8, 7
	r128_add(a, b), r128_add(a, m1);   // a = (a + b) + m1
	r128_xor(d, a), r128_rotr32(d, 8); // d = (d ^ a) >>> 8
	r128_add(c, d);                    // c = c + d
	r128_xor(b, c), r128_rotr32(b, 7); // b = (b ^ c) >>> 7
}

INLINE void E(r128_t v[4], const uint32_t msg[16], const uint8_t s[4][4]) {
	{
		r128_t m0, m1;
		m0 = r128_ld2(msg, s[0]);
		m1 = r128_ld2(msg, s[1]);
		H(v, &m0, &m1);
	}

	// Rotate
	r128_rl1(&v[1]), r128_rr2(&v[2]), r128_rr1(&v[3]);

	{
		r128_t m0, m1;
		m0 = r128_ld2(msg, s[2]);
		m1 = r128_ld2(msg, s[3]);
		H(v, &m0, &m1);
	}

	// Rotate back
	r128_rr1(&v[1]), r128_rr2(&v[2]), r128_rl1(&v[3]);
}

INLINE void compress_pre(r128_t v[4], const uint8_t block[BLAKE3_BLOCK_LEN]) {
	uint32_t block_words[16];
	// TODO(): optimize??
	block_words[0] = load32(block + 4 * 0);
	block_words[1] = load32(block + 4 * 1);
	block_words[2] = load32(block + 4 * 2);
	block_words[3] = load32(block + 4 * 3);
	block_words[4] = load32(block + 4 * 4);
	block_words[5] = load32(block + 4 * 5);
	block_words[6] = load32(block + 4 * 6);
	block_words[7] = load32(block + 4 * 7);
	block_words[8] = load32(block + 4 * 8);
	block_words[9] = load32(block + 4 * 9);
	block_words[10] = load32(block + 4 * 10);
	block_words[11] = load32(block + 4 * 11);
	block_words[12] = load32(block + 4 * 12);
	block_words[13] = load32(block + 4 * 13);
	block_words[14] = load32(block + 4 * 14);
	block_words[15] = load32(block + 4 * 15);

	E(v, block_words, S[0]);
	E(v, block_words, S[1]);
	E(v, block_words, S[2]);
	E(v, block_words, S[3]);
	E(v, block_words, S[4]);
	E(v, block_words, S[5]);
	E(v, block_words, S[6]);
}

void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags) {
	r128_t v[] = {
	    r128_ld(cv),
	    r128_ld(cv + 4),
	    IVV[0],
	    {{counter_low(counter), counter_high(counter), block_len, flags}}};

	compress_pre(v, block);

	r128_xor(&v[0], &v[2]);
	r128_xor(&v[1], &v[3]);

	r128_st(&v[0], cv);
	r128_st(&v[1], cv + 4);
}

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64]) {
	r128_t cv_lo = r128_ld(cv), cv_hi = r128_ld(cv + 4);
	r128_t v[] = {
	    cv_lo,
	    cv_hi,
	    IVV[0],
	    {{counter_low(counter), counter_high(counter), block_len, flags}}};

	compress_pre(v, block);

	// Comression function (part 1)
	r128_xor(&v[0], &v[2]);
	r128_xor(&v[1], &v[3]);

	// Comression function (part 2)
	r128_xor(&v[2], &cv_lo);
	r128_xor(&v[3], &cv_hi);

	// TODO(): optimize??
	store32(out + 4 * 0, v[0].v[0]);
	store32(out + 4 * 1, v[0].v[1]);
	store32(out + 4 * 2, v[0].v[2]);
	store32(out + 4 * 3, v[0].v[3]);
	store32(out + 4 * 4, v[1].v[0]);
	store32(out + 4 * 5, v[1].v[1]);
	store32(out + 4 * 6, v[1].v[2]);
	store32(out + 4 * 7, v[1].v[3]);
	store32(out + 4 * 8, v[2].v[0]);
	store32(out + 4 * 9, v[2].v[1]);
	store32(out + 4 * 10, v[2].v[2]);
	store32(out + 4 * 11, v[2].v[3]);
	store32(out + 4 * 12, v[3].v[0]);
	store32(out + 4 * 13, v[3].v[1]);
	store32(out + 4 * 14, v[3].v[2]);
	store32(out + 4 * 15, v[3].v[3]);
}

INLINE void hash_one_portable(const uint8_t *input, size_t blocks,
                              const uint32_t key[8], uint64_t counter,
                              uint8_t flags, uint8_t flags_start,
                              uint8_t flags_end, uint8_t out[BLAKE3_OUT_LEN]) {
	uint32_t cv[8];
	memcpy(cv, key, sizeof cv);
	uint8_t block_flags = flags | flags_start;
	while (blocks > 0) {
		if (blocks == 1) {
			block_flags |= flags_end;
		}
		blake3_compress_in_place_portable(cv, input, BLAKE3_BLOCK_LEN, counter,
		                                  block_flags);
		input = &input[BLAKE3_BLOCK_LEN];
		blocks -= 1;
		block_flags = flags;
	}
	store_cv_words(out, cv);
}

void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t *out) {
	while (num_inputs > 0) {
		hash_one_portable(inputs[0], blocks, key, counter, flags, flags_start,
		                  flags_end, out);
		if (increment_counter) {
			counter += 1;
		}
		inputs += 1;
		num_inputs -= 1;
		out = &out[BLAKE3_OUT_LEN];
	}
}

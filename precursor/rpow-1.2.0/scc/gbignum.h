/* Generic bignum module for IBM 4758 */
/* Also includes some crypto functions */

#ifndef GBIGNUM_H
#define GBIGNUM_H


#include "scc_int.h"

typedef sccModMath_Int_t		gbignum;
struct gbig_sha1ctx {
	sccSHA_RB_t		sha_rb;
	unsigned buflen;
	unsigned char	buf[64];
};
typedef struct gbig_sha1ctx		gbig_sha1ctx;

#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH	20
#endif /* SHA1_DIGEST_LENGTH */

extern int gbig_initialize(void);
extern int gbig_finalize(void);
extern int gbig_rand_bytes(void *,unsigned);
extern gbignum gbig_value_zero;
extern gbignum gbig_value_one;
extern gbignum gbig_value_two;
extern gbignum gbig_value_three;

extern void gbig_sha1_buf(unsigned char *md, void *buf, unsigned len);
extern void gbig_sha1_init(gbig_sha1ctx *ctx);
extern void gbig_sha1_update(gbig_sha1ctx *ctx, void *buf, unsigned len);
extern void gbig_sha1_final(unsigned char *md, gbig_sha1ctx *ctx);

extern int gbig_rand_bytes (void *buf, unsigned len);
extern void gbig_init (gbignum *bn);
extern void gbig_free (gbignum *bn);
extern void gbig_copy (gbignum *bnb, gbignum *bna);
extern void gbig_add (gbignum *bnc, gbignum *bna, gbignum *bnb);
extern void gbig_sub (gbignum *bnc, gbignum *bna, gbignum *bnb);
extern void gbig_mul (gbignum *bnc, gbignum *bna, gbignum *bnb);
extern void gbig_div (gbignum *bnc, gbignum *bna, gbignum *bnb);
extern void gbig_mod (gbignum *bnc, gbignum *bna, gbignum *bnb);
extern void gbig_div_mod (gbignum *bnq, gbignum *bnr, gbignum *bna,
	gbignum *bnb);
extern void gbig_mod_add (gbignum *bnc, gbignum *bna, gbignum *bnb,
	gbignum *bnm);
extern void gbig_mod_sub (gbignum *bnc, gbignum *bna, gbignum *bnb,
	gbignum *bnm);
extern void gbig_mod_mul (gbignum *bnc, gbignum *bna, gbignum *bnb,
	gbignum *bnm);
extern void gbig_mod_exp (gbignum *bnc, gbignum *bna, gbignum *bnb,
	gbignum *bnm);
extern void gbig_mod_inverse (gbignum *bnb, gbignum *bna, gbignum *bnm);
extern int gbig_cmp (gbignum *bna, gbignum *bnb);
extern void gbig_from_word (gbignum *bna, unsigned n);
extern unsigned gbig_to_word (gbignum *bna);
extern void gbig_set_bit (gbignum *bna, unsigned n);
extern void gbig_clear_bit (gbignum *bna, unsigned n);
extern void gbig_to_buf (void *buf, gbignum *bna);
extern void gbig_to_buf_len (void *buf, unsigned len, gbignum *bna);
extern unsigned gbig_buflen (gbignum *bna);
extern void gbig_from_buf (gbignum *bna, void *buf, int buflen);
extern void gbig_rand_range (gbignum *bnr, gbignum *bna, gbignum *bnb);




#endif /* GBIGNUM_H */

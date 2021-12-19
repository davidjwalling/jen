#pragma once

#include "compress.h"

struct inflate_huft_s {
    union {
        struct {
            Byte Exop;        /*  number of extra bits or operation */
            Byte Bits;        /*  number of bits in this code or subcode */
        } what;
        uInt pad;           /*  pad structure to a power of 2 (4 bytes for */
    } word;               /*   16-bit, 8 bytes for 32-bit int's) */
    uInt base;            /*  literal, length base, distance base,
                              or table offset */
};
typedef struct inflate_huft_s FAR inflate_huft;

/*  Maximum size of dynamic tree.  The maximum found in a long but non-
    exhaustive search was 1004 huft structures (850 for length/literals
    and 154 for distances, the latter actually the result of an
    exhaustive search).  The actual maximum is not known, but the
    value below is more than safe. */
#define MANY 1440

extern int inflate_trees_bits OF((
    uIntf*,                    /*  19 code lengths */
    uIntf*,                    /*  bits tree desired/actual depth */
    inflate_huft* FAR*,       /*  bits tree result */
    inflate_huft*,             /*  space for trees */
    z_streamp));                /*  for messages */

extern int inflate_trees_dynamic OF((
    uInt,                       /*  number of literal/length codes */
    uInt,                       /*  number of distance codes */
    uIntf*,                    /*  that many (total) code lengths */
    uIntf*,                    /*  literal desired/actual bit depth */
    uIntf*,                    /*  distance desired/actual bit depth */
    inflate_huft* FAR*,       /*  literal/length tree result */
    inflate_huft* FAR*,       /*  distance tree result */
    inflate_huft*,             /*  space for trees */
    z_streamp));                /*  for messages */

extern int inflate_trees_fixed OF((
    uIntf*,                    /*  literal desired/actual bit depth */
    uIntf*,                    /*  distance desired/actual bit depth */
    inflate_huft* FAR*,       /*  literal/length tree result */
    inflate_huft* FAR*,       /*  distance tree result */
    z_streamp));                /*  for memory allocation */


struct inflate_blocks_state;
typedef struct inflate_blocks_state FAR inflate_blocks_statef;

extern inflate_blocks_statef* inflate_blocks_new OF((
    z_streamp z,
    check_func c,               /*  check function */
    uInt w));                   /*  window size */

extern int inflate_blocks OF((
    inflate_blocks_statef*,
    z_streamp,
    int));                      /*  initial return code */

extern void inflate_blocks_reset OF((
    inflate_blocks_statef*,
    z_streamp,
    uLongf*));                  /*  check value on output */

extern int inflate_blocks_free OF((
    inflate_blocks_statef*,
    z_streamp));

extern void inflate_set_dictionary OF((
    inflate_blocks_statef* s,
    const Bytef* d,  /*  dictionary */
    uInt  n));       /*  dictionary length */

extern int inflate_blocks_sync_point OF((
    inflate_blocks_statef* s));

struct inflate_codes_state;
typedef struct inflate_codes_state FAR inflate_codes_statef;

extern inflate_codes_statef* inflate_codes_new OF((
    uInt, uInt,
    inflate_huft*, inflate_huft*,
    z_streamp));

extern int inflate_codes OF((
    inflate_blocks_statef*,
    z_streamp,
    int));

extern void inflate_codes_free OF((
    inflate_codes_statef*,
    z_streamp));

typedef enum {
    BLK_TYPE,     /*  get type bits (3, including end bit) */
    BLK_LENS,     /*  get lengths for stored */
    BLK_STORED,   /*  processing stored block */
    BLK_TABLE,    /*  get table lengths */
    BLK_BTREE,    /*  get bit lengths tree for a dynamic block */
    BLK_DTREE,    /*  get length, distance trees for a dynamic block */
    BLK_CODES,    /*  processing fixed or dynamic block */
    BLK_DRY,      /*  output remaining window bytes */
    BLK_DONE,     /*  finished last block, done */
    BLK_BAD
}      /*  got a data error--stuck here */
inflate_block_mode;

/*  inflate blocks semi-private state */
struct inflate_blocks_state {

    /*  mode */
    inflate_block_mode  mode;     /*  current inflate_block mode */

    /*  mode dependent information */
    union {
        uInt left;          /*  if STORED, bytes left to copy */
        struct {
            uInt table;               /*  table lengths (14 bits) */
            uInt index;               /*  index into blens (or border) */
            uIntf* blens;             /*  bit lengths of codes */
            uInt bb;                  /*  bit length tree depth */
            inflate_huft* tb;         /*  bit length decoding tree */
        } trees;            /*  if DTREE, decoding info for trees */
        struct {
            inflate_codes_statef
                * codes;
        } decode;           /*  if CODES, current state */
    } sub;                /*  submode */
    uInt last;            /*  true if this block is the last block */

    /*  mode independent information */
    uInt bitk;            /*  bits in bit buffer */
    uLong bitb;           /*  bit buffer */
    inflate_huft* hufts;  /*  single malloc for tree space */
    Bytef* window;        /*  sliding window */
    Bytef* end;           /*  one byte after sliding window */
    Bytef* read;          /*  window read pointer */
    Bytef* write;         /*  window write pointer */
    check_func checkfn;   /*  check function */
    uLong check;          /*  check on output */

};

/*  defines for inflate input/output */
/*  update pointers and return */
#define UPDBITS {s->bitb=b;s->bitk=k;}
#define UPDIN {z->avail_in=n;z->total_in+=p-z->next_in;z->next_in=p;}
#define UPDOUT {s->write=q;}
#define UPDATE {UPDBITS UPDIN UPDOUT}
#define LEAVE {UPDATE return inflate_flush(s,z,r);}
/*   get bytes and bits */
#define LOADIN {p=z->next_in;n=z->avail_in;b=s->bitb;k=s->bitk;}
#define NEEDBYTEU {if(n)r=Z_OK;else LEAVE}
#define NEXTBYTEU (n--,*p++)
#define NEEDBITS(j) {while(k<(j)){NEEDBYTEU;b|=((uLong)NEXTBYTEU)<<k;k+=8;}}
#define DUMPBITS(j) {b>>=(j);k-=(j);}
/*   output bytes */
#define WAVAIL (uInt)(q<s->read?s->read-q-1:s->end-q)
#define LOADOUT {q=s->write;m=(uInt)WAVAIL;}
#define WRAP {if(q==s->end&&s->read!=s->window){q=s->window;m=(uInt)WAVAIL;}}
#define FLUSH {UPDOUT r=inflate_flush(s,z,r); LOADOUT}
#define NEEDOUT {if(m==0){WRAP if(m==0){FLUSH WRAP if(m==0) LEAVE}}r=Z_OK;}
#define OUTBYTE(a) {*q++=(Byte)(a);m--;}
/*   load local pointers */
#define LOAD {LOADIN LOADOUT}

/*  masks for lower bits (size given to avoid silly warnings with Visual C++) */
//extern uInt inflate_mask[17];

/*  copy as much as possible from the sliding window to the output area */
extern int inflate_flush OF((
    inflate_blocks_statef*,
    z_streamp,
    int));

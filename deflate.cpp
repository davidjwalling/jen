/*  deflate.c -- compress data using the deflation algorithm
 *  Copyright (C) 1995-1998 Jean-loup Gailly.
 *  For conditions of distribution and use, see copyright notice in zlib.h
 */

 /*
  *  ALGORITHM
  *
  *      The "deflation" process depends on being able to identify portions
  *      of the input text which are identical to earlier input (within a
  *      sliding window trailing behind the input currently being processed).
  *
  *      The most straightforward technique turns out to be the fastest for
  *      most input files: try all possible matches and select the longest.
  *      The key feature of this algorithm is that insertions into the string
  *      dictionary are very simple and thus fast, and deletions are avoided
  *      completely. Insertions are performed at each input character, whereas
  *      string matches are performed only when the previous match ends. So it
  *      is preferable to spend more time in matches to allow very fast string
  *      insertions and avoid deletions. The matching algorithm for small
  *      strings is inspired from that of Rabin & Karp. A brute force approach
  *      is used to find longer strings when a small match has been found.
  *      A similar algorithm is used in comic (by Jan-Mark Wams) and freeze
  *      (by Leonid Broukhis).
  *         A previous version of this file used a more sophisticated algorithm
  *      (by Fiala and Greene) which is guaranteed to run in linear amortized
  *      time, but has a larger average cost, uses more memory and is patented.
  *      However the F&G algorithm may be faster for some highly redundant
  *      files if the parameter max_chain_length (described below) is too large.
  *
  *  ACKNOWLEDGEMENTS
  *
  *      The idea of lazy evaluation of matches is due to Jan-Mark Wams, and
  *      I found it in 'freeze' written by Leonid Broukhis.
  *      Thanks to many people for bug reports and testing.
  *
  *  REFERENCES
  *
  *      Deutsch, L.P.,"DEFLATE Compressed Data Format Specification".
  *      Available in ftp://ds.internic.net/rfc/rfc1951.txt
  *
  *      A description of the Rabin and Karp algorithm is given in the book
  *         "Algorithms" by R. Sedgewick, Addison-Wesley, p252.
  *
  *      Fiala,E.R., and Greene,D.H.
  *         Data Compression with Finite Windows, Comm.ACM, 32,4 (1989) 490-595
  *
  */

#include "deflate.h"

const char deflate_copyright[] =
" deflate 1.1.3 Copyright 1995-1998 Jean-loup Gailly ";
/*
  If you use the zlib library in a product, an acknowledgment is welcome
  in the documentation of your product. If for some reason you cannot
  include such an acknowledgment, I would appreciate that you keep this
  copyright string in the executable of your product.
 */

 /*  ===========================================================================
  *  Function prototypes.
  */
typedef enum {
    need_more,      /*  block not completed, need more input or more output */
    block_done,     /*  block flush performed */
    finish_started, /*  finish started, need only more output at next deflate */
    finish_done     /*  finish done, accept no more input or output */
} block_state;

typedef block_state(*compress_func) OF((deflate_state* s, int flush));
/*  Compression function. Returns the block state after the call. */

local void fill_window    OF((deflate_state* s));
local block_state deflate_stored OF((deflate_state* s, int flush));
local block_state deflate_fast   OF((deflate_state* s, int flush));
local block_state deflate_slow   OF((deflate_state* s, int flush));
local void lm_init        OF((deflate_state* s));
local void putShortMSB    OF((deflate_state* s, uInt b));
local void flush_pending  OF((z_streamp strm));
local int read_buf        OF((z_streamp strm, Bytef* buf, unsigned size));
#ifdef ASMV
void match_init OF((void)); /*  asm code initialization */
uInt longest_match  OF((deflate_state* s, IPos cur_match));
#else
local uInt longest_match  OF((deflate_state* s, IPos cur_match));
#endif

#ifdef DEBUG
local  void check_match OF((deflate_state* s, IPos start, IPos match,
    int length));
#endif

/*  ===========================================================================
 *  Local data
 */

#define NIL 0
 /*  Tail of hash chains */

#ifndef TOO_FAR
#  define TOO_FAR 4096
#endif
/*  Matches of length 3 are discarded if their distance exceeds TOO_FAR */

#define MIN_LOOKAHEAD (MAX_MATCH+MIN_MATCH+1)
/*  Minimum amount of lookahead, except at the end of the input file.
 *  See deflate.c for comments about the MIN_MATCH+1.
 */

 /*  Values for max_lazy_match, good_match and max_chain_length, depending on
  *  the desired pack level (0..9). The values given below have been tuned to
  *  exclude worst case performance for pathological files. Better values may be
  *  found for specific files.
  */
typedef struct config_s {
    ush good_length; /*  reduce lazy search above this match length */
    ush max_lazy;    /*  do not perform lazy search above this match length */
    ush nice_length; /*  quit search above this match length */
    ush max_chain;
    compress_func func;
} config;

local const config configuration_table[10] = {
    /*      good lazy nice chain */
    /*  0 */ {0,    0,  0,    0, deflate_stored},  /*  store only */
    /*  1 */ {4,    4,  8,    4, deflate_fast}, /*  maximum speed, no lazy matches */
    /*  2 */ {4,    5, 16,    8, deflate_fast},
    /*  3 */ {4,    6, 32,   32, deflate_fast},

    /*  4 */ {4,    4, 16,   16, deflate_slow},  /*  lazy matches */
    /*  5 */ {8,   16, 32,   32, deflate_slow},
    /*  6 */ {8,   16, 128, 128, deflate_slow},
    /*  7 */ {8,   32, 128, 256, deflate_slow},
    /*  8 */ {32, 128, 258, 1024, deflate_slow},
    /*  9 */ {32, 258, 258, 4096, deflate_slow} }; /*  maximum compression */

    /*  Note: the deflate() code requires max_lazy >= MIN_MATCH and max_chain >= 4
     *  For deflate_fast() (levels <= 3) good is ignored and lazy has a different
     *  meaning.
     */

#define EQUAL 0
     /*  result of memcmp for equal strings */

     //struct static_tree_desc_s {int dummy;}; /*  for buggy compilers */

     /*  ===========================================================================
      *  Update a hash value with the given input byte
      *  IN  assertion: all calls to to UPDATE_HASH are made with consecutive
      *    input characters, so that a running hash key can be computed from the
      *    previous key instead of complete recalculation each time.
      */
#define UPDATE_HASH(s,h,c) (h = (((h)<<s->hash_shift) ^ (c)) & s->hash_mask)


      /*  ===========================================================================
       *  Insert string str in the dictionary and set match_head to the previous head
       *  of the hash chain (the most recent string with same hash key). Return
       *  the previous length of the hash chain.
       *  If this file is compiled with -DFASTEST, the compression level is forced
       *  to 1, and no hash chains are maintained.
       *  IN  assertion: all calls to to INSERT_STRING are made with consecutive
       *    input characters and the first MIN_MATCH bytes of str are valid
       *    (except for the last MIN_MATCH-1 bytes of the input file).
       */
#ifdef FASTEST
#define INSERT_STRING(s, str, match_head) \
   (UPDATE_HASH(s, s->ins_h, s->window[(str) + (MIN_MATCH-1)]), \
    match_head = s->head[s->ins_h], \
    s->head[s->ins_h] = (Pos)(str))
#else
#define INSERT_STRING(s, str, match_head) \
   (UPDATE_HASH(s, s->ins_h, s->window[(str) + (MIN_MATCH-1)]), \
    match_head = s->head[s->ins_h], \
    s->prev[(str) & s->w_mask] = s->head[s->ins_h], \
    s->head[s->ins_h] = (Pos)(str))
#endif

       /*  ===========================================================================
        *  Initialize the hash table (avoiding 64K overflow for 16 bit systems).
        *  prev[] will be initialized on the fly.
        */
#define CLEAR_HASH(s) \
    s->head[s->hash_size-1] = NIL; \
    zmemzero((Bytef *)s->head, (unsigned)(s->hash_size-1)*sizeof(*s->head));

        /*  ========================================================================= */
int ZEXPORT deflateInit_(z_streamp strm, int level, const char* version, int stream_size)
{
    return deflateInit2_(strm, level, Z_DEFLATED, MAX_WBITS, DEF_MEM_LEVEL,
        Z_DEFAULT_STRATEGY, version, stream_size);
    /*  To do: ignore strm->next_in if we use it as window */
}

/*  ========================================================================= */
int ZEXPORT deflateInit2_(z_streamp strm, int level, int method, int windowBits, int memLevel, int strategy, const char* version, int stream_size)
{
    deflate_state* s;
    int noheader = 0;
    static const char* my_version = ZLIB_VERSION;

    ushf* overlay;
    /*  We overlay pending_buf and d_buf+l_buf. This works since the average
     *  output size for (length,distance) codes is <= 24 bits.
     */

    if (version == Z_NULL || version[0] != my_version[0] ||
        stream_size != sizeof(z_stream)) {
        return Z_VERSION_ERROR;
    }
    if (strm == Z_NULL) return Z_STREAM_ERROR;

    strm->msg = Z_NULL;
    if (strm->zalloc == Z_NULL) {
        strm->zalloc = zcalloc;
        strm->opaque = (voidpf)0;
    }
    if (strm->zfree == Z_NULL) strm->zfree = zcfree;

    if (level == Z_DEFAULT_COMPRESSION) level = 6;
#ifdef FASTEST
    level = 1;
#endif

    if (windowBits < 0) { /*  undocumented feature: suppress zlib header */
        noheader = 1;
        windowBits = -windowBits;
    }
    if (memLevel < 1 || memLevel > MAX_MEM_LEVEL || method != Z_DEFLATED ||
        windowBits < 8 || windowBits > 15 || level < 0 || level > 9 ||
        strategy < 0 || strategy > Z_HUFFMAN_ONLY) {
        return Z_STREAM_ERROR;
    }
    s = (deflate_state*)ZALLOC(strm, 1, sizeof(deflate_state));
    if (s == Z_NULL) return Z_MEM_ERROR;
    strm->state = (struct internal_state FAR*)s;
    s->strm = strm;

    s->noheader = noheader;
    s->w_bits = windowBits;
    s->w_size = 1 << s->w_bits;
    s->w_mask = s->w_size - 1;

    s->hash_bits = memLevel + 7;
    s->hash_size = 1 << s->hash_bits;
    s->hash_mask = s->hash_size - 1;
    s->hash_shift = ((s->hash_bits + MIN_MATCH - 1) / MIN_MATCH);

    s->window = (Bytef*)ZALLOC(strm, s->w_size, 2 * sizeof(Byte));
    s->prev = (Posf*)ZALLOC(strm, s->w_size, sizeof(Pos));
    s->head = (Posf*)ZALLOC(strm, s->hash_size, sizeof(Pos));

    s->lit_bufsize = 1 << (memLevel + 6); /*  16K elements by default */

    overlay = (ushf*)ZALLOC(strm, s->lit_bufsize, sizeof(ush) + 2);
    s->pending_buf = (uchf*)overlay;
    s->pending_buf_size = (ulg)s->lit_bufsize * (sizeof(ush) + 2L);

    if (s->window == Z_NULL || s->prev == Z_NULL || s->head == Z_NULL ||
        s->pending_buf == Z_NULL) {
        strm->msg = (char*)ERR_MSG(Z_MEM_ERROR);
        deflateEnd(strm);
        return Z_MEM_ERROR;
    }
    s->d_buf = overlay + s->lit_bufsize / sizeof(ush);
    s->l_buf = s->pending_buf + (1 + sizeof(ush)) * s->lit_bufsize;

    s->level = level;
    s->strategy = strategy;
    s->method = (Byte)method;

    return deflateReset(strm);
}

/*  ========================================================================= */
int ZEXPORT deflateSetDictionary(z_streamp strm, const Bytef* dictionary, uInt dictLength)
{
    deflate_state* s;
    uInt length = dictLength;
    uInt n;
    IPos hash_head = 0;

    if (strm == Z_NULL || strm->state == Z_NULL || dictionary == Z_NULL ||
        strm->state->status != INIT_STATE) return Z_STREAM_ERROR;

    s = strm->state;
    //    strm->adler = adler32(strm->adler, dictionary, dictLength);
    strm->adler = CRC32Adler(strm->adler, dictionary, dictLength);

    if (length < MIN_MATCH) return Z_OK;
    if (length > MAX_DIST(s)) {
        length = MAX_DIST(s);
#ifndef USE_DICT_HEAD
        dictionary += dictLength - length; /*  use the tail of the dictionary */
#endif
    }
    zmemcpy(s->window, dictionary, length);
    s->strstart = length;
    s->block_start = (long)length;

    /*  Insert all strings in the hash table (except for the last two bytes).
     * s->lookahead stays null, so s->ins_h will be recomputed at the next
     * call of fill_window.
     */
    s->ins_h = s->window[0];
    UPDATE_HASH(s, s->ins_h, s->window[1]);
    for (n = 0; n <= length - MIN_MATCH; n++) {
        INSERT_STRING(s, n, hash_head);
    }
    if (hash_head) hash_head = 0;  /*  to make compiler happy */
    return Z_OK;
}

/*  ========================================================================= */
int ZEXPORT deflateReset(z_streamp strm)
{
    deflate_state* s;

    if (strm == Z_NULL || strm->state == Z_NULL ||
        strm->zalloc == Z_NULL || strm->zfree == Z_NULL) return Z_STREAM_ERROR;

    strm->total_in = strm->total_out = 0;
    strm->msg = Z_NULL; /*  use zfree if we ever allocate msg dynamically */
    strm->data_type = Z_UNKNOWN;

    s = (deflate_state*)strm->state;
    s->pending = 0;
    s->pending_out = s->pending_buf;

    if (s->noheader < 0) {
        s->noheader = 0; /*  was set to -1 by deflate(..., Z_FINISH); */
    }
    s->status = s->noheader ? BUSY_STATE : INIT_STATE;
    strm->adler = 1;
    s->last_flush = Z_NO_FLUSH;

    _tr_init(s);
    lm_init(s);

    return Z_OK;
}

/*  ========================================================================= */
int ZEXPORT deflateParams(z_streamp strm, int level, int strategy)
{
    deflate_state* s;
    compress_func func;
    int err = Z_OK;

    if (strm == Z_NULL || strm->state == Z_NULL) return Z_STREAM_ERROR;
    s = strm->state;

    if (level == Z_DEFAULT_COMPRESSION) {
        level = 6;
    }
    if (level < 0 || level > 9 || strategy < 0 || strategy > Z_HUFFMAN_ONLY) {
        return Z_STREAM_ERROR;
    }
    func = configuration_table[s->level].func;

    if (func != configuration_table[level].func && strm->total_in != 0) {
        /*  Flush the last buffer: */
        err = deflate(strm, Z_PARTIAL_FLUSH);
    }
    if (s->level != level) {
        s->level = level;
        s->max_lazy_match = configuration_table[level].max_lazy;
        s->good_match = configuration_table[level].good_length;
        s->nice_match = configuration_table[level].nice_length;
        s->max_chain_length = configuration_table[level].max_chain;
    }
    s->strategy = strategy;
    return err;
}

/*  =========================================================================
 *  Put a short in the pending buffer. The 16-bit value is put in MSB order.
 *  IN assertion: the stream state is correct and there is enough room in
 *  pending_buf.
 */
local void putShortMSB(deflate_state* s, uInt b)
{
    put_byte(s, (Byte)(b >> 8));
    put_byte(s, (Byte)(b & 0xff));
}

/*  =========================================================================
 *  Flush as much pending output as possible. All deflate() output goes
 *  through this function so some applications may wish to modify it
 *  to avoid allocating a large strm->next_out buffer and copying into it.
 *  (See also read_buf()).
 */
local void flush_pending(z_streamp strm)
{
    unsigned len = strm->state->pending;

    if (len > strm->avail_out) len = strm->avail_out;
    if (len == 0) return;

    zmemcpy(strm->next_out, strm->state->pending_out, len);
    strm->next_out += len;
    strm->state->pending_out += len;
    strm->total_out += len;
    strm->avail_out -= len;
    strm->state->pending -= len;
    if (strm->state->pending == 0) {
        strm->state->pending_out = strm->state->pending_buf;
    }
}

/*  ========================================================================= */
int ZEXPORT deflate(z_streamp strm, int flush)
{
    int old_flush; /*  value of flush param for previous deflate call */
    deflate_state* s;

    if (strm == Z_NULL || strm->state == Z_NULL ||
        flush > Z_FINISH || flush < 0) {
        return Z_STREAM_ERROR;
    }
    s = strm->state;

    if (strm->next_out == Z_NULL ||
        (strm->next_in == Z_NULL && strm->avail_in != 0) ||
        (s->status == FINISH_STATE && flush != Z_FINISH)) {
        ERR_RETURN(strm, Z_STREAM_ERROR);
    }
    if (strm->avail_out == 0) ERR_RETURN(strm, Z_BUF_ERROR);

    s->strm = strm; /*  just in case */
    old_flush = s->last_flush;
    s->last_flush = flush;

    /*  Write the zlib header */
    if (s->status == INIT_STATE) {

        uInt header = (Z_DEFLATED + ((s->w_bits - 8) << 4)) << 8;
        uInt level_flags = (s->level - 1) >> 1;

        if (level_flags > 3) level_flags = 3;
        header |= (level_flags << 6);
        if (s->strstart != 0) header |= PRESET_DICT;
        header += 31 - (header % 31);

        s->status = BUSY_STATE;
        putShortMSB(s, header);

        /*  Save the adler32 of the preset dictionary: */
        if (s->strstart != 0) {
            putShortMSB(s, (uInt)(strm->adler >> 16));
            putShortMSB(s, (uInt)(strm->adler & 0xffff));
        }
        strm->adler = 1L;
    }

    /*  Flush as much pending output as possible */
    if (s->pending != 0) {
        flush_pending(strm);
        if (strm->avail_out == 0) {
            /*  Since avail_out is 0, deflate will be called again with
             * more output space, but possibly with both pending and
             * avail_in equal to zero. There won't be anything to do,
             * but this is not an error situation so make sure we
             * return OK instead of BUF_ERROR at next call of deflate:
                 */
            s->last_flush = -1;
            return Z_OK;
        }

        /*  Make sure there is something to do and avoid duplicate consecutive
         *  flushes. For repeated and useless calls with Z_FINISH, we keep
         *  returning Z_STREAM_END instead of Z_BUFF_ERROR.
         */
    } else if (strm->avail_in == 0 && flush <= old_flush &&
        flush != Z_FINISH) {
        ERR_RETURN(strm, Z_BUF_ERROR);
    }

    /*  User must not provide more input after the first FINISH: */
    if (s->status == FINISH_STATE && strm->avail_in != 0) {
        ERR_RETURN(strm, Z_BUF_ERROR);
    }

    /*  Start a new block or continue the current one.
     */
    if (strm->avail_in != 0 || s->lookahead != 0 ||
        (flush != Z_NO_FLUSH && s->status != FINISH_STATE)) {
        block_state bstate;

        bstate = (*(configuration_table[s->level].func))(s, flush);

        if (bstate == finish_started || bstate == finish_done) {
            s->status = FINISH_STATE;
        }
        if (bstate == need_more || bstate == finish_started) {
            if (strm->avail_out == 0) {
                s->last_flush = -1; /*  avoid BUF_ERROR next call, see above */
            }
            return Z_OK;
            /*  If flush != Z_NO_FLUSH && avail_out == 0, the next call
             *  of deflate should use the same flush parameter to make sure
             *  that the flush is complete. So we don't have to output an
             *  empty block here, this will be done at next call. This also
             *  ensures that for a very small output buffer, we emit at most
             *  one empty block.
             */
        }
        if (bstate == block_done) {
            if (flush == Z_PARTIAL_FLUSH) {
                _tr_align(s);
            } else { /*  FULL_FLUSH or SYNC_FLUSH */
                _tr_stored_block(s, (char*)0, 0L, 0);
                /*  For a full flush, this empty block will be recognized
                 * as a special marker by inflate_sync().
                 */
                if (flush == Z_FULL_FLUSH) {
                    CLEAR_HASH(s);             /*  forget history */
                }
            }
            flush_pending(strm);
            if (strm->avail_out == 0) {
                s->last_flush = -1; /*  avoid BUF_ERROR at next call, see above */
                return Z_OK;
            }
        }
    }
    Assert(strm->avail_out > 0, "bug2");

    if (flush != Z_FINISH) return Z_OK;
    if (s->noheader) return Z_STREAM_END;

    /*  Write the zlib trailer (adler32) */
    putShortMSB(s, (uInt)(strm->adler >> 16));
    putShortMSB(s, (uInt)(strm->adler & 0xffff));
    flush_pending(strm);
    /*  If avail_out is zero, the application will call deflate again
     * to flush the rest.
     */
    s->noheader = -1; /*  write the trailer only once! */
    return s->pending != 0 ? Z_OK : Z_STREAM_END;
}

/*  ========================================================================= */
int ZEXPORT deflateEnd(z_streamp strm)
{
    int status;

    if (strm == Z_NULL || strm->state == Z_NULL) return Z_STREAM_ERROR;

    status = strm->state->status;
    if (status != INIT_STATE && status != BUSY_STATE &&
        status != FINISH_STATE) {
        return Z_STREAM_ERROR;
    }

    /*  Deallocate in reverse order of allocations: */
    TRY_FREE(strm, strm->state->pending_buf);
    TRY_FREE(strm, strm->state->head);
    TRY_FREE(strm, strm->state->prev);
    TRY_FREE(strm, strm->state->window);

    ZFREE(strm, strm->state);
    strm->state = Z_NULL;

    return status == BUSY_STATE ? Z_DATA_ERROR : Z_OK;
}

/*  =========================================================================
 *  Copy the source state to the destination state.
 *  To simplify the source, this is not supported for 16-bit MSDOS (which
 *  doesn't have enough memory anyway to duplicate compression states).
 */
int ZEXPORT deflateCopy(z_streamp dest, z_streamp source)
{
#ifdef MAXSEG_64K
    return Z_STREAM_ERROR;
#else
    deflate_state* ds;
    deflate_state* ss;
    ushf* overlay;


    if (source == Z_NULL || dest == Z_NULL || source->state == Z_NULL) {
        return Z_STREAM_ERROR;
    }

    ss = source->state;

    *dest = *source;

    ds = (deflate_state*)ZALLOC(dest, 1, sizeof(deflate_state));
    if (ds == Z_NULL) return Z_MEM_ERROR;
    dest->state = (struct internal_state FAR*) ds;
    *ds = *ss;
    ds->strm = dest;

    ds->window = (Bytef*)ZALLOC(dest, ds->w_size, 2 * sizeof(Byte));
    ds->prev = (Posf*)ZALLOC(dest, ds->w_size, sizeof(Pos));
    ds->head = (Posf*)ZALLOC(dest, ds->hash_size, sizeof(Pos));
    overlay = (ushf*)ZALLOC(dest, ds->lit_bufsize, sizeof(ush) + 2);
    ds->pending_buf = (uchf*)overlay;

    if (ds->window == Z_NULL || ds->prev == Z_NULL || ds->head == Z_NULL ||
        ds->pending_buf == Z_NULL) {
        deflateEnd(dest);
        return Z_MEM_ERROR;
    }
    /*  following zmemcpy do not work for 16-bit MSDOS */
    zmemcpy(ds->window, ss->window, ds->w_size * 2 * sizeof(Byte));
    zmemcpy(ds->prev, ss->prev, ds->w_size * sizeof(Pos));
    zmemcpy(ds->head, ss->head, ds->hash_size * sizeof(Pos));
    zmemcpy(ds->pending_buf, ss->pending_buf, (uInt)ds->pending_buf_size);

    ds->pending_out = ds->pending_buf + (ss->pending_out - ss->pending_buf);
    ds->d_buf = overlay + ds->lit_bufsize / sizeof(ush);
    ds->l_buf = ds->pending_buf + (1 + sizeof(ush)) * ds->lit_bufsize;

    ds->l_desc.dyn_tree = ds->dyn_ltree;
    ds->d_desc.dyn_tree = ds->dyn_dtree;
    ds->bl_desc.dyn_tree = ds->bl_tree;

    return Z_OK;
#endif
}

/*  ===========================================================================
 * Read a new buffer from the current input stream, update the adler32
 * and total number of bytes read.  All deflate() input goes through
 * this function so some applications may wish to modify it to avoid
 * allocating a large strm->next_in buffer and copying from it.
 * (See also flush_pending()).
 */
local int read_buf(z_streamp strm, Bytef* buf, unsigned size)
{
    unsigned len = strm->avail_in;

    if (len > size) len = size;
    if (len == 0) return 0;

    strm->avail_in -= len;

    if (!strm->state->noheader) {
        //        strm->adler = adler32(strm->adler, strm->next_in, len);
        strm->adler = CRC32Adler(strm->adler, strm->next_in, len);
    }
    zmemcpy(buf, strm->next_in, len);
    strm->next_in += len;
    strm->total_in += len;

    return (int)len;
}

/*  ===========================================================================
 *  Initialize the "longest match" routines for a new zlib stream
 */
local void lm_init(deflate_state* s)
{
    s->window_size = (ulg)2L * s->w_size;

    CLEAR_HASH(s);

    /*  Set the default configuration parameters:
     */
    s->max_lazy_match = configuration_table[s->level].max_lazy;
    s->good_match = configuration_table[s->level].good_length;
    s->nice_match = configuration_table[s->level].nice_length;
    s->max_chain_length = configuration_table[s->level].max_chain;

    s->strstart = 0;
    s->block_start = 0L;
    s->lookahead = 0;
    s->match_length = s->prev_length = MIN_MATCH - 1;
    s->match_available = 0;
    s->ins_h = 0;
#ifdef ASMV
    match_init(); /*  initialize the asm code */
#endif
}

/*  ===========================================================================
 *  Set match_start to the longest match starting at the given string and
 *  return its length. Matches shorter or equal to prev_length are discarded,
 *  in which case the result is equal to prev_length and match_start is
 *  garbage.
 *  IN assertions: cur_match is the head of the hash chain for the current
 *    string (strstart) and its distance is <= MAX_DIST, and prev_length >= 1
 *  OUT assertion: the match length is not greater than s->lookahead.
 */
#ifndef ASMV
 /*  For 80x86 and 680x0, an optimized version will be provided in match.asm or
  *  match.S. The code will be functionally equivalent.
  */
#ifndef FASTEST
local uInt longest_match(deflate_state* s, IPos cur_match)
{
    unsigned chain_length = s->max_chain_length;/*  max hash chain length */
    register Bytef* scan = s->window + s->strstart; /*  current string */
    register Bytef* match;                       /*  matched string */
    register int len;                           /*  length of current match */
    int best_len = s->prev_length;              /*  best match length so far */
    int nice_match = s->nice_match;             /*  stop if match long enough */
    IPos limit = s->strstart > (IPos)MAX_DIST(s) ?
        s->strstart - (IPos)MAX_DIST(s) : NIL;
    /*  Stop when cur_match becomes <= limit. To simplify the code,
     *  we prevent matches with the string of window index 0.
     */
    Posf* prev = s->prev;
    uInt wmask = s->w_mask;

#ifdef UNALIGNED_OK
    /*  Compare two bytes at a time. Note: this is not always beneficial.
     *  Try with and without -DUNALIGNED_OK to check.
     */
    register Bytef* strend = s->window + s->strstart + MAX_MATCH - 1;
    register ush scan_start = *(ushf*)scan;
    register ush scan_end = *(ushf*)(scan + best_len - 1);
#else
    register Bytef* strend = s->window + s->strstart + MAX_MATCH;
    register Byte scan_end1 = scan[best_len - 1];
    register Byte scan_end = scan[best_len];
#endif

    /*  The code is optimized for HASH_BITS >= 8 and MAX_MATCH-2 multiple of 16.
     *  It is easy to get rid of this optimization if necessary.
     */
    Assert(s->hash_bits >= 8 && MAX_MATCH == 258, "Code too clever");

    /*  Do not waste too much time if we already have a good match: */
    if (s->prev_length >= s->good_match) {
        chain_length >>= 2;
    }
    /*  Do not look for matches beyond the end of the input. This is necessary
     *  to make deflate deterministic.
     */
    if ((uInt)nice_match > s->lookahead) nice_match = s->lookahead;

    Assert((ulg)s->strstart <= s->window_size - MIN_LOOKAHEAD, "need lookahead");

    do {
        Assert(cur_match < s->strstart, "no future");
        match = s->window + cur_match;

        /*  Skip to next match if the match length cannot increase
         *  or if the match length is less than 2:
         */
#if (defined(UNALIGNED_OK) && MAX_MATCH == 258)
         /*  This code assumes sizeof(unsigned short) == 2. Do not use
          *  UNALIGNED_OK if your compiler uses a different size.
          */
        if (*(ushf*)(match + best_len - 1) != scan_end ||
            *(ushf*)match != scan_start) continue;

        /*  It is not necessary to compare scan[2] and match[2] since they are
         *  always equal when the other bytes match, given that the hash keys
         *  are equal and that HASH_BITS >= 8. Compare 2 bytes at a time at
         *  strstart+3, +5, ... up to strstart+257. We check for insufficient
         *  lookahead only every 4th comparison; the 128th check will be made
         *  at strstart+257. If MAX_MATCH-2 is not a multiple of 8, it is
         *  necessary to put more guard bytes at the end of the window, or
         *  to check more often for insufficient lookahead.
         */
        Assert(scan[2] == match[2], "scan[2]?");
        scan++, match++;
        do {
        } while (*(ushf*)(scan += 2) == *(ushf*)(match += 2) &&
            *(ushf*)(scan += 2) == *(ushf*)(match += 2) &&
            *(ushf*)(scan += 2) == *(ushf*)(match += 2) &&
            *(ushf*)(scan += 2) == *(ushf*)(match += 2) &&
            scan < strend);
        /*  The funny "do {}" generates better code on most compilers */

        /*  Here, scan <= window+strstart+257 */
        Assert(scan <= s->window + (unsigned)(s->window_size - 1), "wild scan");
        if (*scan == *match) scan++;

        len = (MAX_MATCH - 1) - (int)(strend - scan);
        scan = strend - (MAX_MATCH - 1);

#else /*  UNALIGNED_OK */

        if (match[best_len] != scan_end ||
            match[best_len - 1] != scan_end1 ||
            *match != *scan ||
            *++match != scan[1])      continue;

        /*  The check at best_len-1 can be removed because it will be made
         *  again later. (This heuristic is not always a win.)
         *  It is not necessary to compare scan[2] and match[2] since they
         *  are always equal when the other bytes match, given that
         *  the hash keys are equal and that HASH_BITS >= 8.
         */
        scan += 2, match++;
        Assert(*scan == *match, "match[2]?");

        /*  We check for insufficient lookahead only every 8th comparison;
         *  the 256th check will be made at strstart+258.
         */
        do {
        } while (*++scan == *++match && *++scan == *++match &&
            *++scan == *++match && *++scan == *++match &&
            *++scan == *++match && *++scan == *++match &&
            *++scan == *++match && *++scan == *++match &&
            scan < strend);

        Assert(scan <= s->window + (unsigned)(s->window_size - 1), "wild scan");

        len = MAX_MATCH - (int)(strend - scan);
        scan = strend - MAX_MATCH;

#endif /*  UNALIGNED_OK */

        if (len > best_len) {
            s->match_start = cur_match;
            best_len = len;
            if (len >= nice_match) break;
#ifdef UNALIGNED_OK
            scan_end = *(ushf*)(scan + best_len - 1);
#else
            scan_end1 = scan[best_len - 1];
            scan_end = scan[best_len];
#endif
        }
    } while ((cur_match = prev[cur_match & wmask]) > limit
        && --chain_length != 0);

    if ((uInt)best_len <= s->lookahead) return (uInt)best_len;
    return s->lookahead;
}

#else /*  FASTEST */
  /*  ---------------------------------------------------------------------------
   *  Optimized version for level == 1 only
   */
local uInt longest_match(s, cur_match)
deflate_state* s;
IPos cur_match;                             /*  current match */
{
    register Bytef* scan = s->window + s->strstart; /*  current string */
    register Bytef* match;                       /*  matched string */
    register int len;                           /*  length of current match */
    register Bytef* strend = s->window + s->strstart + MAX_MATCH;

    /*  The code is optimized for HASH_BITS >= 8 and MAX_MATCH-2 multiple of 16.
     *  It is easy to get rid of this optimization if necessary.
     */
    Assert(s->hash_bits >= 8 && MAX_MATCH == 258, "Code too clever");

    Assert((ulg)s->strstart <= s->window_size - MIN_LOOKAHEAD, "need lookahead");

    Assert(cur_match < s->strstart, "no future");

    match = s->window + cur_match;

    /*  Return failure if the match length is less than 2:
     */
    if (match[0] != scan[0] || match[1] != scan[1]) return MIN_MATCH - 1;

    /*  The check at best_len-1 can be removed because it will be made
     *  again later. (This heuristic is not always a win.)
     *  It is not necessary to compare scan[2] and match[2] since they
     *  are always equal when the other bytes match, given that
     *  the hash keys are equal and that HASH_BITS >= 8.
     */
    scan += 2, match += 2;
    Assert(*scan == *match, "match[2]?");

    /*  We check for insufficient lookahead only every 8th comparison;
     *  the 256th check will be made at strstart+258.
     */
    do {
    } while (*++scan == *++match && *++scan == *++match &&
        *++scan == *++match && *++scan == *++match &&
        *++scan == *++match && *++scan == *++match &&
        *++scan == *++match && *++scan == *++match &&
        scan < strend);

    Assert(scan <= s->window + (unsigned)(s->window_size - 1), "wild scan");

    len = MAX_MATCH - (int)(strend - scan);

    if (len < MIN_MATCH) return MIN_MATCH - 1;

    s->match_start = cur_match;
    return len <= s->lookahead ? len : s->lookahead;
}
#endif /*  FASTEST */
#endif /*  ASMV */

#ifdef DEBUG
/*  ===========================================================================
 *  Check that the match at match_start is indeed a match.
 */
local void check_match(deflate_state* s, IPos start, IPos match, int length)
{
    /*  check that the match is indeed a match */
    if (zmemcmp(s->window + match,
        s->window + start, length) != EQUAL) {
        fprintf(stderr, " start %u, match %u, length %d\n",
            start, match, length);
        do {
            fprintf(stderr, "%c%c", s->window[match++], s->window[start++]);
        } while (--length != 0);
        z_error("invalid match");
    }
    if (z_verbose > 1) {
        fprintf(stderr, "\\[%d,%d]", start - match, length);
        do { putc(s->window[start++], stderr); } while (--length != 0);
    }
}
#else
#  define check_match(s, start, match, length)
#endif

/*  ===========================================================================
 *  Fill the window when the lookahead becomes insufficient.
 *  Updates strstart and lookahead.
 *
 *  IN assertion: lookahead < MIN_LOOKAHEAD
 *  OUT assertions: strstart <= window_size-MIN_LOOKAHEAD
 *    At least one byte has been read, or avail_in == 0; reads are
 *    performed for at least two bytes (required for the zip translate_eol
 *    option -- not supported here).
 */
local void fill_window(deflate_state* s)
{
    register unsigned n, m;
    register Posf* p;
    unsigned more;    /*  Amount of free space at the end of the window. */
    uInt wsize = s->w_size;

    do {
        more = (unsigned)(s->window_size - (ulg)s->lookahead - (ulg)s->strstart);

        /*  Deal with !@#$% 64K limit: */
        if (more == 0 && s->strstart == 0 && s->lookahead == 0) {
            more = wsize;

        } else if (more == (unsigned)(-1)) {
            /*  Very unlikely, but possible on 16 bit machine if strstart == 0
             *  and lookahead == 1 (input done one byte at time)
             */
            more--;

            /*  If the window is almost full and there is insufficient lookahead,
             *  move the upper half to the lower one to make room in the upper half.
             */
        } else if (s->strstart >= wsize + MAX_DIST(s)) {

            zmemcpy(s->window, s->window + wsize, (unsigned)wsize);
            s->match_start -= wsize;
            s->strstart -= wsize; /*  we now have strstart >= MAX_DIST */
            s->block_start -= (long)wsize;

            /*  Slide the hash table (could be avoided with 32 bit values
                at the expense of memory usage). We slide even when level == 0
                to keep the hash table consistent if we switch back to level > 0
                later. (Using level 0 permanently is not an optimal usage of
                zlib, so we don't care about this pathological case.)
             */
            n = s->hash_size;
            p = &s->head[n];
            do {
                m = *--p;
                *p = (Pos)(m >= wsize ? m - wsize : NIL);
            } while (--n);

            n = wsize;
#ifndef FASTEST
            p = &s->prev[n];
            do {
                m = *--p;
                *p = (Pos)(m >= wsize ? m - wsize : NIL);
                /*  If n is not on any hash chain, prev[n] is garbage but
                 * its value will never be used.
                 */
            } while (--n);
#endif
            more += wsize;
        }
        if (s->strm->avail_in == 0) return;

        /*  If there was no sliding:
         *    strstart <= WSIZE+MAX_DIST-1 && lookahead <= MIN_LOOKAHEAD - 1 &&
         *    more == window_size - lookahead - strstart
         *  => more >= window_size - (MIN_LOOKAHEAD-1 + WSIZE + MAX_DIST-1)
         *  => more >= window_size - 2*WSIZE + 2
         *  In the BIG_MEM or MMAP case (not yet supported),
         *   window_size == input_size + MIN_LOOKAHEAD  &&
         *   strstart + s->lookahead <= input_size => more >= MIN_LOOKAHEAD.
         *  Otherwise, window_size == 2*WSIZE so more >= 2.
         *  If there was sliding, more >= WSIZE. So in all cases, more >= 2.
         */
        Assert(more >= 2, "more < 2");

        n = read_buf(s->strm, s->window + s->strstart + s->lookahead, more);
        s->lookahead += n;

        /*  Initialize the hash value now that we have some input: */
        if (s->lookahead >= MIN_MATCH) {
            s->ins_h = s->window[s->strstart];
            UPDATE_HASH(s, s->ins_h, s->window[s->strstart + 1]);
#if MIN_MATCH != 3
            Call UPDATE_HASH() MIN_MATCH - 3 more times
#endif
        }
        /*  If the whole input has less than MIN_MATCH bytes, ins_h is garbage,
         *  but this is not important since only literal bytes will be emitted.
         */

    } while (s->lookahead < MIN_LOOKAHEAD && s->strm->avail_in != 0);
}

/*  ===========================================================================
 *  Flush the current block, with given end-of-file flag.
 *  IN assertion: strstart is set to the end of the current match.
 */
#define FLUSH_BLOCK_ONLY(s, eof) { \
   _tr_flush_block(s, (s->block_start >= 0L ? \
                   (charf *)&s->window[(unsigned)s->block_start] : \
                   (charf *)Z_NULL), \
        (ulg)((long)s->strstart - s->block_start), \
        (eof)); \
   s->block_start = s->strstart; \
   flush_pending(s->strm); \
   Tracev((stderr,"[FLUSH]")); \
}

 /*  Same but force premature exit if necessary. */
#define FLUSH_BLOCK(s, eof) { \
   FLUSH_BLOCK_ONLY(s, eof); \
   if (s->strm->avail_out == 0) return (eof) ? finish_started : need_more; \
}

/*  ===========================================================================
 *  Copy without compression as much as possible from the input stream, return
 *  the current block state.
 *  This function does not insert new strings in the dictionary since
 *  uncompressible data is probably not useful. This function is used
 *  only for the level=0 compression option.
 *  NOTE: this function should be optimized to avoid extra copying from
 *  window to pending_buf.
 */
local block_state deflate_stored(deflate_state* s, int flush)
{
    /*  Stored blocks are limited to 0xffff bytes, pending_buf is limited
     *  to pending_buf_size, and each stored block has a 5 byte header:
     */
    ulg max_block_size = 0xffff;
    ulg max_start;

    if (max_block_size > s->pending_buf_size - 5) {
        max_block_size = s->pending_buf_size - 5;
    }

    /*  Copy as much as possible from input to output: */
    for (;;) {
        /*  Fill the window as much as possible: */
        if (s->lookahead <= 1) {

            Assert(s->strstart < s->w_size + MAX_DIST(s) ||
                s->block_start >= (long)s->w_size, "slide too late");

            fill_window(s);
            if (s->lookahead == 0 && flush == Z_NO_FLUSH) return need_more;

            if (s->lookahead == 0) break; /*  flush the current block */
        }
        Assert(s->block_start >= 0L, "block gone");

        s->strstart += s->lookahead;
        s->lookahead = 0;

        /*  Emit a stored block if pending_buf will be full: */
        max_start = s->block_start + max_block_size;
        if (s->strstart == 0 || (ulg)s->strstart >= max_start) {
            /*  strstart == 0 is possible when wraparound on 16-bit machine */
            s->lookahead = (uInt)(s->strstart - max_start);
            s->strstart = (uInt)max_start;
            FLUSH_BLOCK(s, 0);
        }
        /*  Flush if we may have to slide, otherwise block_start may become
             * negative and the data will be gone:
             */
        if (s->strstart - (uInt)s->block_start >= MAX_DIST(s)) {
            FLUSH_BLOCK(s, 0);
        }
    }
    FLUSH_BLOCK(s, flush == Z_FINISH);
    return flush == Z_FINISH ? finish_done : block_done;
}

/*  ===========================================================================
 * Compress as much as possible from the input stream, return the current
 * block state.
 * This function does not perform lazy evaluation of matches and inserts
 * new strings in the dictionary only for unmatched strings or for short
 * matches. It is used only for the fast compression options.
 */
local block_state deflate_fast(deflate_state* s, int flush)
{
    IPos hash_head = NIL; /*  head of the hash chain */
    int bflush;           /*  set if current block must be flushed */

    for (;;) {
        /*  Make sure that we always have enough lookahead, except
         *  at the end of the input file. We need MAX_MATCH bytes
         *  for the next match, plus MIN_MATCH bytes to insert the
         *  string following the next match.
         */
        if (s->lookahead < MIN_LOOKAHEAD) {
            fill_window(s);
            if (s->lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH) {
                return need_more;
            }
            if (s->lookahead == 0) break; /*  flush the current block */
        }

        /*  Insert the string window[strstart .. strstart+2] in the
         *  dictionary, and set hash_head to the head of the hash chain:
         */
        if (s->lookahead >= MIN_MATCH) {
            INSERT_STRING(s, s->strstart, hash_head);
        }

        /*  Find the longest match, discarding those <= prev_length.
         *  At this point we have always match_length < MIN_MATCH
         */
        if (hash_head != NIL && s->strstart - hash_head <= MAX_DIST(s)) {
            /*  To simplify the code, we prevent matches with the string
             *  of window index 0 (in particular we have to avoid a match
             *  of the string with itself at the start of the input file).
             */
            if (s->strategy != Z_HUFFMAN_ONLY) {
                s->match_length = longest_match(s, hash_head);
            }
            /*  longest_match() sets match_start */
        }
        if (s->match_length >= MIN_MATCH) {
            check_match(s, s->strstart, s->match_start, s->match_length);

            _tr_tally_dist(s, s->strstart - s->match_start,
                s->match_length - MIN_MATCH, bflush);

            s->lookahead -= s->match_length;

            /*  Insert new strings in the hash table only if the match length
             *  is not too large. This saves time but degrades compression.
             */
#ifndef FASTEST
            if (s->match_length <= s->max_insert_length &&
                s->lookahead >= MIN_MATCH) {
                s->match_length--; /*  string at strstart already in hash table */
                do {
                    s->strstart++;
                    INSERT_STRING(s, s->strstart, hash_head);
                    /*  strstart never exceeds WSIZE-MAX_MATCH, so there are
                     *  always MIN_MATCH bytes ahead.
                     */
                } while (--s->match_length != 0);
                s->strstart++;
            } else
#endif
            {
                s->strstart += s->match_length;
                s->match_length = 0;
                s->ins_h = s->window[s->strstart];
                UPDATE_HASH(s, s->ins_h, s->window[s->strstart + 1]);
#if MIN_MATCH != 3
                Call UPDATE_HASH() MIN_MATCH - 3 more times
#endif
                    /*  If lookahead < MIN_MATCH, ins_h is garbage, but it does not
                     *  matter since it will be recomputed at next deflate call.
                     */
            }
        } else {
            /*  No match, output a literal byte */
            Tracevv((stderr, "%c", s->window[s->strstart]));
            _tr_tally_lit(s, s->window[s->strstart], bflush);
            s->lookahead--;
            s->strstart++;
        }
        if (bflush) FLUSH_BLOCK(s, 0);
    }
    FLUSH_BLOCK(s, flush == Z_FINISH);
    return flush == Z_FINISH ? finish_done : block_done;
}

/*  ===========================================================================
 *  Same as above, but achieves better compression. We use a lazy
 *  evaluation for matches: a match is finally adopted only if there is
 *  no better match at the next window position.
 */
local block_state deflate_slow(deflate_state* s, int flush)
{
    IPos hash_head = NIL;    /*  head of hash chain */
    int bflush;              /*  set if current block must be flushed */

    /*  Process the input block. */
    for (;;) {
        /*  Make sure that we always have enough lookahead, except
         *  at the end of the input file. We need MAX_MATCH bytes
         *  for the next match, plus MIN_MATCH bytes to insert the
         *  string following the next match.
         */
        if (s->lookahead < MIN_LOOKAHEAD) {
            fill_window(s);
            if (s->lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH) {
                return need_more;
            }
            if (s->lookahead == 0) break; /*  flush the current block */
        }

        /*  Insert the string window[strstart .. strstart+2] in the
         *  dictionary, and set hash_head to the head of the hash chain:
         */
        if (s->lookahead >= MIN_MATCH) {
            INSERT_STRING(s, s->strstart, hash_head);
        }

        /*  Find the longest match, discarding those <= prev_length.
         */
        s->prev_length = s->match_length, s->prev_match = s->match_start;
        s->match_length = MIN_MATCH - 1;

        if (hash_head != NIL && s->prev_length < s->max_lazy_match &&
            s->strstart - hash_head <= MAX_DIST(s)) {
            /*  To simplify the code, we prevent matches with the string
             *  of window index 0 (in particular we have to avoid a match
             *  of the string with itself at the start of the input file).
             */
            if (s->strategy != Z_HUFFMAN_ONLY) {
                s->match_length = longest_match(s, hash_head);
            }
            /*  longest_match() sets match_start */

            if (s->match_length <= 5 && (s->strategy == Z_FILTERED ||
                (s->match_length == MIN_MATCH &&
                    s->strstart - s->match_start > TOO_FAR))) {

                /*  If prev_match is also MIN_MATCH, match_start is garbage
                 *  but we will ignore the current match anyway.
                 */
                s->match_length = MIN_MATCH - 1;
            }
        }
        /*  If there was a match at the previous step and the current
         *  match is not better, output the previous match:
         */
        if (s->prev_length >= MIN_MATCH && s->match_length <= s->prev_length) {
            uInt max_insert = s->strstart + s->lookahead - MIN_MATCH;
            /*  Do not insert strings in hash table beyond this. */

            check_match(s, s->strstart - 1, s->prev_match, s->prev_length);

            _tr_tally_dist(s, s->strstart - 1 - s->prev_match,
                s->prev_length - MIN_MATCH, bflush);

            /*  Insert in hash table all strings up to the end of the match.
             *  strstart-1 and strstart are already inserted. If there is not
             *  enough lookahead, the last two strings are not inserted in
             *  the hash table.
             */
            s->lookahead -= s->prev_length - 1;
            s->prev_length -= 2;
            do {
                if (++s->strstart <= max_insert) {
                    INSERT_STRING(s, s->strstart, hash_head);
                }
            } while (--s->prev_length != 0);
            s->match_available = 0;
            s->match_length = MIN_MATCH - 1;
            s->strstart++;

            if (bflush) FLUSH_BLOCK(s, 0);

        } else if (s->match_available) {
            /*  If there was no match at the previous position, output a
             *  single literal. If there was a match but the current match
             *  is longer, truncate the previous match to a single literal.
             */
            Tracevv((stderr, "%c", s->window[s->strstart - 1]));
            _tr_tally_lit(s, s->window[s->strstart - 1], bflush);
            if (bflush) {
                FLUSH_BLOCK_ONLY(s, 0);
            }
            s->strstart++;
            s->lookahead--;
            if (s->strm->avail_out == 0) return need_more;
        } else {
            /*  There is no previous match to compare with, wait for
             *  the next step to decide.
             */
            s->match_available = 1;
            s->strstart++;
            s->lookahead--;
        }
    }
    Assert(flush != Z_NO_FLUSH, "no flush?");
    if (s->match_available) {
        Tracevv((stderr, "%c", s->window[s->strstart - 1]));
        _tr_tally_lit(s, s->window[s->strstart - 1], bflush);
        s->match_available = 0;
    }
    FLUSH_BLOCK(s, flush == Z_FINISH);
    return flush == Z_FINISH ? finish_done : block_done;
}

#ifdef DEBUG
#include                <ctype.h>
#endif

/*  ===========================================================================
 *  Constants
 */

#define MAX_BL_BITS 7
 /*  Bit length codes must not exceed MAX_BL_BITS bits */

#define END_BLOCK 256
/*  end of block literal code */

#define REP_3_6      16
/*  repeat previous bit length 3-6 times (2 bits of repeat count) */

#define REPZ_3_10    17
/*  repeat a zero length 3-10 times  (3 bits of repeat count) */

#define REPZ_11_138  18
/*  repeat a zero length 11-138 times  (7 bits of repeat count) */

local const int extra_lbits[LENGTH_CODES] /*  extra bits for each length code */
= { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };

local const int extra_dbits[D_CODES] /*  extra bits for each distance code */
= { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };

local const int extra_blbits[BL_CODES]/*  extra bits for each bit length code */
= { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,3,7 };

local const uch bl_order[BL_CODES]
= { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
/*  The lengths of the bit length codes are sent in order of decreasing
 *  probability, to avoid transmitting the lengths for unused bit length codes.
 */

#define Buf_size (8 * 2*sizeof(char))
 /*  Number of bits used within bi_buf. (bi_buf might be implemented on
  *  more than 16 bits on some systems.)
  */

  /*  ===========================================================================
   *  Local data. These are initialized only once.
   */

#define DIST_CODE_LEN  512 /*  see definition of array dist_code below */

#if defined(GEN_TREES_H) || !defined(STDC)
   /*  non ANSI compilers may not accept trees.h */

local ct_data static_ltree[L_CODES + 2];
/*  The static literal tree. Since the bit lengths are imposed, there is no
 *  need for the L_CODES extra codes used during heap construction. However
 *  The codes 286 and 287 are needed to build a canonical tree (see _tr_init
 *  below).
 */

local ct_data static_dtree[D_CODES];
/*  The static distance tree. (Actually a trivial tree since all codes use
 *  5 bits.)
 */

uch _dist_code[DIST_CODE_LEN];
/*  Distance codes. The first 256 values correspond to the distances
 *  3 .. 258, the last 256 values correspond to the top 8 bits of
 *  the 15 bit distances.
 */

uch _length_code[MAX_MATCH - MIN_MATCH + 1];
/*  length code for each normalized match length (0 == MIN_MATCH) */

local int base_length[LENGTH_CODES];
/*  First normalized length for each code (0 = MIN_MATCH) */

local int base_dist[D_CODES];
/*  First normalized distance for each code (0 = distance of 1) */

#else
   /*  header created automatically with -DGEN_TREES_H */

local const ct_data static_ltree[L_CODES + 2] = {
{{ 12},{  8}}, {{140},{  8}}, {{ 76},{  8}}, {{204},{  8}}, {{ 44},{  8}},
{{172},{  8}}, {{108},{  8}}, {{236},{  8}}, {{ 28},{  8}}, {{156},{  8}},
{{ 92},{  8}}, {{220},{  8}}, {{ 60},{  8}}, {{188},{  8}}, {{124},{  8}},
{{252},{  8}}, {{  2},{  8}}, {{130},{  8}}, {{ 66},{  8}}, {{194},{  8}},
{{ 34},{  8}}, {{162},{  8}}, {{ 98},{  8}}, {{226},{  8}}, {{ 18},{  8}},
{{146},{  8}}, {{ 82},{  8}}, {{210},{  8}}, {{ 50},{  8}}, {{178},{  8}},
{{114},{  8}}, {{242},{  8}}, {{ 10},{  8}}, {{138},{  8}}, {{ 74},{  8}},
{{202},{  8}}, {{ 42},{  8}}, {{170},{  8}}, {{106},{  8}}, {{234},{  8}},
{{ 26},{  8}}, {{154},{  8}}, {{ 90},{  8}}, {{218},{  8}}, {{ 58},{  8}},
{{186},{  8}}, {{122},{  8}}, {{250},{  8}}, {{  6},{  8}}, {{134},{  8}},
{{ 70},{  8}}, {{198},{  8}}, {{ 38},{  8}}, {{166},{  8}}, {{102},{  8}},
{{230},{  8}}, {{ 22},{  8}}, {{150},{  8}}, {{ 86},{  8}}, {{214},{  8}},
{{ 54},{  8}}, {{182},{  8}}, {{118},{  8}}, {{246},{  8}}, {{ 14},{  8}},
{{142},{  8}}, {{ 78},{  8}}, {{206},{  8}}, {{ 46},{  8}}, {{174},{  8}},
{{110},{  8}}, {{238},{  8}}, {{ 30},{  8}}, {{158},{  8}}, {{ 94},{  8}},
{{222},{  8}}, {{ 62},{  8}}, {{190},{  8}}, {{126},{  8}}, {{254},{  8}},
{{  1},{  8}}, {{129},{  8}}, {{ 65},{  8}}, {{193},{  8}}, {{ 33},{  8}},
{{161},{  8}}, {{ 97},{  8}}, {{225},{  8}}, {{ 17},{  8}}, {{145},{  8}},
{{ 81},{  8}}, {{209},{  8}}, {{ 49},{  8}}, {{177},{  8}}, {{113},{  8}},
{{241},{  8}}, {{  9},{  8}}, {{137},{  8}}, {{ 73},{  8}}, {{201},{  8}},
{{ 41},{  8}}, {{169},{  8}}, {{105},{  8}}, {{233},{  8}}, {{ 25},{  8}},
{{153},{  8}}, {{ 89},{  8}}, {{217},{  8}}, {{ 57},{  8}}, {{185},{  8}},
{{121},{  8}}, {{249},{  8}}, {{  5},{  8}}, {{133},{  8}}, {{ 69},{  8}},
{{197},{  8}}, {{ 37},{  8}}, {{165},{  8}}, {{101},{  8}}, {{229},{  8}},
{{ 21},{  8}}, {{149},{  8}}, {{ 85},{  8}}, {{213},{  8}}, {{ 53},{  8}},
{{181},{  8}}, {{117},{  8}}, {{245},{  8}}, {{ 13},{  8}}, {{141},{  8}},
{{ 77},{  8}}, {{205},{  8}}, {{ 45},{  8}}, {{173},{  8}}, {{109},{  8}},
{{237},{  8}}, {{ 29},{  8}}, {{157},{  8}}, {{ 93},{  8}}, {{221},{  8}},
{{ 61},{  8}}, {{189},{  8}}, {{125},{  8}}, {{253},{  8}}, {{ 19},{  9}},
{{275},{  9}}, {{147},{  9}}, {{403},{  9}}, {{ 83},{  9}}, {{339},{  9}},
{{211},{  9}}, {{467},{  9}}, {{ 51},{  9}}, {{307},{  9}}, {{179},{  9}},
{{435},{  9}}, {{115},{  9}}, {{371},{  9}}, {{243},{  9}}, {{499},{  9}},
{{ 11},{  9}}, {{267},{  9}}, {{139},{  9}}, {{395},{  9}}, {{ 75},{  9}},
{{331},{  9}}, {{203},{  9}}, {{459},{  9}}, {{ 43},{  9}}, {{299},{  9}},
{{171},{  9}}, {{427},{  9}}, {{107},{  9}}, {{363},{  9}}, {{235},{  9}},
{{491},{  9}}, {{ 27},{  9}}, {{283},{  9}}, {{155},{  9}}, {{411},{  9}},
{{ 91},{  9}}, {{347},{  9}}, {{219},{  9}}, {{475},{  9}}, {{ 59},{  9}},
{{315},{  9}}, {{187},{  9}}, {{443},{  9}}, {{123},{  9}}, {{379},{  9}},
{{251},{  9}}, {{507},{  9}}, {{  7},{  9}}, {{263},{  9}}, {{135},{  9}},
{{391},{  9}}, {{ 71},{  9}}, {{327},{  9}}, {{199},{  9}}, {{455},{  9}},
{{ 39},{  9}}, {{295},{  9}}, {{167},{  9}}, {{423},{  9}}, {{103},{  9}},
{{359},{  9}}, {{231},{  9}}, {{487},{  9}}, {{ 23},{  9}}, {{279},{  9}},
{{151},{  9}}, {{407},{  9}}, {{ 87},{  9}}, {{343},{  9}}, {{215},{  9}},
{{471},{  9}}, {{ 55},{  9}}, {{311},{  9}}, {{183},{  9}}, {{439},{  9}},
{{119},{  9}}, {{375},{  9}}, {{247},{  9}}, {{503},{  9}}, {{ 15},{  9}},
{{271},{  9}}, {{143},{  9}}, {{399},{  9}}, {{ 79},{  9}}, {{335},{  9}},
{{207},{  9}}, {{463},{  9}}, {{ 47},{  9}}, {{303},{  9}}, {{175},{  9}},
{{431},{  9}}, {{111},{  9}}, {{367},{  9}}, {{239},{  9}}, {{495},{  9}},
{{ 31},{  9}}, {{287},{  9}}, {{159},{  9}}, {{415},{  9}}, {{ 95},{  9}},
{{351},{  9}}, {{223},{  9}}, {{479},{  9}}, {{ 63},{  9}}, {{319},{  9}},
{{191},{  9}}, {{447},{  9}}, {{127},{  9}}, {{383},{  9}}, {{255},{  9}},
{{511},{  9}}, {{  0},{  7}}, {{ 64},{  7}}, {{ 32},{  7}}, {{ 96},{  7}},
{{ 16},{  7}}, {{ 80},{  7}}, {{ 48},{  7}}, {{112},{  7}}, {{  8},{  7}},
{{ 72},{  7}}, {{ 40},{  7}}, {{104},{  7}}, {{ 24},{  7}}, {{ 88},{  7}},
{{ 56},{  7}}, {{120},{  7}}, {{  4},{  7}}, {{ 68},{  7}}, {{ 36},{  7}},
{{100},{  7}}, {{ 20},{  7}}, {{ 84},{  7}}, {{ 52},{  7}}, {{116},{  7}},
{{  3},{  8}}, {{131},{  8}}, {{ 67},{  8}}, {{195},{  8}}, {{ 35},{  8}},
{{163},{  8}}, {{ 99},{  8}}, {{227},{  8}}
};

local const ct_data static_dtree[D_CODES] = {
{{ 0},{ 5}}, {{16},{ 5}}, {{ 8},{ 5}}, {{24},{ 5}}, {{ 4},{ 5}},
{{20},{ 5}}, {{12},{ 5}}, {{28},{ 5}}, {{ 2},{ 5}}, {{18},{ 5}},
{{10},{ 5}}, {{26},{ 5}}, {{ 6},{ 5}}, {{22},{ 5}}, {{14},{ 5}},
{{30},{ 5}}, {{ 1},{ 5}}, {{17},{ 5}}, {{ 9},{ 5}}, {{25},{ 5}},
{{ 5},{ 5}}, {{21},{ 5}}, {{13},{ 5}}, {{29},{ 5}}, {{ 3},{ 5}},
{{19},{ 5}}, {{11},{ 5}}, {{27},{ 5}}, {{ 7},{ 5}}, {{23},{ 5}}
};

const uch _dist_code[DIST_CODE_LEN] = {
 0,  1,  2,  3,  4,  4,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,  8,  8,  8,  8,
 8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9, 10, 10, 10, 10, 10, 10, 10, 10,
10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13,
13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15,
15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,  0,  0, 16, 17,
18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22,
23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27,
27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
};

const uch _length_code[MAX_MATCH - MIN_MATCH + 1] = {
 0,  1,  2,  3,  4,  5,  6,  7,  8,  8,  9,  9, 10, 10, 11, 11, 12, 12, 12, 12,
13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16,
17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19,
19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22, 22,
22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26,
26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28
};

local const int base_length[LENGTH_CODES] = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56,
64, 80, 96, 112, 128, 160, 192, 224, 0
};

local const int base_dist[D_CODES] = {
    0,     1,     2,     3,     4,     6,     8,    12,    16,    24,
   32,    48,    64,    96,   128,   192,   256,   384,   512,   768,
 1024,  1536,  2048,  3072,  4096,  6144,  8192, 12288, 16384, 24576
};

#endif /*  GEN_TREES_H */

//struct static_tree_desc_s {
//    const ct_data *static_tree;  /*  static tree or NULL */
//    const intf *extra_bits;      /*  extra bits for each code or NULL */
//    int     extra_base;          /*  base index for extra_bits */
//    int     elems;               /*  max number of elements in the tree */
//    int     max_length;          /*  max bit length for the codes */
//};

local static_tree_desc  static_l_desc =
{ static_ltree, extra_lbits, LITERALS + 1, L_CODES, MAX_BITS };

local static_tree_desc  static_d_desc =
{ static_dtree, extra_dbits, 0,          D_CODES, MAX_BITS };

local static_tree_desc  static_bl_desc =
{ (const ct_data*)0, extra_blbits, 0,   BL_CODES, MAX_BL_BITS };

/*  ===========================================================================
 * Local (static) routines in this file.
 */

local void tr_static_init OF((void));
local void init_block     OF((deflate_state* s));
local void pqdownheap     OF((deflate_state* s, ct_data* tree, int k));
local void gen_bitlen     OF((deflate_state* s, tree_desc* desc));
local void gen_codes      OF((ct_data* tree, int max_code, ushf* bl_count));
local void build_tree     OF((deflate_state* s, tree_desc* desc));
local void scan_tree      OF((deflate_state* s, ct_data* tree, int max_code));
local void send_tree      OF((deflate_state* s, ct_data* tree, int max_code));
local int  build_bl_tree  OF((deflate_state* s));
local void send_all_trees OF((deflate_state* s, int lcodes, int dcodes,
    int blcodes));
local void compress_block OF((deflate_state* s, ct_data* ltree,
    ct_data* dtree));
local void set_data_type  OF((deflate_state* s));
local unsigned bi_reverse OF((unsigned value, int length));
local void bi_windup      OF((deflate_state* s));
local void bi_flush       OF((deflate_state* s));
local void copy_block     OF((deflate_state* s, charf* buf, unsigned len,
    int header));

#ifdef GEN_TREES_H
local void gen_trees_header OF((void));
#endif

#ifndef DEBUG
#  define send_code(s, c, tree) send_bits(s, tree[c].Code, tree[c].Len)
/*  Send a code of the given tree. c and tree must not have side effects */

#else /*  DEBUG */
#  define send_code(s, c, tree) \
     { if (z_verbose>2) fprintf(stderr,"\ncd %3d ",(c)); \
       send_bits(s, tree[c].Code, tree[c].Len); }
#endif

/*  ===========================================================================
 *  Output a short LSB first on the stream.
 *  IN assertion: there is enough room in pendingBuf.
 */
#define put_short(s, w) { \
    put_byte(s, (uch)((w) & 0xff)); \
    put_byte(s, (uch)((ush)(w) >> 8)); \
}

 /*  ===========================================================================
  *  Send a value on a given number of bits.
  *  IN assertion: length <= 16 and value fits in length bits.
  */
#ifdef DEBUG
local void send_bits      OF((deflate_state* s, int value, int length));

local void send_bits(deflate_state* s, int value, int length)
{
    Tracevv((stderr, " l %2d v %4x ", length, value));
    Assert(length > 0 && length <= 15, "invalid length");
    s->bits_sent += (ulg)length;

    /*  If not enough room in bi_buf, use (valid) bits from bi_buf and
     *  (16 - bi_valid) bits from value, leaving (width - (16-bi_valid))
     *  unused bits in value.
     */
    if (s->bi_valid > (int)Buf_size - length) {
        s->bi_buf |= (value << s->bi_valid);
        put_short(s, s->bi_buf);
        s->bi_buf = (ush)value >> (Buf_size - s->bi_valid);
        s->bi_valid += length - Buf_size;
    } else {
        s->bi_buf |= value << s->bi_valid;
        s->bi_valid += length;
    }
}
#else /*  !DEBUG */

#define send_bits(s, value, length) \
{ int len = length;\
  if (s->bi_valid > (int)Buf_size - len) {\
    int val = value;\
    s->bi_buf |= (val << s->bi_valid);\
    put_short(s, s->bi_buf);\
    s->bi_buf = (ush)((ush)val >> (Buf_size - s->bi_valid));\
    s->bi_valid += len - Buf_size;\
  } else {\
    s->bi_buf |= (value) << s->bi_valid;\
    s->bi_valid += len;\
  }\
}
#endif /*  DEBUG */

#if !defined( MAX )
#define MAX(a,b) (a >= b ? a : b)
#endif

  /*  the arguments must not have side effects */

  /*  ===========================================================================
   *  Initialize the various 'constant' tables.
   */
local void tr_static_init()
{
#if defined(GEN_TREES_H) || !defined(STDC)
    static int static_init_done = 0;
    int n;        /*  iterates over tree elements */
    int bits;     /*  bit counter */
    int length;   /*  length value */
    int code;     /*  code value */
    int dist;     /*  distance index */
    ush bl_count[MAX_BITS + 1];
    /*  number of codes at each bit length for an optimal tree */

    if (static_init_done) return;

    /*  For some embedded targets, global variables are not initialized: */
    static_l_desc.static_tree = static_ltree;
    static_l_desc.extra_bits = extra_lbits;
    static_d_desc.static_tree = static_dtree;
    static_d_desc.extra_bits = extra_dbits;
    static_bl_desc.extra_bits = extra_blbits;

    /*  Initialize the mapping length (0..255) -> length code (0..28) */
    length = 0;
    for (code = 0; code < LENGTH_CODES - 1; code++) {
        base_length[code] = length;
        for (n = 0; n < (1 << extra_lbits[code]); n++) {
            _length_code[length++] = (uch)code;
        }
    }
    Assert(length == 256, "tr_static_init: length != 256");
    /*  Note that the length 255 (match length 258) can be represented
     *  in two different ways: code 284 + 5 bits or code 285, so we
     *  overwrite length_code[255] to use the best encoding:
     */
    _length_code[length - 1] = (uch)code;

    /*  Initialize the mapping dist (0..32K) -> dist code (0..29) */
    dist = 0;
    for (code = 0; code < 16; code++) {
        base_dist[code] = dist;
        for (n = 0; n < (1 << extra_dbits[code]); n++) {
            _dist_code[dist++] = (uch)code;
        }
    }
    Assert(dist == 256, "tr_static_init: dist != 256");
    dist >>= 7; /*  from now on, all distances are divided by 128 */
    for (; code < D_CODES; code++) {
        base_dist[code] = dist << 7;
        for (n = 0; n < (1 << (extra_dbits[code] - 7)); n++) {
            _dist_code[256 + dist++] = (uch)code;
        }
    }
    Assert(dist == 256, "tr_static_init: 256+dist != 512");

    /*  Construct the codes of the static literal tree */
    for (bits = 0; bits <= MAX_BITS; bits++) bl_count[bits] = 0;
    n = 0;
    while (n <= 143) static_ltree[n++].Len = 8, bl_count[8]++;
    while (n <= 255) static_ltree[n++].Len = 9, bl_count[9]++;
    while (n <= 279) static_ltree[n++].Len = 7, bl_count[7]++;
    while (n <= 287) static_ltree[n++].Len = 8, bl_count[8]++;
    /*  Codes 286 and 287 do not exist, but we must include them in the
     *  tree construction to get a canonical Huffman tree (longest code
     *  all ones)
     */
    gen_codes((ct_data*)static_ltree, L_CODES + 1, bl_count);

    /*  The static distance tree is trivial: */
    for (n = 0; n < D_CODES; n++) {
        static_dtree[n].Len = 5;
        static_dtree[n].Code = bi_reverse((unsigned)n, 5);
    }
    static_init_done = 1;

#  ifdef GEN_TREES_H
    gen_trees_header();
#  endif
#endif /*  defined(GEN_TREES_H) || !defined(STDC) */
}

/*  ===========================================================================
 *  Genererate the file trees.h describing the static trees.
 */
#ifdef GEN_TREES_H
#ifndef DEBUG
#include                <stdio.h>
#endif

#define SEPARATOR(i, last, width) \
      ((i) == (last)? "\n};\n\n" :    \
       ((i) % (width) == (width)-1 ? ",\n" : ", "))

void gen_trees_header()
{
    FILE* header = fopen("trees.h", "w");
    int i;

    Assert(header != NULL, "Can't open trees.h");
    fprintf(header,
        "/* header created automatically with -DGEN_TREES_H */\n\n");

    fprintf(header, "local const ct_data static_ltree[L_CODES+2] = {\n");
    for (i = 0; i < L_CODES + 2; i++) {
        fprintf(header, "{{%3u},{%3u}}%s", static_ltree[i].Code,
            static_ltree[i].Len, SEPARATOR(i, L_CODES + 1, 5));
    }

    fprintf(header, "local const ct_data static_dtree[D_CODES] = {\n");
    for (i = 0; i < D_CODES; i++) {
        fprintf(header, "{{%2u},{%2u}}%s", static_dtree[i].Code,
            static_dtree[i].Len, SEPARATOR(i, D_CODES - 1, 5));
    }

    fprintf(header, "const uch _dist_code[DIST_CODE_LEN] = {\n");
    for (i = 0; i < DIST_CODE_LEN; i++) {
        fprintf(header, "%2u%s", _dist_code[i],
            SEPARATOR(i, DIST_CODE_LEN - 1, 20));
    }

    fprintf(header, "const uch _length_code[MAX_MATCH-MIN_MATCH+1]= {\n");
    for (i = 0; i < MAX_MATCH - MIN_MATCH + 1; i++) {
        fprintf(header, "%2u%s", _length_code[i],
            SEPARATOR(i, MAX_MATCH - MIN_MATCH, 20));
    }

    fprintf(header, "local const int base_length[LENGTH_CODES] = {\n");
    for (i = 0; i < LENGTH_CODES; i++) {
        fprintf(header, "%1u%s", base_length[i],
            SEPARATOR(i, LENGTH_CODES - 1, 20));
    }

    fprintf(header, "local const int base_dist[D_CODES] = {\n");
    for (i = 0; i < D_CODES; i++) {
        fprintf(header, "%5u%s", base_dist[i],
            SEPARATOR(i, D_CODES - 1, 10));
    }

    fclose(header);
}
#endif /*  GEN_TREES_H */

/*  ===========================================================================
 *  Initialize the tree data structures for a new zlib stream.
 */
void _tr_init(deflate_state* s)
{
    tr_static_init();

    s->l_desc.dyn_tree = s->dyn_ltree;
    s->l_desc.stat_desc = &static_l_desc;

    s->d_desc.dyn_tree = s->dyn_dtree;
    s->d_desc.stat_desc = &static_d_desc;

    s->bl_desc.dyn_tree = s->bl_tree;
    s->bl_desc.stat_desc = &static_bl_desc;

    s->bi_buf = 0;
    s->bi_valid = 0;
    s->last_eob_len = 8; /*  enough lookahead for inflate */
#ifdef DEBUG
    s->compressed_len = 0L;
    s->bits_sent = 0L;
#endif

    /*  Initialize the first block of the first file: */
    init_block(s);
}

/*  ===========================================================================
 *  Initialize a new block.
 */
local void init_block(deflate_state* s)
{
    int n; /*  iterates over tree elements */

    /*  Initialize the trees. */
    for (n = 0; n < L_CODES; n++) s->dyn_ltree[n].Freq = 0;
    for (n = 0; n < D_CODES; n++) s->dyn_dtree[n].Freq = 0;
    for (n = 0; n < BL_CODES; n++) s->bl_tree[n].Freq = 0;

    s->dyn_ltree[END_BLOCK].Freq = 1;
    s->opt_len = s->static_len = 0L;
    s->last_lit = s->matches = 0;
}

#define SMALLEST 1
/*  Index within the heap array of least frequent node in the Huffman tree */


/*  ===========================================================================
 *  Remove the smallest element from the heap and recreate the heap with
 *  one less element. Updates heap and heap_len.
 */
#define pqremove(s, tree, top) \
{\
    top = s->heap[SMALLEST]; \
    s->heap[SMALLEST] = s->heap[s->heap_len--]; \
    pqdownheap(s, tree, SMALLEST); \
}

 /*  ===========================================================================
  *  Compares to subtrees, using the tree depth as tie breaker when
  *  the subtrees have equal frequency. This minimizes the worst case length.
  */
#define smaller(tree, n, m, depth) \
   (tree[n].Freq < tree[m].Freq || \
   (tree[n].Freq == tree[m].Freq && depth[n] <= depth[m]))

  /*  ===========================================================================
   *  Restore the heap property by moving down the tree starting at node k,
   *  exchanging a node with the smallest of its two sons if necessary, stopping
   *  when the heap property is re-established (each father smaller than its
   *  two sons).
   */
local void pqdownheap(deflate_state* s, ct_data* tree, int k)
{
    int v = s->heap[k];
    int j = k << 1;  /*  left son of k */
    while (j <= s->heap_len) {
        /*  Set j to the smallest of the two sons: */
        if (j < s->heap_len &&
            smaller(tree, s->heap[j + 1], s->heap[j], s->depth)) {
            j++;
        }
        /*  Exit if v is smaller than both sons */
        if (smaller(tree, v, s->heap[j], s->depth)) break;

        /*  Exchange v with the smallest son */
        s->heap[k] = s->heap[j];  k = j;

        /*  And continue down the tree, setting j to the left son of k */
        j <<= 1;
    }
    s->heap[k] = v;
}

/*  ===========================================================================
 *  Compute the optimal bit lengths for a tree and update the total bit length
 *  for the current block.
 *  IN assertion: the fields freq and dad are set, heap[heap_max] and
 *    above are the tree nodes sorted by increasing frequency.
 *  OUT assertions: the field len is set to the optimal bit length, the
 *     array bl_count contains the frequencies for each bit length.
 *     The length opt_len is updated; static_len is also updated if stree is
 *     not null.
 */
local void gen_bitlen(deflate_state* s, tree_desc* desc)
{
    ct_data* tree = desc->dyn_tree;
    int max_code = desc->max_code;
    const ct_data* stree = desc->stat_desc->static_tree;
    const intf* extra = desc->stat_desc->extra_bits;
    int base = desc->stat_desc->extra_base;
    int max_length = desc->stat_desc->max_length;
    int h;              /*  heap index */
    int n, m;           /*  iterate over the tree elements */
    int bits;           /*  bit length */
    int xbits;          /*  extra bits */
    ush f;              /*  frequency */
    int overflow = 0;   /*  number of elements with bit length too large */

    for (bits = 0; bits <= MAX_BITS; bits++) s->bl_count[bits] = 0;

    /*  In a first pass, compute the optimal bit lengths (which may
     *  overflow in the case of the bit length tree).
     */
    tree[s->heap[s->heap_max]].Len = 0; /*  root of the heap */

    for (h = s->heap_max + 1; h < HEAP_SIZE; h++) {
        n = s->heap[h];
        bits = tree[tree[n].Dad].Len + 1;
        if (bits > max_length) bits = max_length, overflow++;
        tree[n].Len = (ush)bits;
        /*  We overwrite tree[n].Dad which is no longer needed */

        if (n > max_code) continue; /*  not a leaf node */

        s->bl_count[bits]++;
        xbits = 0;
        if (n >= base) xbits = extra[n - base];
        f = tree[n].Freq;
        s->opt_len += (ulg)f * (bits + xbits);
        if (stree) s->static_len += (ulg)f * (stree[n].Len + xbits);
    }
    if (overflow == 0) return;

    Trace((stderr, "\nbit length overflow\n"));
    /*  This happens for example on obj2 and pic of the Calgary corpus */

    /*  Find the first bit length which could increase: */
    do {
        bits = max_length - 1;
        while (s->bl_count[bits] == 0) bits--;
        s->bl_count[bits]--;      /*  move one leaf down the tree */
        s->bl_count[bits + 1] += 2; /*  move one overflow item as its brother */
        s->bl_count[max_length]--;
        /*  The brother of the overflow item also moves one step up,
         *  but this does not affect bl_count[max_length]
         */
        overflow -= 2;
    } while (overflow > 0);

    /*  Now recompute all bit lengths, scanning in increasing frequency.
     *  h is still equal to HEAP_SIZE. (It is simpler to reconstruct all
     *  lengths instead of fixing only the wrong ones. This idea is taken
     *  from 'ar' written by Haruhiko Okumura.)
     */
    for (bits = max_length; bits != 0; bits--) {
        n = s->bl_count[bits];
        while (n != 0) {
            m = s->heap[--h];
            if (m > max_code) continue;
            if (tree[m].Len != (unsigned)bits) {
                Trace((stderr, "code %d bits %d->%d\n", m, tree[m].Len, bits));
                s->opt_len += ((long)bits - (long)tree[m].Len)
                    * (long)tree[m].Freq;
                tree[m].Len = (ush)bits;
            }
            n--;
        }
    }
}

/*  ===========================================================================
 *  Generate the codes for a given tree and bit counts (which need not be
 *  optimal).
 *  IN assertion: the array bl_count contains the bit length statistics for
 *  the given tree and the field len is set for all tree elements.
 *  OUT assertion: the field code is set for all tree elements of non
 *      zero code length.
 */
local void gen_codes(ct_data* tree, int max_code, ushf* bl_count)
{
    ush next_code[MAX_BITS + 1]; /*  next code value for each bit length */
    ush code = 0;              /*  running code value */
    int bits;                  /*  bit index */
    int n;                     /*  code index */

    /*  The distribution counts are first used to generate the code values
     *  without bit reversal.
     */
    for (bits = 1; bits <= MAX_BITS; bits++) {
        next_code[bits] = code = (ush)((code + bl_count[bits - 1]) << 1);
    }
    /*  Check that the bit counts in bl_count are consistent. The last code
     *  must be all ones.
     */
    Assert(code + bl_count[MAX_BITS] - 1 == (1 << MAX_BITS) - 1,
        "inconsistent bit counts");
    Tracev((stderr, "\ngen_codes: max_code %d ", max_code));

    for (n = 0; n <= max_code; n++) {
        int len = tree[n].Len;
        if (len == 0) continue;
        /*  Now reverse the bits */
        tree[n].Code = (ush)bi_reverse(next_code[len]++, len);

        Tracecv(tree != static_ltree, (stderr, "\nn %3d %c l %2d c %4x (%x) ",
            n, (isgraph(n) ? n : ' '), len, tree[n].Code, next_code[len] - 1));
    }
}

/*  ===========================================================================
 *  Construct one Huffman tree and assigns the code bit strings and lengths.
 *  Update the total bit length for the current block.
 *  IN assertion: the field freq is set for all tree elements.
 *  OUT assertions: the fields len and code are set to the optimal bit length
 *      and corresponding code. The length opt_len is updated; static_len is
 *      also updated if stree is not null. The field max_code is set.
 */
local void build_tree(deflate_state* s, tree_desc* desc)
{
    ct_data* tree = desc->dyn_tree;
    const ct_data* stree = desc->stat_desc->static_tree;
    int elems = desc->stat_desc->elems;
    int n, m;          /*  iterate over heap elements */
    int max_code = -1; /*  largest code with non zero frequency */
    int node;          /*  new node being created */

    /*  Construct the initial heap, with least frequent element in
     *  heap[SMALLEST]. The sons of heap[n] are heap[2*n] and heap[2*n+1].
     *  heap[0] is not used.
     */
    s->heap_len = 0, s->heap_max = HEAP_SIZE;

    for (n = 0; n < elems; n++) {
        if (tree[n].Freq != 0) {
            s->heap[++(s->heap_len)] = max_code = n;
            s->depth[n] = 0;
        } else {
            tree[n].Len = 0;
        }
    }

    /*  The pkzip format requires that at least one distance code exists,
     *  and that at least one bit should be sent even if there is only one
     *  possible code. So to avoid special checks later on we force at least
     *  two codes of non zero frequency.
     */
    while (s->heap_len < 2) {
        node = s->heap[++(s->heap_len)] = (max_code < 2 ? ++max_code : 0);
        tree[node].Freq = 1;
        s->depth[node] = 0;
        s->opt_len--; if (stree) s->static_len -= stree[node].Len;
        /*  node is 0 or 1 so it does not have extra bits */
    }
    desc->max_code = max_code;

    /*  The elements heap[heap_len/2+1 .. heap_len] are leaves of the tree,
     *  establish sub-heaps of increasing lengths:
     */
    for (n = s->heap_len / 2; n >= 1; n--) pqdownheap(s, tree, n);

    /*  Construct the Huffman tree by repeatedly combining the least two
     *  frequent nodes.
     */
    node = elems;              /*  next internal node of the tree */
    do {
        pqremove(s, tree, n);  /*  n = node of least frequency */
        m = s->heap[SMALLEST]; /*  m = node of next least frequency */

        s->heap[--(s->heap_max)] = n; /*  keep the nodes sorted by frequency */
        s->heap[--(s->heap_max)] = m;

        /*  Create a new node father of n and m */
        tree[node].Freq = (ush)(tree[n].Freq + tree[m].Freq);
        s->depth[node] = (uch)(MAX(s->depth[n], s->depth[m]) + 1);
        tree[n].Dad = tree[m].Dad = (ush)node;
#ifdef DUMP_BL_TREE
        if (tree == s->bl_tree) {
            fprintf(stderr, "\nnode %d(%d), sons %d(%d) %d(%d)",
                node, tree[node].Freq, n, tree[n].Freq, m, tree[m].Freq);
        }
#endif
        /*  and insert the new node in the heap */
        s->heap[SMALLEST] = node++;
        pqdownheap(s, tree, SMALLEST);

    } while (s->heap_len >= 2);

    s->heap[--(s->heap_max)] = s->heap[SMALLEST];

    /*  At this point, the fields freq and dad are set. We can now
     *  generate the bit lengths.
     */
    gen_bitlen(s, (tree_desc*)desc);

    /*  The field len is now set, we can generate the bit codes */
    gen_codes((ct_data*)tree, max_code, s->bl_count);
}

/*  ===========================================================================
 *  Scan a literal or distance tree to determine the frequencies of the codes
 *  in the bit length tree.
 */
local void scan_tree(deflate_state* s, ct_data* tree, int max_code)
{
    int n;                     /*  iterates over all tree elements */
    int prevlen = -1;          /*  last emitted length */
    int curlen;                /*  length of current code */
    int nextlen = tree[0].Len; /*  length of next code */
    int count = 0;             /*  repeat count of the current code */
    int max_count = 7;         /*  max repeat count */
    int min_count = 4;         /*  min repeat count */

    if (nextlen == 0) max_count = 138, min_count = 3;
    tree[max_code + 1].Len = (ush)0xffff; /*  guard */

    for (n = 0; n <= max_code; n++) {
        curlen = nextlen; nextlen = tree[n + 1].Len;
        if (++count < max_count && curlen == nextlen) {
            continue;
        } else if (count < min_count) {
            s->bl_tree[curlen].Freq = (ush)(s->bl_tree[curlen].Freq + count);
        } else if (curlen != 0) {
            if (curlen != prevlen) s->bl_tree[curlen].Freq++;
            s->bl_tree[REP_3_6].Freq++;
        } else if (count <= 10) {
            s->bl_tree[REPZ_3_10].Freq++;
        } else {
            s->bl_tree[REPZ_11_138].Freq++;
        }
        count = 0; prevlen = curlen;
        if (nextlen == 0) {
            max_count = 138, min_count = 3;
        } else if (curlen == nextlen) {
            max_count = 6, min_count = 3;
        } else {
            max_count = 7, min_count = 4;
        }
    }
}

/*  ===========================================================================
 *  Send a literal or distance tree in compressed form, using the codes in
 *  bl_tree.
 */
local void send_tree(deflate_state* s, ct_data* tree, int max_code)
{
    int n;                     /*  iterates over all tree elements */
    int prevlen = -1;          /*  last emitted length */
    int curlen;                /*  length of current code */
    int nextlen = tree[0].Len; /*  length of next code */
    int count = 0;             /*  repeat count of the current code */
    int max_count = 7;         /*  max repeat count */
    int min_count = 4;         /*  min repeat count */

    /*  tree[max_code+1].Len = -1; */  /*  guard already set */
    if (nextlen == 0) max_count = 138, min_count = 3;

    for (n = 0; n <= max_code; n++) {
        curlen = nextlen; nextlen = tree[n + 1].Len;
        if (++count < max_count && curlen == nextlen) {
            continue;
        } else if (count < min_count) {
            do { send_code(s, curlen, s->bl_tree); } while (--count != 0);

        } else if (curlen != 0) {
            if (curlen != prevlen) {
                send_code(s, curlen, s->bl_tree); count--;
            }
            Assert(count >= 3 && count <= 6, " 3_6?");
            send_code(s, REP_3_6, s->bl_tree); send_bits(s, count - 3, 2);

        } else if (count <= 10) {
            send_code(s, REPZ_3_10, s->bl_tree); send_bits(s, count - 3, 3);

        } else {
            send_code(s, REPZ_11_138, s->bl_tree); send_bits(s, count - 11, 7);
        }
        count = 0; prevlen = curlen;
        if (nextlen == 0) {
            max_count = 138, min_count = 3;
        } else if (curlen == nextlen) {
            max_count = 6, min_count = 3;
        } else {
            max_count = 7, min_count = 4;
        }
    }
}

/*  ===========================================================================
 *  Construct the Huffman tree for the bit lengths and return the index in
 *  bl_order of the last bit length code to send.
 */
local int build_bl_tree(deflate_state* s)
{
    int max_blindex;  /*  index of last bit length code of non zero freq */

    /*  Determine the bit length frequencies for literal and distance trees */
    scan_tree(s, (ct_data*)s->dyn_ltree, s->l_desc.max_code);
    scan_tree(s, (ct_data*)s->dyn_dtree, s->d_desc.max_code);

    /*  Build the bit length tree: */
    build_tree(s, (tree_desc*)(&(s->bl_desc)));
    /*  opt_len now includes the length of the tree representations, except
     *  the lengths of the bit lengths codes and the 5+5+4 bits for the counts.
     */

     /*  Determine the number of bit length codes to send. The pkzip format
      *  requires that at least 4 bit length codes be sent. (appnote.txt says
      *  3 but the actual value used is 4.)
      */
    for (max_blindex = BL_CODES - 1; max_blindex >= 3; max_blindex--) {
        if (s->bl_tree[bl_order[max_blindex]].Len != 0) break;
    }
    /*  Update opt_len to include the bit length tree and counts */
    s->opt_len += 3 * (max_blindex + 1) + 5 + 5 + 4;
    Tracev((stderr, "\ndyn trees: dyn %ld, stat %ld",
        s->opt_len, s->static_len));

    return max_blindex;
}

/*  ===========================================================================
 *  Send the header for a block using dynamic Huffman trees: the counts, the
 *  lengths of the bit length codes, the literal tree and the distance tree.
 *  IN assertion: lcodes >= 257, dcodes >= 1, blcodes >= 4.
 */
local void send_all_trees(deflate_state* s, int lcodes, int dcodes, int blcodes)
{
    int rank;                    /*  index in bl_order */

    Assert(lcodes >= 257 && dcodes >= 1 && blcodes >= 4, "not enough codes");
    Assert(lcodes <= L_CODES && dcodes <= D_CODES && blcodes <= BL_CODES,
        "too many codes");
    Tracev((stderr, "\nbl counts: "));
    send_bits(s, lcodes - 257, 5); /*  not +255 as stated in appnote.txt */
    send_bits(s, dcodes - 1, 5);
    send_bits(s, blcodes - 4, 4); /*  not -3 as stated in appnote.txt */
    for (rank = 0; rank < blcodes; rank++) {
        Tracev((stderr, "\nbl code %2d ", bl_order[rank]));
        send_bits(s, s->bl_tree[bl_order[rank]].Len, 3);
    }
    Tracev((stderr, "\nbl tree: sent %ld", s->bits_sent));

    send_tree(s, (ct_data*)s->dyn_ltree, lcodes - 1); /*  literal tree */
    Tracev((stderr, "\nlit tree: sent %ld", s->bits_sent));

    send_tree(s, (ct_data*)s->dyn_dtree, dcodes - 1); /*  distance tree */
    Tracev((stderr, "\ndist tree: sent %ld", s->bits_sent));
}

/*  ===========================================================================
 *  Send a stored block
 */
void _tr_stored_block(deflate_state* s, charf* buf, ulg stored_len, int eof)
{
    send_bits(s, (STORED_BLOCK << 1) + eof, 3);  /*  send block type */
#ifdef DEBUG
    s->compressed_len = (s->compressed_len + 3 + 7) & (ulg)~7L;
    s->compressed_len += (stored_len + 4) << 3;
#endif
    copy_block(s, buf, (unsigned)stored_len, 1); /*  with header */
}

/*  ===========================================================================
 *  Send one empty static block to give enough lookahead for inflate.
 *  This takes 10 bits, of which 7 may remain in the bit buffer.
 *  The current inflate code requires 9 bits of lookahead. If the
 *  last two codes for the previous block (real code plus EOB) were coded
 *  on 5 bits or less, inflate may have only 5+3 bits of lookahead to decode
 *  the last real code. In this case we send two empty static blocks instead
 *  of one. (There are no problems if the previous block is stored or fixed.)
 *  To simplify the code, we assume the worst case of last real code encoded
 *  on one bit only.
 */
void _tr_align(deflate_state* s)
{
    send_bits(s, STATIC_TREES << 1, 3);
    send_code(s, END_BLOCK, static_ltree);
#ifdef DEBUG
    s->compressed_len += 10L; /*  3 for block type, 7 for EOB */
#endif
    bi_flush(s);
    /*  Of the 10 bits for the empty block, we have already sent
     * (10 - bi_valid) bits. The lookahead for the last real code (before
     * the EOB of the previous block) was thus at least one plus the length
     * of the EOB plus what we have just sent of the empty static block.
     */
    if (1 + s->last_eob_len + 10 - s->bi_valid < 9) {
        send_bits(s, STATIC_TREES << 1, 3);
        send_code(s, END_BLOCK, static_ltree);
#ifdef DEBUG
        s->compressed_len += 10L;
#endif
        bi_flush(s);
    }
    s->last_eob_len = 7;
}

/*  ===========================================================================
 *  Determine the best encoding for the current block: dynamic trees, static
 *  trees or store, and output the encoded block to the zip file.
 */
void _tr_flush_block(deflate_state* s, charf* buf, ulg stored_len, int eof)
{
    ulg opt_lenb, static_lenb; /*  opt_len and static_len in bytes */
    int max_blindex = 0;  /*  index of last bit length code of non zero freq */

    /*  Build the Huffman trees unless a stored block is forced */
    if (s->level > 0) {

        /*  Check if the file is ascii or binary */
        if (s->data_type == Z_UNKNOWN) set_data_type(s);

        /*  Construct the literal and distance trees */
        build_tree(s, (tree_desc*)(&(s->l_desc)));
        Tracev((stderr, "\nlit data: dyn %ld, stat %ld", s->opt_len,
            s->static_len));

        build_tree(s, (tree_desc*)(&(s->d_desc)));
        Tracev((stderr, "\ndist data: dyn %ld, stat %ld", s->opt_len,
            s->static_len));
        /*  At this point, opt_len and static_len are the total bit lengths of
         *  the compressed block data, excluding the tree representations.
         */

         /*  Build the bit length tree for the above two trees, and get the index
          *  in bl_order of the last bit length code to send.
          */
        max_blindex = build_bl_tree(s);

        /*  Determine the best encoding. Compute first the block length in bytes*/
        opt_lenb = (s->opt_len + 3 + 7) >> 3;
        static_lenb = (s->static_len + 3 + 7) >> 3;

        Tracev((stderr, "\nopt %lu(%lu) stat %lu(%lu) stored %lu lit %u ",
            opt_lenb, s->opt_len, static_lenb, s->static_len, stored_len,
            s->last_lit));

        if (static_lenb <= opt_lenb) opt_lenb = static_lenb;

    } else {
        Assert(buf != (char*)0, "lost buf");
        opt_lenb = static_lenb = stored_len + 5; /*  force a stored block */
    }

#ifdef FORCE_STORED
    if (buf != (char*)0) { /*  force stored block */
#else
    if (stored_len + 4 <= opt_lenb && buf != (char*)0) {
        /*  4: two words for the lengths */
#endif
        /*  The test buf != NULL is only necessary if LIT_BUFSIZE > WSIZE.
         *  Otherwise we can't have processed more than WSIZE input bytes since
         *  the last block flush, because compression would have been
         *  successful. If LIT_BUFSIZE <= WSIZE, it is never too late to
         *  transform a block into a stored block.
         */
        _tr_stored_block(s, buf, stored_len, eof);

#ifdef FORCE_STATIC
    } else if (static_lenb >= 0) { /*  force static trees */
#else
    } else if (static_lenb == opt_lenb) {
#endif
        send_bits(s, (STATIC_TREES << 1) + eof, 3);
        compress_block(s, (ct_data*)static_ltree, (ct_data*)static_dtree);
#ifdef DEBUG
        s->compressed_len += 3 + s->static_len;
#endif
    } else {
        send_bits(s, (DYN_TREES << 1) + eof, 3);
        send_all_trees(s, s->l_desc.max_code + 1, s->d_desc.max_code + 1,
            max_blindex + 1);
        compress_block(s, (ct_data*)s->dyn_ltree, (ct_data*)s->dyn_dtree);
#ifdef DEBUG
        s->compressed_len += 3 + s->opt_len;
#endif
    }
    Assert(s->compressed_len == s->bits_sent, "bad compressed size");
    /*  The above check is made mod 2^32, for files larger than 512 MB
     *  and uLong implemented on 32 bits.
     */
    init_block(s);

    if (eof) {
        bi_windup(s);
#ifdef DEBUG
        s->compressed_len += 7;  /*  align on byte boundary */
#endif
    }
    Tracev((stderr, "\ncomprlen %lu(%lu) ", s->compressed_len >> 3,
        s->compressed_len - 7 * eof));
    }

/*  ===========================================================================
 *  Save the match info and tally the frequency counts. Return true if
 *  the current block must be flushed.
 */
int _tr_tally(deflate_state * s, unsigned dist, unsigned lc)
{
    s->d_buf[s->last_lit] = (ush)dist;
    s->l_buf[s->last_lit++] = (uch)lc;
    if (dist == 0) {
        /*  lc is the unmatched char */
        s->dyn_ltree[lc].Freq++;
    } else {
        s->matches++;
        /*  Here, lc is the match length - MIN_MATCH */
        dist--;             /*  dist = match distance - 1 */
        Assert((ush)dist < (ush)MAX_DIST(s) &&
            (ush)lc <= (ush)(MAX_MATCH - MIN_MATCH) &&
            (ush)d_code(dist) < (ush)D_CODES, "_tr_tally: bad match");

        s->dyn_ltree[_length_code[lc] + LITERALS + 1].Freq++;
        s->dyn_dtree[d_code(dist)].Freq++;
    }

#ifdef TRUNCATE_BLOCK
    /*  Try to guess if it is profitable to stop the current block here */
    if ((s->last_lit & 0x1fff) == 0 && s->level > 2) {
        /*  Compute an upper bound for the compressed length */
        ulg out_length = (ulg)s->last_lit * 8L;
        ulg in_length = (ulg)((long)s->strstart - s->block_start);
        int dcode;
        for (dcode = 0; dcode < D_CODES; dcode++) {
            out_length += (ulg)s->dyn_dtree[dcode].Freq *
                (5L + extra_dbits[dcode]);
        }
        out_length >>= 3;
        Tracev((stderr, "\nlast_lit %u, in %ld, out ~%ld(%ld%%) ",
            s->last_lit, in_length, out_length,
            100L - out_length * 100L / in_length));
        if (s->matches < s->last_lit / 2 && out_length < in_length / 2) return 1;
    }
#endif
    return (s->last_lit == s->lit_bufsize - 1);
    /*  We avoid equality with lit_bufsize because of wraparound at 64K
     * on 16 bit machines and because stored blocks are restricted to
     * 64K-1 bytes.
     */
}

/*  ===========================================================================
 *  Send the block data compressed using the given Huffman trees
 */
local void compress_block(deflate_state * s, ct_data * ltree, ct_data * dtree)
{
    unsigned dist;      /*  distance of matched string */
    int lc;             /*  match length or unmatched char (if dist == 0) */
    unsigned lx = 0;    /*  running index in l_buf */
    unsigned code;      /*  the code to send */
    int extra;          /*  number of extra bits to send */

    if (s->last_lit != 0) do {
        dist = s->d_buf[lx];
        lc = s->l_buf[lx++];
        if (dist == 0) {
            send_code(s, lc, ltree); /*  send a literal byte */
            Tracecv(isgraph(lc), (stderr, " '%c' ", lc));
        } else {
            /*  Here, lc is the match length - MIN_MATCH */
            code = _length_code[lc];
            send_code(s, code + LITERALS + 1, ltree); /*  send the length code */
            extra = extra_lbits[code];
            if (extra != 0) {
                lc -= base_length[code];
                send_bits(s, lc, extra);       /*  send the extra length bits */
            }
            dist--; /*  dist is now the match distance - 1 */
            code = d_code(dist);
            Assert(code < D_CODES, "bad d_code");

            send_code(s, code, dtree);       /*  send the distance code */
            extra = extra_dbits[code];
            if (extra != 0) {
                dist -= base_dist[code];
                send_bits(s, dist, extra);   /*  send the extra distance bits */
            }
        } /*  literal or match pair ? */

        /*  Check that the overlay between pending_buf and d_buf+l_buf is ok: */
        Assert(s->pending < s->lit_bufsize + 2 * lx, "pendingBuf overflow");

    } while (lx < s->last_lit);

    send_code(s, END_BLOCK, ltree);
    s->last_eob_len = ltree[END_BLOCK].Len;
}

/*  ===========================================================================
 *  Set the data type to ASCII or BINARY, using a crude approximation:
 *  binary if more than 20% of the bytes are <= 6 or >= 128, ascii otherwise.
 *  IN assertion: the fields freq of dyn_ltree are set and the total of all
 *  frequencies does not exceed 64K (to fit in an int on 16 bit machines).
 */
local void set_data_type(deflate_state * s)
{
    int n = 0;
    unsigned ascii_freq = 0;
    unsigned bin_freq = 0;
    while (n < 7)        bin_freq += s->dyn_ltree[n++].Freq;
    while (n < 128)    ascii_freq += s->dyn_ltree[n++].Freq;
    while (n < LITERALS) bin_freq += s->dyn_ltree[n++].Freq;
    s->data_type = (Byte)(bin_freq > (ascii_freq >> 2) ? Z_BINARY : Z_ASCII);
}

/*  ===========================================================================
 *  Reverse the first len bits of a code, using straightforward code (a faster
 *  method would use a table)
 *  IN assertion: 1 <= len <= 15
 */
local unsigned bi_reverse(unsigned code, int len)
{
    register unsigned res = 0;
    do {
        res |= code & 1;
        code >>= 1, res <<= 1;
    } while (--len > 0);
    return res >> 1;
}

/*  ===========================================================================
 *  Flush the bit buffer, keeping at most 7 bits in it.
 */
local void bi_flush(deflate_state * s)
{
    if (s->bi_valid == 16) {
        put_short(s, s->bi_buf);
        s->bi_buf = 0;
        s->bi_valid = 0;
    } else if (s->bi_valid >= 8) {
        put_byte(s, (Byte)s->bi_buf);
        s->bi_buf >>= 8;
        s->bi_valid -= 8;
    }
}

/*  ===========================================================================
 *  Flush the bit buffer and align the output on a byte boundary
 */
local void bi_windup(deflate_state * s)
{
    if (s->bi_valid > 8) {
        put_short(s, s->bi_buf);
    } else if (s->bi_valid > 0) {
        put_byte(s, (Byte)s->bi_buf);
    }
    s->bi_buf = 0;
    s->bi_valid = 0;
#ifdef DEBUG
    s->bits_sent = (s->bits_sent + 7) & ~7;
#endif
}

/*  ===========================================================================
 *  Copy a stored block, storing first the length and its
 *  one's complement if requested.
 */
local void copy_block(deflate_state * s, charf * buf, unsigned len, int header)
{
    bi_windup(s);        /*  align on byte boundary */
    s->last_eob_len = 8; /*  enough lookahead for inflate */

    if (header) {
        put_short(s, (ush)len);
        put_short(s, (ush)~len);
#ifdef DEBUG
        s->bits_sent += 2 * 16;
#endif
    }
#ifdef DEBUG
    s->bits_sent += (ulg)len << 3;
#endif
    while (len--) {
        put_byte(s, *buf++);
    }
}


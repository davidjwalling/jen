#include "base64.h"

uint8_t pr2six[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#define DEC(c) pr2six[(int)c]

bool base64enc(uint8_t* out, uint8_t* in, size_t* len, size_t maxlen)
{
    intmax_t h = *len;
    size_t llen = 0;
    size_t bytes = 0;
    uint8_t* op = out;
    uint8_t a, b, c;

    for (; h > 0; h -= 3, in += 3) {
        b = c = 0;
        a = in[0];
        bytes = 1;
        if (h > 1) {
            b = in[1];
            bytes = 2;
            if (h > 2) {
                c = in[2];
                bytes = 3;
            }
        }
        *(op++) = ENC((a >> 2) & 0x3f);
        *(op++) = ENC(((a << 4) & 0x30) | ((b >> 4) & 0x0f));
        *(op++) = ENC(((b << 2) & 0x3c) | ((c >> 6) & 0x03));
        *(op++) = ENC(c & 0x3f);
        llen += 4;
        if ((maxlen) && (llen >= maxlen)) {
            *op++ = '\r';
            *op++ = '\n';
            llen = 0;
        }
    }
    if (2 == bytes) {
        op[-1] = '=';
    } else if (1 == bytes) {
        op[-1] = '=';
        op[-2] = '=';
    }
    if ((maxlen) && (llen)) {
        *op++ = '\r';
        *op++ = '\n';
    }
    *len = op - out;
    return true;
}

bool base64dec(uint8_t* out, const char* in, size_t* len)
{
    return base64dec(out, (uint8_t*)in, len);
}

bool base64dec(uint8_t* out, uint8_t* in, size_t* len)
{
    intmax_t inlen = *len;
    size_t outlen = 0;
    size_t j;
    uint8_t* q;

    if (!pr2six[0]) {
        for (j = 0; j < 256; pr2six[j] = 0x40, j++);
        for (j = 0; j < 64; pr2six[six2pr[j]] = (uint8_t)j, j++);
    }
    for (q = out; inlen >= 4; outlen += 3) {
        if (('\r' == in[0]) && ('\n' == in[1])) {
            in += 2;
            inlen -= 2;
            continue;
        }
        if ((DEC(in[0]) > 63) || (DEC(in[1]) > 63) || ((DEC(in[2]) > 63) && ('=' != in[2])) || ((DEC(in[3]) > 63) && ('=' != in[3])))
            return false;
        *(q++) = (uint8_t)(DEC(in[0]) << 2 | DEC(in[1]) >> 4);
        *(q++) = (uint8_t)(DEC(in[1]) << 4);
        if ('=' != in[2])
            q[-1] |= (uint8_t)(DEC(in[2]) >> 2);
        *(q++) = (uint8_t)(DEC(in[2]) << 6);
        if ('=' != in[3])
            q[-1] |= (uint8_t)(DEC(in[3]));
        in += 4;
        inlen -= 4;
    }
    if (pr2six[in[-2]] >= 0x40)
        outlen -= 2;
    else if (pr2six[in[-1]] >= 0x40)
        outlen -= 1;
    *len = outlen;
    return true;
}

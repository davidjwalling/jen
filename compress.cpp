#include "compress.h"

const char* z_errmsg[10] = {
    "need dictionary",          //  Z_NEED_DICT       2 
    "stream end",               //  Z_STREAM_END      1 
    "",                         //  Z_OK              0 
    "file error",               //  Z_ERRNO         (-1)
    "stream error",             //  Z_STREAM_ERROR  (-2)
    "data error",               //  Z_DATA_ERROR    (-3)
    "insufficient memory",      //  Z_MEM_ERROR     (-4)
    "buffer error",             //  Z_BUF_ERROR     (-5)
    "incompatible version",     //  Z_VERSION_ERROR (-6)
    ""
};

voidpf zcalloc(voidpf opaque, unsigned items, unsigned size)
{
    if (opaque)
        items += size - size;
    return (voidpf)calloc(items, size);
}

void zcfree(voidpf opaque, voidpf ptr)
{
    free(ptr);
    if (opaque)
        return;
}

int DeflateInit(z_streamp stream)
{
    return(deflateInit(stream, Z_DEFAULT_COMPRESSION));
}

int DeflateNext(z_streamp stream)
{
    return(deflate(stream, Z_SYNC_FLUSH));
}

int DeflateFinal(z_streamp stream)
{
    return(deflate(stream, Z_FINISH));
}

int DeflateEnd(z_streamp stream)
{
    return(deflateEnd(stream));
}

int Deflate(z_streamp stream, int nFlag)
{
    return(deflate(stream, nFlag));
}

int InflateInit(z_streamp stream)
{
    return(inflateInit(stream));
}

int InflateNext(z_streamp stream)
{
    return(inflate(stream, Z_SYNC_FLUSH));
}

int InflateFinal(z_streamp stream)
{
    return(inflate(stream, Z_FINISH));
}

int InflateEnd(z_streamp stream)
{
    return(inflateEnd(stream));
}

int Inflate(z_streamp stream, int nFlag)
{
    return(inflate(stream, nFlag));
}

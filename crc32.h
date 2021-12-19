#pragma once

#include "compress.h"

#define DO1( buf )  { crc = crc_table[((int)crc ^ ( *buf++ )) & 0xff] ^ ( crc >> 8 ); }
#define DO2( buf )  { DO1( buf ); DO1( buf ); }
#define DO4( buf )  { DO2( buf ); DO2( buf ); }
#define DO8( buf )  { DO4( buf ); DO4( buf ); }

#define ADLER_BASE          65521L

//  ADLER_NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1

#define ADLER_NMAX          5552

#define ADLER_DO1( buf, i )  { s1 += buf[i]; s2 += s1; }
#define ADLER_DO2( buf, i )  { ADLER_DO1( buf, i ); ADLER_DO1( buf, i + 1 ); }
#define ADLER_DO4( buf, i )  { ADLER_DO2( buf, i ); ADLER_DO2( buf, i + 2 ); }
#define ADLER_DO8( buf, i )  { ADLER_DO4( buf, i ); ADLER_DO4( buf, i + 4 ); }
#define ADLER_DO16( buf )    { ADLER_DO8( buf, 0 ); ADLER_DO8( buf, 8 ); }

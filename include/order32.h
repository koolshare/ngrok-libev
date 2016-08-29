#ifndef ORDER32_H
#define ORDER32_H

#include <limits.h>
#include <stdint.h>

#if CHAR_BIT != 8
#error "unsupported char size"
#endif

enum
{
    O32_LITTLE_ENDIAN = 0x03020100ul,
    O32_BIG_ENDIAN = 0x00010203ul,
    O32_PDP_ENDIAN = 0x01000302ul
};

static const union { unsigned char bytes[4]; uint32_t value; } o32_host_order =
    { { 0, 1, 2, 3 } };

#define O32_HOST_ORDER (o32_host_order.value)

#define Swap64(ll) (((ll) >> 56) |(((ll) & 0x00ff000000000000LL) >> 40) |(((ll) & 0x0000ff0000000000LL) >> 24) |(((ll) & 0x000000ff00000000LL) >> 8)|(((ll) & 0x00000000ff000000LL) << 8) |(((ll) & 0x0000000000ff0000LL) << 24) |(((ll) & 0x000000000000ff00LL) << 40) |(((ll) << 56)))

//#if O32_HOST_ORDER == O32_LITTLE_ENDIAN
//TODO use little
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define TO_LITTLE(ll) (ll)
#else
#define TO_LITTLE(ll) Swap64(ll)
#endif

#endif

/**
 * @brief Implementations for libc functions which the compiler expects to be present
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include <string.h>

#include <stdint.h>

// as per https://stackoverflow.com/questions/67210527/how-to-provide-an-implementation-of-memcpy
// attribute required to prevent these functions from optimizing to themselves
#define inhibit_libcall_opt [[gnu::optimize("no-tree-loop-distribute-patterns")]]

inhibit_libcall_opt void* memset(void* b, int c, size_t len) {
    uint8_t* p = (uint8_t*)b;
    for (size_t i = 0; i < len; ++i) {
        p[i] = (uint8_t)c;
    }
    return b;
}

inhibit_libcall_opt void* memcpy(void* restrict dst, const void* restrict src, size_t n) {
    if (dst == src) { // gcc supposedly requires this
        return dst;
    }

    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (size_t i = 0; i < n; ++i) {
        d[i] = s[i];
    }
    return dst;
}

inhibit_libcall_opt int memcmp(const void* vl, const void* vr, size_t n) {
    // taken from MUSL http://git.musl-libc.org/cgit/musl/tree/src/string/memcmp.c
    // under MIT license ( https://opensource.org/license/mit )
    const unsigned char *l = vl, *r = vr;
    for (; n && *l == *r; n--, l++, r++)
        ;
    return n ? *l - *r : 0;
}

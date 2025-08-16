// ref: https://chromium.googlesource.com/external/github.com/google/protobuf/+/HEAD/ruby/ext/google/protobuf_c/wrap_memcpy.c

#include <string.h>
#ifdef __linux__
#if defined(__x86_64__) && defined(__GNU_LIBRARY__)
__asm__(".symver memcpy,memcpy@GLIBC_2.2.5");
void *__wrap_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, n);
}
#else
void *__wrap_memcpy(void *dest, const void *src, size_t n) {
    return memmove(dest, src, n);
}
#endif
#endif

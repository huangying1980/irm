/* huangying */
#ifndef IRM_FAST_MEMCPY_X86_64_H_
#define IRM_FAST_MEMCPY_X86_64_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>
#if defined(__AVX__)
#include <immintrin.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
#ifdef IRM_SOCK_DISABLE_ALWAYS_INLINE
#define IRM_SOCK_ALWAYS_INLINE inline
#else
#define IRM_SOCK_ALWAYS_INLINE inline __attribute__((always_inline))
#endif

static IRM_SOCK_ALWAYS_INLINE void*
irm_fast_memcpy(void* dst, const void* src, size_t n);

#if defined __AVX512F__

#define ALIGNMENT_MASK 0x3F

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov16(uint8_t* dst, const uint8_t* src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov32(uint8_t* dst, const uint8_t* src)
{
	__m256i ymm0;

	ymm0 = _mm256_loadu_si256((const __m256i *)src);
	_mm256_storeu_si256((__m256i *)dst, ymm0);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov64(uint8_t* dst, const uint8_t* src)
{
	__m512i zmm0;

	zmm0 = _mm512_loadu_si512((const void *)src);
	_mm512_storeu_si512((void *)dst, zmm0);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov128(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov64(dst + 0 * 64, src + 0 * 64);
	irm_fast_mov64(dst + 1 * 64, src + 1 * 64);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov256(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov64(dst + 0 * 64, src + 0 * 64);
	irm_fast_mov64(dst + 1 * 64, src + 1 * 64);
	irm_fast_mov64(dst + 2 * 64, src + 2 * 64);
	irm_fast_mov64(dst + 3 * 64, src + 3 * 64);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov128blocks(uint8_t* dst,
    const uint8_t* src, size_t n)
{
	__m512i zmm0, zmm1;

	while (n >= 128) {
		zmm0 = _mm512_loadu_si512((const void *)(src + 0 * 64));
		n -= 128;
		zmm1 = _mm512_loadu_si512((const void *)(src + 1 * 64));
		src = src + 128;
		_mm512_storeu_si512((void *)(dst + 0 * 64), zmm0);
		_mm512_storeu_si512((void *)(dst + 1 * 64), zmm1);
		dst = dst + 128;
	}
}

static inline void irm_fast_mov512blocks(uint8_t* dst, const uint8_t* src, size_t n)
{
	__m512i zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7;

	while (n >= 512) {
		zmm0 = _mm512_loadu_si512((const void *)(src + 0 * 64));
		n -= 512;
		zmm1 = _mm512_loadu_si512((const void *)(src + 1 * 64));
		zmm2 = _mm512_loadu_si512((const void *)(src + 2 * 64));
		zmm3 = _mm512_loadu_si512((const void *)(src + 3 * 64));
		zmm4 = _mm512_loadu_si512((const void *)(src + 4 * 64));
		zmm5 = _mm512_loadu_si512((const void *)(src + 5 * 64));
		zmm6 = _mm512_loadu_si512((const void *)(src + 6 * 64));
		zmm7 = _mm512_loadu_si512((const void *)(src + 7 * 64));
		src = src + 512;
		_mm512_storeu_si512((void *)(dst + 0 * 64), zmm0);
		_mm512_storeu_si512((void *)(dst + 1 * 64), zmm1);
		_mm512_storeu_si512((void *)(dst + 2 * 64), zmm2);
		_mm512_storeu_si512((void *)(dst + 3 * 64), zmm3);
		_mm512_storeu_si512((void *)(dst + 4 * 64), zmm4);
		_mm512_storeu_si512((void *)(dst + 5 * 64), zmm5);
		_mm512_storeu_si512((void *)(dst + 6 * 64), zmm6);
		_mm512_storeu_si512((void *)(dst + 7 * 64), zmm7);
		dst = dst + 512;
	}
}

static IRM_SOCK_ALWAYS_INLINE void* irm_fast_memcpy_generic(void* dst,
    const void* src, size_t n)
{
	uintptr_t   dstu = (uintptr_t)dst;
	uintptr_t   srcu = (uintptr_t)src;
	void*       ret = dst;
	size_t      dstofss;
	size_t      bits;

	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dstu = *(const uint8_t *)srcu;
			srcu = (uintptr_t)((const uint8_t *)srcu + 1);
			dstu = (uintptr_t)((uint8_t *)dstu + 1);
		}
		if (n & 0x02) {
			*(uint16_t *)dstu = *(const uint16_t *)srcu;
			srcu = (uintptr_t)((const uint16_t *)srcu + 1);
			dstu = (uintptr_t)((uint16_t *)dstu + 1);
		}
		if (n & 0x04) {
			*(uint32_t *)dstu = *(const uint32_t *)srcu;
			srcu = (uintptr_t)((const uint32_t *)srcu + 1);
			dstu = (uintptr_t)((uint32_t *)dstu + 1);
		}
		if (n & 0x08)
			*(uint64_t *)dstu = *(const uint64_t *)srcu;
		return ret;
	}

	if (n <= 32) {
		irm_fast_mov16((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov16((uint8_t *)dst - 16 + n,
				  (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 64) {
		irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov32((uint8_t *)dst - 32 + n,
				  (const uint8_t *)src - 32 + n);
		return ret;
	}
	if (n <= 512) {
		if (n >= 256) {
			n -= 256;
			irm_fast_mov256((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 256;
			dst = (uint8_t *)dst + 256;
		}
		if (n >= 128) {
			n -= 128;
			irm_fast_mov128((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}
COPY_BLOCK_128_BACK63:
		if (n > 64) {
			irm_fast_mov64((uint8_t *)dst, (const uint8_t *)src);
			irm_fast_mov64((uint8_t *)dst - 64 + n,
					  (const uint8_t *)src - 64 + n);
			return ret;
		}
		if (n > 0)
			irm_fast_mov64((uint8_t *)dst - 64 + n,
					  (const uint8_t *)src - 64 + n);
		return ret;
	}

	dstofss = ((uintptr_t)dst & 0x3F);
	if (dstofss > 0) {
		dstofss = 64 - dstofss;
		n -= dstofss;
		irm_fast_mov64((uint8_t *)dst, (const uint8_t *)src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}

	irm_fast_mov512blocks((uint8_t *)dst, (const uint8_t *)src, n);
	bits = n;
	n = n & 511;
	bits -= n;
	src = (const uint8_t *)src + bits;
	dst = (uint8_t *)dst + bits;

	if (n >= 128) {
		irm_fast_mov128blocks((uint8_t *)dst, (const uint8_t *)src, n);
		bits = n;
		n = n & 127;
		bits -= n;
		src = (const uint8_t *)src + bits;
		dst = (uint8_t *)dst + bits;
	}

	goto COPY_BLOCK_128_BACK63;
}

#elif defined __AVX2__

#define ALIGNMENT_MASK 0x1F

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov16(uint8_t* dst, const uint8_t* src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov32(uint8_t* dst, const uint8_t* src)
{
	__m256i ymm0;

	ymm0 = _mm256_loadu_si256((const __m256i *)src);
	_mm256_storeu_si256((__m256i *)dst, ymm0);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov64(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov32((uint8_t *)dst + 0 * 32, (const uint8_t *)src + 0 * 32);
	irm_fast_mov32((uint8_t *)dst + 1 * 32, (const uint8_t *)src + 1 * 32);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov128(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov32((uint8_t *)dst + 0 * 32, (const uint8_t *)src + 0 * 32);
	irm_fast_mov32((uint8_t *)dst + 1 * 32, (const uint8_t *)src + 1 * 32);
	irm_fast_mov32((uint8_t *)dst + 2 * 32, (const uint8_t *)src + 2 * 32);
	irm_fast_mov32((uint8_t *)dst + 3 * 32, (const uint8_t *)src + 3 * 32);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov128blocks(uint8_t* dst,
    const uint8_t* src, size_t n)
{
	__m256i ymm0, ymm1, ymm2, ymm3;

	while (n >= 128) {
		ymm0 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 0 * 32));
		n -= 128;
		ymm1 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 1 * 32));
		ymm2 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 2 * 32));
		ymm3 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 3 * 32));
		src = (const uint8_t *)src + 128;
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 0 * 32), ymm0);
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 1 * 32), ymm1);
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 2 * 32), ymm2);
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 3 * 32), ymm3);
		dst = (uint8_t *)dst + 128;
	}
}

static IRM_SOCK_ALWAYS_INLINE void* irm_fast_memcpy_generic(void* dst,
    const void* src, size_t n)
{
	uintptr_t   dstu = (uintptr_t)dst;
	uintptr_t   srcu = (uintptr_t)src;
	void*       ret = dst;
	size_t      dstofss;
	size_t      bits;

	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dstu = *(const uint8_t *)srcu;
			srcu = (uintptr_t)((const uint8_t *)srcu + 1);
			dstu = (uintptr_t)((uint8_t *)dstu + 1);
		}
		if (n & 0x02) {
			*(uint16_t *)dstu = *(const uint16_t *)srcu;
			srcu = (uintptr_t)((const uint16_t *)srcu + 1);
			dstu = (uintptr_t)((uint16_t *)dstu + 1);
		}
		if (n & 0x04) {
			*(uint32_t *)dstu = *(const uint32_t *)srcu;
			srcu = (uintptr_t)((const uint32_t *)srcu + 1);
			dstu = (uintptr_t)((uint32_t *)dstu + 1);
		}
		if (n & 0x08) {
			*(uint64_t *)dstu = *(const uint64_t *)srcu;
		}
		return ret;
	}

	if (n <= 32) {
		irm_fast_mov16((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov16((uint8_t *)dst - 16 + n,
				(const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 48) {
		irm_fast_mov16((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov16((uint8_t *)dst + 16, (const uint8_t *)src + 16);
		irm_fast_mov16((uint8_t *)dst - 16 + n,
				(const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 64) {
		irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov32((uint8_t *)dst - 32 + n,
				(const uint8_t *)src - 32 + n);
		return ret;
	}
	if (n <= 256) {
		if (n >= 128) {
			n -= 128;
			irm_fast_mov128((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}
COPY_BLOCK_128_BACK31:
		if (n >= 64) {
			n -= 64;
			irm_fast_mov64((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 64;
			dst = (uint8_t *)dst + 64;
		}
		if (n > 32) {
			irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
			irm_fast_mov32((uint8_t *)dst - 32 + n,
					(const uint8_t *)src - 32 + n);
			return ret;
		}
		if (n > 0) {
			irm_fast_mov32((uint8_t *)dst - 32 + n,
					(const uint8_t *)src - 32 + n);
		}
		return ret;
	}

	dstofss = (uintptr_t)dst & 0x1F;
	if (dstofss > 0) {
		dstofss = 32 - dstofss;
		n -= dstofss;
		irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}

	irm_fast_mov128blocks((uint8_t *)dst, (const uint8_t *)src, n);
	bits = n;
	n = n & 127;
	bits -= n;
	src = (const uint8_t *)src + bits;
	dst = (uint8_t *)dst + bits;

	goto COPY_BLOCK_128_BACK31;
}

#else /* __AVX512F__ */

#define ALIGNMENT_MASK 0x0F

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov16(uint8_t* dst, const uint8_t* src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)(const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov32(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	irm_fast_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov64(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	irm_fast_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
	irm_fast_mov16((uint8_t *)dst + 2 * 16, (const uint8_t *)src + 2 * 16);
	irm_fast_mov16((uint8_t *)dst + 3 * 16, (const uint8_t *)src + 3 * 16);
}

static IRM_SOCK_ALWAYS_INLINE void irm_fast_mov128(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	irm_fast_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
	irm_fast_mov16((uint8_t *)dst + 2 * 16, (const uint8_t *)src + 2 * 16);
	irm_fast_mov16((uint8_t *)dst + 3 * 16, (const uint8_t *)src + 3 * 16);
	irm_fast_mov16((uint8_t *)dst + 4 * 16, (const uint8_t *)src + 4 * 16);
	irm_fast_mov16((uint8_t *)dst + 5 * 16, (const uint8_t *)src + 5 * 16);
	irm_fast_mov16((uint8_t *)dst + 6 * 16, (const uint8_t *)src + 6 * 16);
	irm_fast_mov16((uint8_t *)dst + 7 * 16, (const uint8_t *)src + 7 * 16);
}

static inline void irm_fast_mov256(uint8_t* dst, const uint8_t* src)
{
	irm_fast_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	irm_fast_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
	irm_fast_mov16((uint8_t *)dst + 2 * 16, (const uint8_t *)src + 2 * 16);
	irm_fast_mov16((uint8_t *)dst + 3 * 16, (const uint8_t *)src + 3 * 16);
	irm_fast_mov16((uint8_t *)dst + 4 * 16, (const uint8_t *)src + 4 * 16);
	irm_fast_mov16((uint8_t *)dst + 5 * 16, (const uint8_t *)src + 5 * 16);
	irm_fast_mov16((uint8_t *)dst + 6 * 16, (const uint8_t *)src + 6 * 16);
	irm_fast_mov16((uint8_t *)dst + 7 * 16, (const uint8_t *)src + 7 * 16);
	irm_fast_mov16((uint8_t *)dst + 8 * 16, (const uint8_t *)src + 8 * 16);
	irm_fast_mov16((uint8_t *)dst + 9 * 16, (const uint8_t *)src + 9 * 16);
	irm_fast_mov16((uint8_t *)dst + 10 * 16, (const uint8_t *)src + 10 * 16);
	irm_fast_mov16((uint8_t *)dst + 11 * 16, (const uint8_t *)src + 11 * 16);
	irm_fast_mov16((uint8_t *)dst + 12 * 16, (const uint8_t *)src + 12 * 16);
	irm_fast_mov16((uint8_t *)dst + 13 * 16, (const uint8_t *)src + 13 * 16);
	irm_fast_mov16((uint8_t *)dst + 14 * 16, (const uint8_t *)src + 14 * 16);
	irm_fast_mov16((uint8_t *)dst + 15 * 16, (const uint8_t *)src + 15 * 16);
}

#define MOVEUNALIGNED_LEFT47_IMM(dst, src, len, offset)                                                     \
__extension__ ({                                                                                            \
    size_t tmp;                                                                                                \
    while (len >= 128 + 16 - offset) {                                                                      \
        xmm0 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 0 * 16));                  \
        len -= 128;                                                                                         \
        xmm1 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 1 * 16));                  \
        xmm2 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 2 * 16));                  \
        xmm3 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 3 * 16));                  \
        xmm4 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 4 * 16));                  \
        xmm5 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 5 * 16));                  \
        xmm6 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 6 * 16));                  \
        xmm7 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 7 * 16));                  \
        xmm8 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 8 * 16));                  \
        src = (const uint8_t *)src + 128;                                                                   \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 2 * 16), _mm_alignr_epi8(xmm3, xmm2, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 3 * 16), _mm_alignr_epi8(xmm4, xmm3, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 4 * 16), _mm_alignr_epi8(xmm5, xmm4, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 5 * 16), _mm_alignr_epi8(xmm6, xmm5, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 6 * 16), _mm_alignr_epi8(xmm7, xmm6, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 7 * 16), _mm_alignr_epi8(xmm8, xmm7, offset));        \
        dst = (uint8_t *)dst + 128;                                                                         \
    }                                                                                                       \
    tmp = len;                                                                                              \
    len = ((len - 16 + offset) & 127) + 16 - offset;                                                        \
    tmp -= len;                                                                                             \
    src = (const uint8_t *)src + tmp;                                                                       \
    dst = (uint8_t *)dst + tmp;                                                                             \
    if (len >= 32 + 16 - offset) {                                                                          \
        while (len >= 32 + 16 - offset) {                                                                   \
            xmm0 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 0 * 16));              \
            len -= 32;                                                                                      \
            xmm1 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 1 * 16));              \
            xmm2 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 2 * 16));              \
            src = (const uint8_t *)src + 32;                                                                \
            _mm_storeu_si128((__m128i *)((uint8_t *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));    \
            _mm_storeu_si128((__m128i *)((uint8_t *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));    \
            dst = (uint8_t *)dst + 32;                                                                      \
        }                                                                                                   \
        tmp = len;                                                                                          \
        len = ((len - 16 + offset) & 31) + 16 - offset;                                                     \
        tmp -= len;                                                                                         \
        src = (const uint8_t *)src + tmp;                                                                   \
        dst = (uint8_t *)dst + tmp;                                                                         \
    }                                                                                                       \
})

#define MOVEUNALIGNED_LEFT47(dst, src, len, offset)                   \
__extension__ ({                                                      \
    switch (offset) {                                                 \
    case 0x01: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x01); break;    \
    case 0x02: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x02); break;    \
    case 0x03: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x03); break;    \
    case 0x04: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x04); break;    \
    case 0x05: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x05); break;    \
    case 0x06: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x06); break;    \
    case 0x07: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x07); break;    \
    case 0x08: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x08); break;    \
    case 0x09: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x09); break;    \
    case 0x0A: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0A); break;    \
    case 0x0B: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0B); break;    \
    case 0x0C: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0C); break;    \
    case 0x0D: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0D); break;    \
    case 0x0E: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0E); break;    \
    case 0x0F: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0F); break;    \
    default:;                                                         \
    }                                                                 \
})

static IRM_SOCK_ALWAYS_INLINE void* irm_fast_memcpy_generic(void* dst,
    const void* src, size_t n)
{
	__m128i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8;
	uintptr_t   dstu = (uintptr_t)dst;
	uintptr_t   srcu = (uintptr_t)src;
	void*       ret = dst;
	size_t      dstofss;
	size_t      srcofs;

	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dstu = *(const uint8_t *)srcu;
			srcu = (uintptr_t)((const uint8_t *)srcu + 1);
			dstu = (uintptr_t)((uint8_t *)dstu + 1);
		}
		if (n & 0x02) {
			*(uint16_t *)dstu = *(const uint16_t *)srcu;
			srcu = (uintptr_t)((const uint16_t *)srcu + 1);
			dstu = (uintptr_t)((uint16_t *)dstu + 1);
		}
		if (n & 0x04) {
			*(uint32_t *)dstu = *(const uint32_t *)srcu;
			srcu = (uintptr_t)((const uint32_t *)srcu + 1);
			dstu = (uintptr_t)((uint32_t *)dstu + 1);
		}
		if (n & 0x08) {
			*(uint64_t *)dstu = *(const uint64_t *)srcu;
		}
		return ret;
	}

	if (n <= 32) {
		irm_fast_mov16((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 48) {
		irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 64) {
		irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov16((uint8_t *)dst + 32, (const uint8_t *)src + 32);
		irm_fast_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 128) {
		goto COPY_BLOCK_128_BACK15;
	}
	if (n <= 512) {
		if (n >= 256) {
			n -= 256;
			irm_fast_mov128((uint8_t *)dst, (const uint8_t *)src);
			irm_fast_mov128((uint8_t *)dst + 128, (const uint8_t *)src + 128);
			src = (const uint8_t *)src + 256;
			dst = (uint8_t *)dst + 256;
		}
COPY_BLOCK_255_BACK15:
		if (n >= 128) {
			n -= 128;
			irm_fast_mov128((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}
COPY_BLOCK_128_BACK15:
		if (n >= 64) {
			n -= 64;
			irm_fast_mov64((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 64;
			dst = (uint8_t *)dst + 64;
		}
COPY_BLOCK_64_BACK15:
		if (n >= 32) {
			n -= 32;
			irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 32;
			dst = (uint8_t *)dst + 32;
		}
		if (n > 16) {
			irm_fast_mov16((uint8_t *)dst, (const uint8_t *)src);
			irm_fast_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
			return ret;
		}
		if (n > 0) {
			irm_fast_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		}
		return ret;
	}

	dstofss = (uintptr_t)dst & 0x0F;
	if (dstofss > 0) {
		dstofss = 16 - dstofss + 16;
		n -= dstofss;
		irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}
	srcofs = ((uintptr_t)src & 0x0F);

	if (srcofs == 0) {
		for (; n >= 256; n -= 256) {
			irm_fast_mov256((uint8_t *)dst, (const uint8_t *)src);
			dst = (uint8_t *)dst + 256;
			src = (const uint8_t *)src + 256;
		}

		goto COPY_BLOCK_255_BACK15;
	}

	MOVEUNALIGNED_LEFT47(dst, src, n, srcofs);

	goto COPY_BLOCK_64_BACK15;
}

#endif /* __AVX512F__ */

static IRM_SOCK_ALWAYS_INLINE void* irm_fast_memcpy_aligned(void* dst,
    const void* src, size_t n)
{
	void* ret = dst;

	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dst = *(const uint8_t *)src;
			src = (const uint8_t *)src + 1;
			dst = (uint8_t *)dst + 1;
		}
		if (n & 0x02) {
			*(uint16_t *)dst = *(const uint16_t *)src;
			src = (const uint16_t *)src + 1;
			dst = (uint16_t *)dst + 1;
		}
		if (n & 0x04) {
			*(uint32_t *)dst = *(const uint32_t *)src;
			src = (const uint32_t *)src + 1;
			dst = (uint32_t *)dst + 1;
		}
		if (n & 0x08)
			*(uint64_t *)dst = *(const uint64_t *)src;

		return ret;
	}

	if (n <= 32) {
		irm_fast_mov16((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov16((uint8_t *)dst - 16 + n,
				(const uint8_t *)src - 16 + n);

		return ret;
	}

	if (n <= 64) {
		irm_fast_mov32((uint8_t *)dst, (const uint8_t *)src);
		irm_fast_mov32((uint8_t *)dst - 32 + n,
				(const uint8_t *)src - 32 + n);

		return ret;
	}

	for (; n >= 64; n -= 64) {
		irm_fast_mov64((uint8_t *)dst, (const uint8_t *)src);
		dst = (uint8_t *)dst + 64;
		src = (const uint8_t *)src + 64;
	}

	irm_fast_mov64((uint8_t *)dst - 64 + n,
			(const uint8_t *)src - 64 + n);

	return ret;
}

static IRM_SOCK_ALWAYS_INLINE void* irm_fast_memcpy(void* dst,
    const void* src, size_t n)
{
	if (!(((uintptr_t)dst | (uintptr_t)src) & ALIGNMENT_MASK))
		return irm_fast_memcpy_aligned(dst, src, n);
	else
		return irm_fast_memcpy_generic(dst, src, n);
}

#ifdef __cplusplus
}
#endif

#endif

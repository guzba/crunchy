import common

## These functions are Nim conversions of an original implementation
## from the Chromium repository. That implementation is:
##
## Copyright 2017 The Chromium Authors. All rights reserved.
## Use of this source code is governed by a BSD-style license that can be
## found in the Chromium source repository LICENSE file.

const
  nmax = 5552
  blockSize = 32.uint32

when defined(release):
  {.push checks: off.}

when defined(amd64):
  import nimsimd/ssse3

  when defined(gcc) or defined(clang):
    {.localPassC: "-mssse3".}

  proc adler32_ssse3*(src: pointer, len: int): uint32 =
    if len <= 0:
      return 1

    if len.uint64 > uint32.high:
      raise newException(CrunchyError, "Adler-32 len > uint32.high")

    let src = cast[ptr UncheckedArray[uint8]](src)

    var
      pos: uint32
      remaining = cast[uint32](len)
      s1 = 1.uint32
      s2 = 0.uint32

    var blocks = remaining div blockSize

    remaining -= (blocks * blockSize)

    let
      tap1 = mm_setr_epi8(32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17)
      tap2 = mm_setr_epi8(16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)
      zero = mm_setzero_si128()
      ones = mm_set1_epi16(1)

    while blocks > 0:
      var n = nmax div blockSize
      if n > blocks:
        n = blocks

      blocks -= n

      var
        vecPs = mm_set_epi32(0, 0, 0, s1 * n)
        vecS2 = mm_set_epi32(0, 0, 0, s2)
        vecS1 = mm_set_epi32(0, 0, 0, 0)

      while n > 0:
        let
          bytes1 = mm_loadu_si128(src[pos + 0].addr)
          bytes2 = mm_loadu_si128(src[pos + 16].addr)

        vecPs = mm_add_epi32(vecPs, vecS1)

        vecS1 = mm_add_epi32(vecS1, mm_sad_epu8(bytes1, zero))
        let mad1 = mm_maddubs_epi16(bytes1, tap1)
        vecS2 = mm_add_epi32(vecS2, mm_madd_epi16(mad1, ones))
        vecS1 = mm_add_epi32(vecS1, mm_sad_epu8(bytes2, zero))
        let mad2 = mm_maddubs_epi16(bytes2, tap2)
        vecS2 = mm_add_epi32(vecS2, mm_madd_epi16(mad2, ones))

        dec n
        pos += 32

      vecS2 = mm_add_epi32(vecS2, mm_slli_epi32(vecPs, 5))

      vecS1 = mm_add_epi32(vecS1, mm_shuffle_epi32(vecS1, MM_SHUFFLE(2, 3, 0, 1)))
      vecS1 = mm_add_epi32(vecS1, mm_shuffle_epi32(vecS1, MM_SHUFFLE(1, 0, 3, 2)))
      s1 += cast[uint32](mm_cvtsi128_si32(vecS1))
      vecS2 = mm_add_epi32(vecS2, mm_shuffle_epi32(vecS2, MM_SHUFFLE(2, 3, 0, 1)))
      vecS2 = mm_add_epi32(vecS2, mm_shuffle_epi32(vecS2, MM_SHUFFLE(1, 0, 3, 2)))
      s2 = cast[uint32](mm_cvtsi128_si32(vecS2))

      s1 = s1 mod 65521
      s2 = s2 mod 65521

    for i in 0 ..< remaining:
      s1 += src[pos + i]
      s2 += s1

    s1 = s1 mod 65521
    s2 = s2 mod 65521

    result = (s2 shl 16) or s1

elif defined(arm64):
  import nimsimd/neon

  proc adler32_neon*(src: pointer, len: int): uint32 =
    if len <= 0:
      return 1

    if len.uint64 > uint32.high:
      raise newException(CrunchyError, "Adler-32 len > uint32.high")

    let src = cast[ptr UncheckedArray[uint8]](src)

    var
      pos: uint32
      remaining = cast[uint32](len)
      s1 = 1.uint32
      s2 = 0.uint32

    const blockSize = 32.uint32

    var blocks = remaining div blockSize

    remaining -= (blocks * blockSize)

    var wtf1, wtf2, wtf3, wtf4, wtf5, wtf6, wtf7, wtf8, wtf9: uint16x4
    block:
      var tmp = [32.uint16, 31, 30, 29]
      wtf1 = vld1_u16(tmp.addr)
      tmp = [28.uint16, 27, 26, 25]
      wtf2 = vld1_u16(tmp.addr)
      tmp = [24.uint16, 23, 22, 21]
      wtf3 = vld1_u16(tmp.addr)
      tmp = [20.uint16, 19, 18, 17]
      wtf4 = vld1_u16(tmp.addr)
      tmp = [16.uint16, 15, 14, 13]
      wtf5 = vld1_u16(tmp.addr)
      tmp = [12.uint16, 11, 10, 9]
      wtf6 = vld1_u16(tmp.addr)
      tmp = [8.uint16, 7, 6, 5]
      wtf7 = vld1_u16(tmp.addr)
      tmp = [4.uint16, 3, 2, 1]
      wtf8 = vld1_u16(tmp.addr)

    while blocks > 0:
      var n = nmax div blockSize
      if n > blocks:
        n = blocks

      blocks -= n
      var
        vecS2 = vmovq_n_u32(0)
        vecS1 = vmovq_n_u32(0)
        vecColumnSum1 = vmovq_n_u16(0)
        vecColumnSum2 = vmovq_n_u16(0)
        vecColumnSum3 = vmovq_n_u16(0)
        vecColumnSum4 = vmovq_n_u16(0)
      block:
        var tmp = s1 * n
        vecS2 = vld1q_lane_u32(tmp.addr, vecS2, 0)

      while n > 0:
        let
          bytes1 = vld1q_u8(src[pos + 0].addr)
          bytes2 = vld1q_u8(src[pos + 16].addr)
        vecS2 = vaddq_u32(vecS2, vecS1)
        vecS1 = vpadalq_u16(vecS1, vpadalq_u8(vpaddlq_u8(bytes1), bytes2))
        vecColumnSum1 = vaddw_u8(vecColumnSum1, vget_low_u8(bytes1))
        vecColumnSum2 = vaddw_u8(vecColumnSum2, vget_high_u8(bytes1))
        vecColumnSum3 = vaddw_u8(vecColumnSum3, vget_low_u8(bytes2))
        vecColumnSum4 = vaddw_u8(vecColumnSum4, vget_high_u8(bytes2))
        dec n
        pos += 32

      vecS2 = vshlq_n_u32(vecS2, 5)

      vecS2 = vmlal_u16(vecS2, vget_low_u16(vecColumnSum1), wtf1)
      vecS2 = vmlal_u16(vecS2, vget_high_u16(vecColumnSum1), wtf2)
      vecS2 = vmlal_u16(vecS2, vget_low_u16(vecColumnSum2), wtf3)
      vecS2 = vmlal_u16(vecS2, vget_high_u16(vecColumnSum2), wtf4)
      vecS2 = vmlal_u16(vecS2, vget_low_u16(vecColumnSum3), wtf5)
      vecS2 = vmlal_u16(vecS2, vget_high_u16(vecColumnSum3), wtf6)
      vecS2 = vmlal_u16(vecS2, vget_low_u16(vecColumnSum4), wtf7)
      vecS2 = vmlal_u16(vecS2, vget_high_u16(vecColumnSum4), wtf8)

      let
        sum1 = vpadd_u32(vget_low_u32(vecS1), vget_high_u32(vecS1))
        sum2 = vpadd_u32(vget_low_u32(vecS2), vget_high_u32(vecS2))
        s1s2 = vpadd_u32(sum1, sum2)

      s1 += vget_lane_u32(s1s2, 0)
      s2 += vget_lane_u32(s1s2, 1)

      s1 = s1 mod 65521
      s2 = s2 mod 65521

    for i in 0 ..< remaining:
      s1 += src[pos + i]
      s2 += s1

    s1 = s1 mod 65521
    s2 = s2 mod 65521

    result = (s2 shl 16) or s1

when defined(release):
  {.pop.}

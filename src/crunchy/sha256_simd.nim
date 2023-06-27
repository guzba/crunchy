when defined(release):
  {.push checks: off.}

when defined(amd64):
  import nimsimd/sse41

  when defined(gcc) or defined(clang):
    {.localPassC: "-msse4.1 -msha".}

  {.push header: "immintrin.h".}
  proc mm_sha256msg1_epu32(a, b: M128i): M128i {.importc: "_mm_sha256msg1_epu32".}
  proc mm_sha256msg2_epu32(a, b: M128i): M128i {.importc: "_mm_sha256msg2_epu32".}
  proc mm_sha256rnds2_epu32(a, b, k: M128i): M128i {.importc: "_mm_sha256rnds2_epu32".}
  {.pop.}

  template do64(
    state0, state1, tmp: var M128i,
    mask: M128i,
    src: ptr UncheckedArray[uint8],
    pos: var int
  ) =
    # Save current state
    let
      abefSave = state0
      cdghSave = state1

    var msg, msg0, msg1, msg2, msg3: M128i

    # Rounds 0-3
    msg = mm_loadu_si128(src[pos].addr)
    msg0 = mm_shuffle_epi8(msg, mask)
    msg = mm_add_epi32(msg0, mm_set_epi64x(0xE9B5DBA5B5C0FBCF, 0x71374491428A2F98))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)

    # Rounds 4-7
    msg1 = mm_loadu_si128(src[pos + 16].addr)
    msg1 = mm_shuffle_epi8(msg1, mask)
    msg = mm_add_epi32(msg1, mm_set_epi64x(0xAB1C5ED5923F82A4, 0x59F111F13956C25B))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg0 = mm_sha256msg1_epu32(msg0, msg1)

    # Rounds 8-11
    msg2 = mm_loadu_si128(src[pos + 32].addr)
    msg2 = mm_shuffle_epi8(msg2, mask)
    msg = mm_add_epi32(msg2, mm_set_epi64x(0x550C7DC3243185BE, 0x12835B01D807AA98))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg1 = mm_sha256msg1_epu32(msg1, msg2)

    # Rounds 12-15
    msg3 = mm_loadu_si128(src[pos + 48].addr)
    msg3 = mm_shuffle_epi8(msg3, mask)
    msg = mm_add_epi32(msg3, mm_set_epi64x(0xC19BF1749BDC06A7, 0x80DEB1FE72BE5D74))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg3, msg2, 4)
    msg0 = mm_add_epi32(msg0, tmp)
    msg0 = mm_sha256msg2_epu32(msg0, msg3)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg2 = mm_sha256msg1_epu32(msg2, msg3)

    # Rounds 16-19
    msg = mm_add_epi32(msg0, mm_set_epi64x(0x240CA1CC0FC19DC6, 0xEFBE4786E49B69C1))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg0, msg3, 4)
    msg1 = mm_add_epi32(msg1, tmp)
    msg1 = mm_sha256msg2_epu32(msg1, msg0)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg3 = mm_sha256msg1_epu32(msg3, msg0)

    # Rounds 20-23
    msg = mm_add_epi32(msg1, mm_set_epi64x(0x76F988DA5CB0A9DC, 0x4A7484AA2DE92C6F))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg1, msg0, 4)
    msg2 = mm_add_epi32(msg2, tmp)
    msg2 = mm_sha256msg2_epu32(msg2, msg1)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg0 = mm_sha256msg1_epu32(msg0, msg1)

    # Rounds 24-27
    msg = mm_add_epi32(msg2, mm_set_epi64x(0xBF597FC7B00327C8, 0xA831C66D983E5152))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg2, msg1, 4)
    msg3 = mm_add_epi32(msg3, tmp)
    msg3 = mm_sha256msg2_epu32(msg3, msg2)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg1 = mm_sha256msg1_epu32(msg1, msg2)

    # Rounds 28-31
    msg = mm_add_epi32(msg3, mm_set_epi64x(0x1429296706CA6351,  0xD5A79147C6E00BF3))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg3, msg2, 4)
    msg0 = mm_add_epi32(msg0, tmp)
    msg0 = mm_sha256msg2_epu32(msg0, msg3)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg2 = mm_sha256msg1_epu32(msg2, msg3)

    # Rounds 32-35
    msg = mm_add_epi32(msg0, mm_set_epi64x(0x53380D134D2C6DFC, 0x2E1B213827B70A85))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg0, msg3, 4)
    msg1 = mm_add_epi32(msg1, tmp)
    msg1 = mm_sha256msg2_epu32(msg1, msg0)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg3 = mm_sha256msg1_epu32(msg3, msg0)

    # Rounds 36-39
    msg = mm_add_epi32(msg1, mm_set_epi64x(0x92722C8581C2C92E, 0x766A0ABB650A7354))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg1, msg0, 4)
    msg2 = mm_add_epi32(msg2, tmp)
    msg2 = mm_sha256msg2_epu32(msg2, msg1)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg0 = mm_sha256msg1_epu32(msg0, msg1)

    # Rounds 40-43
    msg = mm_add_epi32(msg2, mm_set_epi64x(0xC76C51A3C24B8B70, 0xA81A664BA2BFE8A1))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg2, msg1, 4)
    msg3 = mm_add_epi32(msg3, tmp)
    msg3 = mm_sha256msg2_epu32(msg3, msg2)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg1 = mm_sha256msg1_epu32(msg1, msg2)

    # Rounds 44-47
    msg = mm_add_epi32(msg3, mm_set_epi64x(0x106AA070F40E3585, 0xD6990624D192E819))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg3, msg2, 4)
    msg0 = mm_add_epi32(msg0, tmp)
    msg0 = mm_sha256msg2_epu32(msg0, msg3)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg2 = mm_sha256msg1_epu32(msg2, msg3)

    # Rounds 48-51
    msg = mm_add_epi32(msg0, mm_set_epi64x(0x34B0BCB52748774C, 0x1E376C0819A4C116))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg0, msg3, 4)
    msg1 = mm_add_epi32(msg1, tmp)
    msg1 = mm_sha256msg2_epu32(msg1, msg0)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)
    msg3 = mm_sha256msg1_epu32(msg3, msg0)

    # Rounds 52-55
    msg = mm_add_epi32(msg1, mm_set_epi64x(0x682E6FF35B9CCA4F, 0x4ED8AA4A391C0CB3))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg1, msg0, 4)
    msg2 = mm_add_epi32(msg2, tmp)
    msg2 = mm_sha256msg2_epu32(msg2, msg1)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)

    # Rounds 56-59
    msg = mm_add_epi32(msg2, mm_set_epi64x(0x8CC7020884C87814, 0x78A5636F748F82EE))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    tmp = mm_alignr_epi8(msg2, msg1, 4)
    msg3 = mm_add_epi32(msg3, tmp)
    msg3 = mm_sha256msg2_epu32(msg3, msg2)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)

    # Rounds 60-63
    msg = mm_add_epi32(msg3, mm_set_epi64x(0xC67178F2BEF9A3F7, 0xA4506CEB90BEFFFA))
    state1 = mm_sha256rnds2_epu32(state1, state0, msg)
    msg = mm_shuffle_epi32(msg, 0x0E)
    state0 = mm_sha256rnds2_epu32(state0, state1, msg)

    # Combine state
    state0 = mm_add_epi32(state0, abefSave)
    state1 = mm_add_epi32(state1, cdghSave)

    pos += 64

  proc x64sha256*(
    state: var array[8, uint32],
    src1: ptr UncheckedArray[uint8],
    len1: int,
    src2: ptr UncheckedArray[uint8],
    len2: int
  ) =
    let mask = mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203)

    var
      tmp = mm_loadu_si128(state[0].addr)
      state1 = mm_loadu_si128(state[4].addr)

    tmp = mm_shuffle_epi32(tmp, 0xb1)
    state1 = mm_shuffle_epi32(state1, 0x1b)

    var state0 = mm_alignr_epi8(tmp, state1, 8)

    state1 = mm_blend_epi16(state1, tmp, 0xf0)

    var pos = 0
    for _ in 0 ..< len1 div 64:
      do64(state0, state1, tmp, mask, src1, pos)

    var pos2 = 0
    if len2 == 128: # 128 -> 64
      do64(state0, state1, tmp, mask, src2, pos2)

    # Last 64
    do64(state0, state1, tmp, mask, src2, pos2)

    tmp = mm_shuffle_epi32(state0, 0x1b)
    state1 = mm_shuffle_epi32(state1, 0xb1)
    state0 = mm_blend_epi16(tmp, state1, 0xf0)
    state1 = mm_alignr_epi8(state1, tmp, 8)

    mm_storeu_si128(state[0].addr, state0)
    mm_storeu_si128(state[4].addr, state1)

when defined(release):
  {.pop.}

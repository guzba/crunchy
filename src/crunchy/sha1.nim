import std/endians

when defined(clang):
  # Something is wrong with std/bitops + my Mac.
  # This is 10x faster in debug builds.
  func rotateLeftBits(value: uint32, shift: uint32): uint32
    {.importc: "__builtin_rotateleft32", nodecl.}
else:
  import std/bitops

when defined(release):
  {.push checks: off.}

template do64(
  src: ptr UncheckedArray[uint8],
  pos: var int,
  state: var array[5, uint32],
  w: var array[80, uint32]
) =
  # Copy 64 bytes (16 uint32) into w from data
  # This cannot just be a copyMem due to byte ordering
  for i in 0 ..< 16:
    var value: uint32
    swapEndian32(value.addr, src[pos + i * 4].addr)
    w[i] = value

  var
    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

  template fff(i: int, f, k: uint32) =
    let temp = rotateLeftBits(a, 5) + f + e + k + w[i]
    e = d
    d = c
    c = rotateLeftBits(b, 30)
    b = a
    a = temp

  for i in 0 ..< 16:
    let f = (b and c) or ((not b) and d)
    const k = 0x5A827999'u32
    fff(i, f, k)

  for i in 16 ..< 20:
    w[i] = rotateLeftBits((w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]), 1)
    let f = (b and c) or ((not b) and d)
    const k = 0x5A827999'u32
    fff(i, f, k)

  for i in 20 ..< 40:
    w[i] = rotateLeftBits((w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]), 1)
    let f = b xor c xor d
    const k = 0x6ED9EBA1'u32
    fff(i, f, k)

  for i in 40 ..< 60:
    w[i] = rotateLeftBits((w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]), 1)
    let f = (b and c) or (b and d) or (c and d)
    const k = 0x8F1BBCDC'u32
    fff(i, f, k)

  for i in 60 ..< 80:
    w[i] = rotateLeftBits((w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]), 1)
    let f = b xor c xor d
    const k = 0xCA62C1D6'u32
    fff(i, f, k)

  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e
  pos += 64

proc sha1*(src: pointer, len: int): array[20, uint8] =
  let src = cast[ptr UncheckedArray[uint8]](src)

  var
    len1 = len
    len2: int
    last128: array[128, uint8]
    L = len.uint64 * 8

  if len <= 55:
    len1 = 0
    len2 = 64
    if len > 0:
      copyMem(last128[0].addr, src[0].addr, len)
    last128[len] = 0b10000000
    swapEndian64(last128[56].addr, L.addr)
  elif len <= 119: # 56 <= len <= 119
    len1 = 0
    len2 = 128
    copyMem(last128[0].addr, src[0].addr, len)
    last128[len] = 0b10000000
    swapEndian64(last128[120].addr, L.addr)
  else: # len >= 120
    let m = len mod 64
    len1 = len - m
    if m <= 55:
      len2 = 64
      copyMem(last128[0].addr, src[len1].addr, m)
      last128[m] = 0b10000000
      swapEndian64(last128[56].addr, L.addr)
    else:
      len2 = 128
      copyMem(last128[0].addr, src[len1].addr, m)
      last128[m] = 0b10000000
      swapEndian64(last128[120].addr, L.addr)

  var state = [
    0x67452301'u32,
    0xEFCDAB89'u32,
    0x98BADCFE'u32,
    0x10325476'u32,
    0xC3D2E1F0'u32
  ]

  var
    pos: int
    w: array[80, uint32]
  for _ in 0 ..< len1 div 64:
    do64(src, pos, state, w)

  # Last 128 bytes
  var tmp = 0
  if len2 == 128:
    do64(cast[ptr UncheckedArray[uint8]](last128[0].addr), tmp, state, w)
  do64(cast[ptr UncheckedArray[uint8]](last128[0].addr), tmp, state, w)

  for i in 0 ..< state.len:
    swapEndian32(result[i * 4].addr, state[i].addr)

proc sha1*(data: openarray[byte]): array[20, uint8] {.inline.} =
  if data.len <= 0:
    sha1(nil, 0)
  else:
    sha1(data[0].unsafeAddr, data.len)

proc sha1*(data: string): array[20, uint8] {.inline.} =
  sha1(data.cstring, data.len)

when defined(release):
  {.pop.}

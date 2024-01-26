import common, internal, std/endians

when defined(clang):
  # Something is wrong with std/bitops + my Mac.
  # This is 10x faster in debug builds.
  func rotateRightBits(value: uint32, shift: uint32): uint32
    {.importc: "__builtin_rotateright32", nodecl.}
else:
  import std/bitops

const k = [
  0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
  0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
  0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
  0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
  0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
  0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
  0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
  0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
  0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
  0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
  0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
  0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
  0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
  0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
  0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
  0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
]

when allowSimd:
  import sha256_simd

  when defined(amd64):
    import nimsimd/runtimecheck

    let canUseIntrinsics = checkInstructionSets({SSE41, SHA})

when defined(release):
  {.push checks: off.}

template do64(
  src: ptr UncheckedArray[uint8],
  pos: var int,
  state: var array[8, uint32],
  w: var array[64, uint32]
) =
  # Copy 64 bytes (16 uint32) into w from data
  # This cannot just be a copyMem due to byte ordering
  for i in 0 ..< 16:
    var value: uint32
    swapEndian32(value.addr, src[pos + i * 4].addr)
    w[i] = value

  for i in 16 ..< 64:
    let
      s0 =
        rotateRightBits(w[i - 15], 7) xor
        rotateRightBits(w[i - 15], 18) xor
        (w[i - 15] shr 3)
      s1 =
        rotateRightBits(w[i - 2], 17) xor
        rotateRightBits(w[i - 2], 19) xor
        (w[i - 2] shr 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1

  var
    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]
    f = state[5]
    g = state[6]
    h = state[7]
  for i in 0 ..< 64:
    let
      S1 =
        rotateRightBits(e, 6) xor
        rotateRightBits(e, 11) xor
        rotateRightBits(e, 25)
      ch = (e and f) xor ((not e) and g)
      temp1 = h + S1 + ch + k[i] + w[i]
      S0 =
        rotateRightBits(a, 2) xor
        rotateRightBits(a, 13) xor
        rotateRightBits(a, 22)
      maj = (a and b) xor (a and c) xor (b and c)
      temp2 = S0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2

  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e
  state[5] += f
  state[6] += g
  state[7] += h
  pos += 64

proc sha256*(src: pointer, len: int): array[32, uint8] =
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
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  var usedIntrinsics: bool
  when allowSimd and defined(amd64):
    if canUseIntrinsics:
      let src2 = cast[ptr UncheckedArray[uint8]](last128[0].addr)
      x64sha256(state, src, len1, src2, len2)
      usedIntrinsics = true

  if not usedIntrinsics:
    # See https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
    var
      pos: int
      w: array[64, uint32]
    for _ in 0 ..< len1 div 64:
      do64(src, pos, state, w)

    # Last 128 bytes
    var tmp = 0
    if len2 == 128:
      do64(cast[ptr UncheckedArray[uint8]](last128[0].addr), tmp, state, w)
    do64(cast[ptr UncheckedArray[uint8]](last128[0].addr), tmp, state, w)

  for i in 0 ..< state.len:
    swapEndian32(result[i * 4].addr, state[i].addr)

proc sha256*(data: openarray[byte]): array[32, uint8] {.inline.} =
  if data.len <= 0:
    sha256(nil, 0)
  else:
    sha256(data[0].unsafeAddr, data.len)

proc sha256*(data: string): array[32, uint8] {.inline.} =
  sha256(data.cstring, data.len)

proc hmacSha256*(key, data: openarray[uint8]): array[32, uint8] =
  const
    blockSize = 64
    ipad = 0x36
    opad = 0x5c

  var blockSizeKey: array[blockSize, uint8]
  if key.len > blockSize:
    let hash = sha256(key)
    copyMem(blockSizeKey[0].addr, hash[0].unsafeAddr, hash.len)
  elif key.len > 0:
    copyMem(blockSizeKey[0].addr, key[0].unsafeAddr, key.len)

  proc applyXor(s: array[64, uint8], value: uint8): array[64, uint8] =
    result = s
    for c in result.mitems:
      c = (c xor value)

  let ipadXor = applyXor(blockSizeKey, ipad)

  let h1 =
    if data.len > 0:
      var s = newString(ipadXor.len + data.len)
      copyMem(s[0].addr, ipadXor[0].unsafeAddr, ipadXor.len)
      copyMem(s[ipadXor.len].addr, data[0].unsafeAddr, data.len)
      sha256(s)
    else:
      sha256(ipadXor)

  let opadXor = applyXor(blockSizeKey, opad)

  var s2 = newString(opadXor.len + 32)
  copyMem(s2[0].addr, opadXor[0].unsafeAddr, opadXor.len)
  copyMem(s2[opadXor.len].addr, h1[0].unsafeAddr, 32)

  sha256(s2)

proc hmacSha256*(
  key, data: string
): array[32, uint8] {.inline.} =
  hmacSha256(
    key.toOpenArrayByte(0, key.high),
    data.toOpenArrayByte(0, data.high)
  )

proc hmacSha256*(
  key: string,
  data: openarray[byte]
): array[32, uint8] {.inline.} =
  hmacSha256(
    key.toOpenArrayByte(0, key.high),
    data
  )

proc hmacSha256*(
  key: openarray[byte],
  data: string
): array[32, uint8] {.inline.} =
  hmacSha256(
    key,
    data.toOpenArrayByte(0, data.high)
  )

proc pbkdf2*(password, salt: string, iterations: int): array[32, uint8] =
  ## PBKDF2-HMAC-SHA256

  if iterations < 1:
    raise newException(CrunchyError, "Invalid number of iterations")

  result = hmacSha256(password, salt & "\0\0\0\1")

  var
    buf1 = result
    buf2: array[32, uint8]
  for _ in 1 ..< iterations:
    swap(buf1, buf2)
    buf1 = hmacSha256(password, buf2)
    for i in 0 ..< 32:
      result[i] = result[i] xor buf1[i]

when defined(release):
  {.pop.}

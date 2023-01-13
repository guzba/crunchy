import internal, std/bitops, std/endians, std/strutils

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

proc sha256*(src: pointer, len: int): array[32, uint8] =
  # This needs a pointer + len implementation that avoids copying the input
  var data2: string
  if len > 0:
    data2.setLen(len)
    copyMem(data2[0].addr, src, len)

  data2.add 0b10000000.char
  while data2.len mod 64 != 56:
    data2.add 0.char
  data2.setLen(data2.len + 8)
  var L = len.uint64 * 8
  swapEndian64(data2[data2.len - 8].addr, L.addr)

  var state = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]

  var usedIntrinsics: bool
  when allowSimd and defined(amd64):
    if canUseIntrinsics:
      x64sha256(state, data2)
      usedIntrinsics = true

  if not usedIntrinsics:
    # See https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
    var
      pos: int
      w: array[64, uint32]
    for _ in 0 ..< data2.len div 64:
      # Copy 64 bytes (16 uint32) into w from data
      # This cannot just be a copyMem due to byte ordering
      for i in 0 ..< 16:
        var value: uint32
        swapEndian32(value.addr, data2[pos + i * 4].addr)
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

  for i in 0 ..< state.len:
    swapEndian32(result[i * 4].addr, state[i].addr)

proc sha256*(data: openarray[byte]): array[32, uint8] {.inline.} =
  if data.len <= 0:
    sha256(nil, 0)
  else:
    sha256(data[0].unsafeAddr, data.len)

proc sha256*(data: string): array[32, uint8] {.inline.} =
  sha256(data.cstring, data.len)

proc toHex*(a: array[32, uint8]): string =
  result = newStringOfCap(64)
  for i in 0 ..< a.len:
    result.add toHex(a[i], 2)
  result = result.toLowerAscii()

when defined(release):
  {.pop.}

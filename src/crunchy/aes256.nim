import std/bitops, std/endians

# Helpful: https://blog.nindalf.com/posts/implementing-aes/

const
  Rcon = [0x0'u8, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
  SBox = [
    [0x63'u8, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca'u8, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7'u8, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04'u8, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09'u8, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53'u8, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0'u8, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51'u8, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd'u8, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60'u8, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0'u8, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7'u8, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba'u8, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70'u8, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1'u8, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c'u8, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
  ]
  # InvSBox = [
  #   [0x52'u8, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
  #   [0x7c'u8, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
  #   [0x54'u8, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
  #   [0x08'u8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
  #   [0x72'u8, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
  #   [0x6c'u8, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
  #   [0x90'u8, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
  #   [0xd0'u8, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
  #   [0x3a'u8, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
  #   [0x96'u8, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
  #   [0x47'u8, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
  #   [0xfc'u8, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
  #   [0x1f'u8, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
  #   [0x60'u8, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
  #   [0xa0'u8, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
  #   [0x17'u8, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
  # ]

when defined(release):
  {.push checks: off.}

proc subWord(value: uint32): uint32 =
  var a = cast[array[4, uint8]](value)
  for i in 0 ..< 4:
    a[i] = SBox[a[i] shr 4][(a[i] and 0x0f)]
  cast[uint32](a)

proc rotWord(value: uint32): uint32 {.inline.} =
  rotateRightBits(value, 8)

proc keyExpansion(key: array[32, uint8]): array[60, uint32] =
  for i in 0 ..< 8:
    copyMem(result[i].addr, key[i * 4].unsafeAddr, 4)

  for i in 8 ..< 60:
    var tmp: uint32
    if i mod 8 == 0:
      tmp = subWord(rotWord(result[i - 1])) xor Rcon[i div 8]
    elif i mod 8 == 4:
      tmp = subWord(result[i - 1])
    else:
      tmp = result[i - 1]
    result[i] = result[i - 8] xor tmp

proc addRoundKey(state: pointer, keys: pointer) =
  let
    state = cast[ptr array[4, array[4, uint8]]](state)
    keys = cast[ptr array[4, array[4, uint8]]](keys)
  for i in 0 ..< 4:
    for j in 0 ..< 4:
      state[i][j] = state[i][j] xor keys[j][i]

proc subBytes(state: pointer) =
  let state = cast[ptr array[4, array[4, uint8]]](state)
  for i in 0 ..< 4:
    for j in 0 ..< 4:
      state[i][j] = SBox[(state[i][j] and 0xf0) shr 4][(state[i][j] and 0x0f)]

# proc invSubBytes(state: var array[4, uint32]) =
#   var s: array[4, array[4, uint8]]
#   copyMem(s[0].addr, state[0].addr, 16)
#   for i in 0 ..< 4:
#     for j in 0 ..< 4:
#       s[i][j] = InvSBox[(s[i][j] and 0xf0) shr 4][(s[i][j] and 0x0f)]
#   copyMem(state[0].addr, s[0].addr, 16)

proc shiftRows(state: var array[4, uint32]) =
  state[1] = rotateRightBits(state[1], 8)
  state[2] = rotateRightBits(state[2], 16)
  state[3] = rotateRightBits(state[3], 24)

# proc invShiftRows(state: var array[4, uint32]) =
#   state[1] = rotateRightBits(state[1], 24)
#   state[2] = rotateRightBits(state[2], 16)
#   state[3] = rotateRightBits(state[3], 8)

proc gf(a, b: uint8): uint8 =
  var
    a = a
    b = b
  for i in 0 ..< 8:
    if (b and 1) != 0:
      result = result xor a
    let highBitSet = (a and 0x80) != 0
    a  = a shl 1
    if highBitSet:
      a = a xor 0x1b
    b = b shr 1

proc mixColumns(state: pointer) =
  let state = cast[ptr array[4, array[4, uint8]]](state)
  var tmp: array[4, array[4, uint8]]
  copyMem(tmp[0].addr, state[0].addr, 16)
  for c in 0 ..< 4:
    state[0][c] = gf(0x02, tmp[0][c]) xor gf(0x03, tmp[1][c]) xor tmp[2][c] xor tmp[3][c]
    state[1][c] = tmp[0][c] xor gf(0x02, tmp[1][c]) xor gf(0x03, tmp[2][c]) xor tmp[3][c]
    state[2][c] = tmp[0][c] xor tmp[1][c] xor gf(0x02, tmp[2][c]) xor gf(0x03, tmp[3][c])
    state[3][c] = gf(0x03, tmp[0][c]) xor tmp[1][c] xor tmp[2][c] xor gf(0x02, tmp[3][c])

# proc invMixColumns(state: var array[4, uint32]) =
#   let s = cast[array[4, array[4, uint8]]](state)
#   var tmp: array[4, array[4, uint8]]
#   for c in 0 ..< 4:
#     tmp[0][c] = gf(14, s[0][c]) xor gf(11, s[1][c]) xor gf(13, s[2][c]) xor gf(9, s[3][c])
#     tmp[1][c] = gf(9, s[0][c]) xor gf(14, s[1][c]) xor gf(11, s[2][c]) xor gf(13, s[3][c])
#     tmp[2][c] = gf(13, s[0][c]) xor gf(9, s[1][c]) xor gf(14, s[2][c]) xor gf(11, s[3][c])
#     tmp[3][c] = gf(11, s[0][c]) xor gf(13, s[1][c]) xor gf(9, s[2][c]) xor gf(14, s[3][c])
#   state = cast[array[4, uint32]](tmp)

proc aes256EncryptBlock(
  roundKeys: array[60, uint32],
  src: pointer
): array[16, uint8] =
  var rowMajor: array[4, array[4, uint8]]
  copyMem(rowMajor[0].addr, src, 16)

  var columnMajor: array[4, array[4, uint8]]
  for c in 0 ..< 4:
    columnMajor[c][0] = rowMajor[0][c]
    columnMajor[c][1] = rowMajor[1][c]
    columnMajor[c][2] = rowMajor[2][c]
    columnMajor[c][3] = rowMajor[3][c]

  var state = cast[array[4, uint32]](columnMajor)

  addRoundKey(state[0].addr, roundKeys[0].unsafeAddr)

  for round in 1 ..< 14:
    subBytes(state[0].addr)
    shiftRows(state)
    mixColumns(state[0].addr)
    addRoundKey(state[0].addr, roundKeys[round * 4].unsafeAddr)

  subBytes(state[0].addr)
  shiftRows(state)
  addRoundKey(state[0].addr, roundKeys[56].unsafeAddr)

  rowMajor = cast[array[4, array[4, uint8]]](state)

  for i in 0 ..< 4:
    for j in 0 ..< 4:
      result[i * 4 + j] = rowMajor[j][i]

# proc aes256DecryptBlock(
#   roundKeys: array[60, uint32],
#   src: pointer
# ): array[16, uint8] =
#   var rowMajor: array[4, array[4, uint8]]
#   copyMem(rowMajor[0].addr, src, 16)

#   var columnMajor: array[4, array[4, uint8]]
#   for c in 0 ..< 4:
#     columnMajor[c][0] = rowMajor[0][c]
#     columnMajor[c][1] = rowMajor[1][c]
#     columnMajor[c][2] = rowMajor[2][c]
#     columnMajor[c][3] = rowMajor[3][c]

#   var state = cast[array[4, uint32]](columnMajor)

#   addRoundKey(state, roundKeys, 56)

#   for round in 1 ..< 14:
#     invShiftRows(state)
#     invSubBytes(state)
#     addRoundKey(state, roundKeys, 60 - ((round + 1) * 4))
#     invMixColumns(state)

#   invShiftRows(state)
#   invSubBytes(state)
#   addRoundKey(state, roundKeys, 0)

#   for c in 0 ..< 4:
#     var word: array[4, uint8]
#     word[0] = cast[array[4, array[4, uint8]]](state)[0][c]
#     word[1] = cast[array[4, array[4, uint8]]](state)[1][c]
#     word[2] = cast[array[4, array[4, uint8]]](state)[2][c]
#     word[3] = cast[array[4, array[4, uint8]]](state)[3][c]
#     copyMem(result[c * 4].addr, word.addr, 4)

proc ghash(h: array[16, uint8], asdf: string): array[16, uint8] =

  proc rightShift(a: array[16, uint8]): array[16, uint8] =
    var prev: uint8
    for i in 0 ..< 16:
      let v = a[i]
      result[i] = v shr 1
      if (prev and 1) != 0:
        result[i] = result[i] or 0b10000000
      prev = v

  proc `xor`(a, b: array[16, uint8]): array[16, uint8] =
    for i in 0 ..< 16:
      result[i] = a[i] xor b[i]

  proc `*`(a, b: array[16, uint8]): array[16, uint8] =
    const R = [
      0xe1'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8,
      0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8
    ]
    var tmp = b
    for i in 0 ..< 16:
      for j in countdown(7, 0):
        if (a[i] and (1.uint8 shl j)) != 0:
          result = result xor tmp
        if (tmp[15] and 1) != 0:
          tmp = tmp.rightShift() xor R
        else:
          tmp = tmp.rightShift()

  var pos: int
  while pos < asdf.len:
    var tmp: array[16, uint8]
    copyMem(tmp[0].addr, asdf[pos].unsafeAddr, 16)
    result = (result xor tmp) * h
    pos += 16

proc aes256gcmEncrypt*(
  key: array[32, uint8],
  iv: array[12, uint8],
  plaintext: string
): (string, array[16, uint8]) =
  var encrypted = newString(plaintext.len)

  let roundKeys = keyExpansion(key)

  var h: array[16, uint8]
  h = aes256EncryptBlock(roundKeys, h[0].addr)

  var ivAndCounter: array[4, uint32]
  copyMem(ivAndCounter[0].addr, iv[0].unsafeAddr, 12)

  var counter = 1.uint32
  bigEndian32(ivAndCounter[3].addr, counter.addr)

  let eky0 = aes256EncryptBlock(roundKeys, ivAndCounter[0].addr)

  inc counter
  bigEndian32(ivAndCounter[3].addr, counter.addr)

  var pos: int
  while pos + 16 <= plaintext.len:
    let tmp = aes256EncryptBlock(roundKeys, ivAndCounter[0].addr)

    for i in 0 ..< 16:
      encrypted[pos + i] = (plaintext[pos + i].uint8 xor tmp[i]).char

    pos += 16
    inc counter
    bigEndian32(ivAndCounter[3].addr, counter.addr)

  if pos < plaintext.len:
    let tmp = aes256EncryptBlock(roundKeys, ivAndCounter[0].addr)

    for i in 0 ..< plaintext.len - pos:
      encrypted[pos + i] = (plaintext[pos + i].uint8 xor tmp[i]).char

  var asdfLen = 16 + encrypted.len + 4 + 4 + 8
  if encrypted.len mod 16 != 0:
    asdfLen += 16 - encrypted.len mod 16

  var asdf = newString(asdfLen)
  copyMem(asdf[16].addr, encrypted[0].addr, encrypted.len)

  var encryptedBits = encrypted.len * 8
  bigEndian64(asdf[asdfLen - 8].addr, encryptedBits.addr)

  let whatever = ghash(h, asdf)

  var tag: array[16, uint8]
  for i in 0 ..< 16:
    tag[i] = whatever[i] xor eky0[i]

  (move encrypted, tag)

proc aes256gcmDecrypt*(
  key: array[32, uint8],
  iv: array[12, uint8],
  encrypted: string
): (string, array[16, uint8]) =
  var decrypted = newString(encrypted.len)

  let roundKeys = keyExpansion(key)

  var h: array[16, uint8]
  h = aes256EncryptBlock(roundKeys, h[0].addr)

  var ivAndCounter: array[4, uint32]
  copyMem(ivAndCounter[0].addr, iv[0].unsafeAddr, 12)

  var counter = 1.uint32
  bigEndian32(ivAndCounter[3].addr, counter.addr)

  let eky0 = aes256EncryptBlock(roundKeys, ivAndCounter[0].addr)

  inc counter
  bigEndian32(ivAndCounter[3].addr, counter.addr)

  var pos: int
  while pos + 16 <= encrypted.len:
    let tmp = aes256EncryptBlock(roundKeys, ivAndCounter[0].addr)

    for i in 0 ..< 16:
      decrypted[pos + i] = (encrypted[pos + i].uint8 xor tmp[i]).char

    pos += 16
    inc counter
    bigEndian32(ivAndCounter[3].addr, counter.addr)

  if pos < encrypted.len:
    let tmp = aes256EncryptBlock(roundKeys, ivAndCounter[0].addr)

    for i in 0 ..< encrypted.len - pos:
      decrypted[pos + i] = (encrypted[pos + i].uint8 xor tmp[i]).char

  var asdfLen = 16 + encrypted.len + 4 + 4 + 8
  if encrypted.len mod 16 != 0:
    asdfLen += 16 - encrypted.len mod 16

  var asdf = newString(asdfLen)
  copyMem(asdf[16].addr, encrypted[0].unsafeAddr, encrypted.len)

  var encryptedBits = encrypted.len * 8
  bigEndian64(asdf[asdfLen - 8].addr, encryptedBits.addr)

  let whatever = ghash(h, asdf)

  var tag: array[16, uint8]
  for i in 0 ..< 16:
    tag[i] = whatever[i] xor eky0[i]

  (move decrypted, tag)

when defined(release):
  {.pop.}

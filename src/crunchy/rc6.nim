import common, std/bitops

when defined(release):
  {.push checks: off.}

proc makeKeySchedule(key: array[32, uint8]): array[44, uint32] =
  var L = cast[array[8, uint32]](key)

  result[0] = 0xb7e15163'u32

  for i in 1 ..< 44:
    result[i] = result[i - 1] + 0x9e3779b9'u32

  var A, B, i, j: uint32
  for _ in 1 .. 132:
    A = rotateLeftBits((result[i] + A + B), 3)
    result[i] = A
    B = rotateLeftBits((L[j] + A + B), (A + B) mod 32)
    L[j] = B
    i = (i + 1) mod 44
    j = (j + 1) mod 8

proc rc6EncryptBlock(S: array[44, uint32], src: pointer): array[16, uint8] =
  let src = cast[ptr UncheckedArray[uint8]](src)

  var A, B, C, D: uint32
  copyMem(A.addr, src[0].addr, 4)
  copyMem(B.addr, src[4].addr, 4)
  copyMem(C.addr, src[8].addr, 4)
  copyMem(D.addr, src[12].addr, 4)

  B = B + S[0]
  D = D + S[1]
  for i in 1 .. 20:
    let
      t = rotateLeftBits((B * (2 * B + 1)), 5)
      u = rotateLeftBits((D * (2 * D + 1)), 5)
    A = rotateLeftBits((A xor t), u mod 32) + S[2 * i]
    C = rotateLeftBits((C xor u), t mod 32) + S[2 * i + 1]
    (A, B, C, D) = (B, C, D, A)
  A = A + S[42]
  C = C + S[43]

  return cast[array[16, uint8]]([A, B, C, D])

proc rc6DecryptBlock(S: array[44, uint32], src: pointer): array[16, uint8] =
  let src = cast[ptr UncheckedArray[uint8]](src)

  var A, B, C, D: uint32
  copyMem(A.addr, src[0].addr, 4)
  copyMem(B.addr, src[4].addr, 4)
  copyMem(C.addr, src[8].addr, 4)
  copyMem(D.addr, src[12].addr, 4)

  C = C - S[43]
  A = A - S[42]
  for i in countdown(20, 1):
    (A, B, C, D) = (D, A, B, C)
    let
      u = rotateLeftBits((D * (2 * D + 1)), 5)
      t = rotateLeftBits((B * (2 * B + 1)), 5)
    C = rotateRightBits((C - S[2 * i + 1]), t mod 32) xor u
    A = rotateRightBits((A - S[2 * i]), u mod 32) xor t
  D = D - S[1]
  B = B - S[0]

  return cast[array[16, uint8]]([A, B, C, D])

proc rc6cbcEncrypt*(
  key: array[32, uint8],
  iv: array[16, uint8],
  plaintext: string
): string =
  ## Encrypts the plaintext input using RC6-CBC with PKCS #7 padding.
  ## Consider using PBKDF2 from crunchy/sha256 to generate a key from a password.
  let
    padding = 16 - (plaintext.len mod 16)
    S = makeKeySchedule(key)

  result.setLen(plaintext.len + padding)

  var
    plaintextBlock: array[16, uint8]
    ciphertextBlock = iv

  var pos: int
  while pos + 16 <= plaintext.len:
    copyMem(plaintextBlock[0].addr, plaintext[pos].unsafeAddr, 16)
    for i in 0 ..< 16:
      plaintextBlock[i] = plaintextBlock[i] xor ciphertextBlock[i]
    ciphertextBlock = rc6EncryptBlock(S, plaintextBlock[0].addr)
    copyMem(result[pos].addr, ciphertextBlock[0].unsafeAddr, 16)
    pos += 16

  if pos < plaintext.len:
    copyMem(
      plaintextBlock[0].addr,
      plaintext[pos].unsafeAddr,
      plaintext.len - pos
    )
  for i in plaintext.len - pos ..< 16:
    plaintextBlock[i] = padding.uint8

  for i in 0 ..< 16:
    plaintextBlock[i] = plaintextBlock[i] xor ciphertextBlock[i]

  let encrypted = rc6EncryptBlock(S, plaintextBlock[0].addr)
  copyMem(result[pos].addr, encrypted[0].unsafeAddr, 16)

proc rc6cbcDecrypt*(
  key: array[32, uint8],
  iv: array[16, uint8],
  encrypted: string
): string =
  ## Returns the decrypted data. Expects PKCS #7 padding.
  if encrypted.len mod 16 != 0:
    raise newException(
      CrunchyError,
      "Invalid encrypted input, len must be a multiple of 16"
    )

  result.setLen(encrypted.len)

  let S = makeKeySchedule(key)

  var
    plaintextBlock: array[16, uint8]
    prevCiphertextBlock = iv

  var pos: int
  while pos < encrypted.len:
    plaintextBlock = rc6DecryptBlock(S, encrypted[pos].unsafeAddr)
    for i in 0 ..< 16:
      plaintextBlock[i] = plaintextBlock[i] xor prevCiphertextBlock[i]
    copyMem(prevCiphertextBlock[0].addr, encrypted[pos].unsafeAddr, 16)
    copyMem(result[pos].addr, plaintextBlock[0].addr, 16)
    pos += 16

  let padding = result[^1].int
  result.setLen(result.len - padding)

when defined(release):
  {.pop.}

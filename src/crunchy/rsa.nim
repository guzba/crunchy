import bigints, common, sha256, std/base64, std/strutils

export bigints

type RsaPrivateKey* = object
  size*: int ## In bits, eg 1024, 2048, 4096
  n*, e*, d*, p*, q*, e1*, e2*, coef*: BigInt

proc sign*(pk: RsaPrivateKey, message: string): string =
  ## RSASSA-PKCS1-v1_5 using SHA-256

  const oid =
    "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

  let hash = sha256(message)

  var padded: string

  case pk.size:
  of 1024:
    padded.setLen(128)
  of 2048:
    padded.setLen(256)
  of 4096:
    padded.setLen(512)
  else:
    raise newException(CrunchyError, "Unexpected RSA key size: " & $pk.size)

  padded[1] = 1.char

  for i in 2 ..< padded.len - 32 - oid.len - 1:
    padded[i] = 0xff.char

  let oidStart = padded.len - 32 - oid.len
  for i in 0 ..< oid.len:
    padded[oidStart + i] = oid[i]

  copyMem(padded[padded.len - 32].addr, hash[0].unsafeAddr, 32)

  let
    c = initBigInt(padded.toHex(), base = 16)
    # CRT
    pq = pk.p * pk.q
    m1 = c.powmod(pk.e1, pk.p)
    m2 = c.powmod(pk.e2, pk.q)
    h = (pk.coef * (m1 - m2)) mod pk.p
    m = (m2 + (h * pk.q)) mod pq

  # Without CRT
  # let m = c.powmod(pk.d, pk.n)

  # Temporary fix for bigints toString(16) producing undesirable hex output
  var hex = m.toString(16)
  case pk.size:
  of 1024:
    if hex.len < 256:
      var prefix = newString(256 - hex.len)
      for i in 0 ..< prefix.len:
        prefix[i] = '0'
      hex = prefix & hex
  of 2048:
    if hex.len < 512:
      var prefix = newString(512 - hex.len)
      for i in 0 ..< prefix.len:
        prefix[i] = '0'
      hex = prefix & hex
  of 4096:
    if hex.len < 1024:
      var prefix = newString(1024 - hex.len)
      for i in 0 ..< prefix.len:
        prefix[i] = '0'
      hex = prefix & hex
  else:
    discard

  return parseHexStr(hex)

template raisePrivateKeyError() =
  raise newException(CrunchyError, "RSA private key data appears invalid")

proc decodeLength(buf: string, pos: var int): int =
  # https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
  if (buf[pos].uint8 and 0b10000000) != 0:
    let numBytes = (buf[pos].uint8 and 0b01111111).int
    inc pos
    if pos + numBytes > buf.len or  numBytes > 4:
      raisePrivateKeyError()
    for _ in 0 ..< numBytes:
      result = (result shl 8) or buf[pos].int
      inc pos
  else:
    result = buf[pos].int
    inc pos

proc decodeBigInt(buf: string, pos: var int): BigInt =
  let len = decodeLength(buf, pos)
  if pos + len > buf.len:
    raisePrivateKeyError()
  result = initBigInt(buf[pos ..< pos + len].toHex(), base = 16)
  pos += len

proc skipToPrivateKeyValues(buf: string, pos: var int) =
  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x30.char:
    raisePrivateKeyError()
  inc pos

  discard decodeLength(buf, pos)

  if pos + 5 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  if buf[pos] != 0x01.char:
    raisePrivateKeyError()
  inc pos

  if buf[pos] != 0x00.char:
    raisePrivateKeyError()
  inc pos

  # This is PKCS#8 format, skip past the header
  if buf[pos] == 0x30.char:
    inc pos

    discard decodeLength(buf, pos)

    if pos + 2 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x06.char:
      raisePrivateKeyError()
    inc pos

    # https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier

    let oidLen = decodeLength(buf, pos)

    if pos + oidLen > buf.len:
      raisePrivateKeyError()

    pos += oidLen

    if pos + 4 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x05.char:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x00.char:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x04.char:
      raisePrivateKeyError()
    inc pos

    discard decodeLength(buf, pos)

    if pos + 2 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x30.char:
      raisePrivateKeyError()
    inc pos

    discard decodeLength(buf, pos)

    if pos + 3 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x02.char:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x01.char:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x00.char:
      raisePrivateKeyError()
    inc pos

proc decodePrivateKey*(s: string): RsaPrivateKey =
  var lines = s.split('\n')

  # Ignore any newlines at the end of the key
  if lines[lines.high] == "":
    discard lines.pop()

  # Ignore any newlines before the start of the key
  while lines.len > 0:
    if lines[0] == "":
      lines.delete(0)
    else:
      break

  if lines.len == 0:
    raisePrivateKeyError()

  if lines[0].startsWith('-'):
    # Trim off -----BEGIN RSA PRIVATE KEY-----, -----END RSA PRIVATE KEY-----
    lines = lines[1 ..< ^1]

  let buf = decode(lines.join())

  var pos: int
  skipToPrivateKeyValues(buf, pos)

  # PKCS#1 private key values start here

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  block:
    let
      tmp = pos
      len = decodeLength(buf, pos)
    pos = tmp
    result.size = ((len div 8) * 8) * 8
    result.n = decodeBigInt(buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  result.e = decodeBigInt(buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  result.d = decodeBigInt(buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  result.p = decodeBigInt(buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  result.q = decodeBigInt(buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  result.e1 = decodeBigInt(buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  result.e2 = decodeBigInt(buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02.char:
    raisePrivateKeyError()
  inc pos

  result.coef = decodeBigInt(buf, pos)

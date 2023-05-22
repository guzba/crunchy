# Constantine
# Copyright (c) 2018-2019    Status Research & Development GmbH
# Copyright (c) 2020-Present Mamy André-Ratsimbazafy
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This is a support file for signing with an RSA private key
# Constantine high-level API is not designed yet for RSA hence it uses
# low-level primitives.
# Internals may change (i.e. directories may be renamed).
# It is recommended to vendor constantine and fix a git commit.
#
# File is provided as-is in hope it will be useful. No warranty, it may eat your dog.

import
  constantine/math/arithmetic/limbs_unsaturated, # TODO: move SignedSecretWord to constantine/platforms/constant_time
  constantine/math/arithmetic/[bigints, bigints_montgomery, limbs_montgomery],
  constantine/math/config/precompute,
  constantine/math/io/io_bigints,
  constantine/platforms/abstractions,
  constantine/hashes

from std/base64 import nil # unfortunately no encode function, and signature is public so ¯\_(ツ)_/¯

# No exceptions allowed
{.push raises:[], checks:off.}

# TODO: create a SecretMask type with value 0 or -1

template ssw(a: auto): SignedSecretWord = SignedSecretWord(a)

func isInRangeMask(val, lo, hi: SignedSecretWord): SignedSecretWord =
  ## Produce 0b11111111 mask if lo <= val <= hi (inclusive range)
  ## and 0b00000000 otherwise
  let loInvMask = isNegMask(val-lo) # if val-lo < 0 => val < lo
  let hiInvMask = isNegMask(hi-val) # if hi-val < 0 => val > hi
  return not(loInvMask or hiInvMask)

func base64_decode(
       dst: var openArray[byte],
       src: openArray[char]): int =
  ## Decode a Base64 string/bytearray input into
  ## an octet string
  ## This procedure is constant-time, except for new lines, padding and invalid base64 characters
  ##
  ## Returns -1 if the buffer is too small
  ## or the number of bytes written.
  ## Bytes are written from the start of the buffer
  var s, d = 0
  var vals: array[4, SecretWord]
  var bytes: array[3, byte]

  while s < src.len and d < dst.len:
    var padding = ssw 0

    for i in 0 ..< 4:
      const OOR = ssw 256        # Push chars out-of-range

      var c = ssw(src[s]) + OOR
      s += 1

      # 'A' -> 'Z' maps to [0, 26)
      c.csub(OOR + ssw('A'),          c.isInRangeMask(ssw('A') + OOR, ssw('Z') + OOR))
      # 'a' -> 'z' maps to [26, 52)
      c.csub(OOR + ssw('a') - ssw 26, c.isInRangeMask(ssw('a') + OOR, ssw('z') + OOR))
      # '0' -> '9' maps to [52, 61)
      c.csub(OOR + ssw('0') - ssw 52, c.isInRangeMask(ssw('0') + OOR, ssw('9') + OOR))
      # '+' maps to 62
      c.csub(OOR + ssw('+') - ssw 62, c.isInRangeMask(ssw('+') + OOR, ssw('+') + OOR))
      # '/' maps to 63
      c.csub(OOR + ssw('/') - ssw 63, c.isInRangeMask(ssw('/') + OOR, ssw('/') + OOR))
      # '=' is padding and everything else is ignored
      padding.cadd(ssw 1, c.isInRangeMask(ssw('=') + OOR, ssw('=') + OOR))

      # https://www.rfc-editor.org/rfc/rfc7468#section-2
      # "Furthermore, parsers SHOULD ignore whitespace and other non-
      #  base64 characters and MUST handle different newline conventions."
      #
      # Unfortunately, there is no way to deal with newlines, padding and invalid characters
      # without revealing that they exist when we do not increment the destination index
      if c.int >= OOR.int:
        continue

      vals[i] = SecretWord(c)

    bytes[0] = byte((vals[0] shl 2) or (vals[1] shr 4))
    bytes[1] = byte((vals[1] shl 4) or (vals[2] shr 2))
    bytes[2] = byte((vals[2] shl 6) or  vals[3]       )


    for i in 0 ..< 3 - padding.int:
      if d >= dst.len:
        return -1
      dst[d] = bytes[i]
      d += 1
  return d

proc base64_decodeMaxSize(size: int): int =
  return (size * 3 div 4) + 6

type
  RsaSecretKey[N, halfN: static int] = object
    ## RSA secret key metadata
    ## Using N+N, N div 2 or N shr 1 to parametrize with a single one is broken
    n:  BigInt[N]            # The modulus (not really necessary with p and q but useful for debug)
    e:  BigInt[64]           # Public exponent, usually 3, 5, 17, 257, 65537
    d:  BigInt[N]            # The private exponent (not really necessary with dp and dq but useful for debug)
    p:  BigInt[halfN]        # First prime factor
    q:  BigInt[halfN]        # Second prime factor
    dp: BigInt[halfN]        # d mod (p-1), with d the private exponent
    dq: BigInt[halfN]        # d mod (q-1), with d the private exponent
    qInvModP: BigInt[halfN]  # Chinese Remainder Theorem coefficient

    # Montgomery Residue form
    p0ninv:  BaseType    # -1/p[0] (uint64)
    oneMontP: BigInt[halfN]
    r3mod_p: BigInt[halfN]

    q0ninv: BaseType     # -1/q[0] (uint64)
    onemontQ: BigInt[halfN]
    r3mod_q: BigInt[halfN]

  RsaKind* = enum
    k1024
    k2048
    k4096

  RsaPrivateKey* = object
    # TODO, macroify variant accesses, similar to
    # https://github.com/mratsim/trace-of-radiance/blob/e928285/trace_of_radiance/support/emulate_classes_with_ADTs.nim#L246-L276
    case kind: RsaKind
    of k1024:
      rsa1024: RsaSecretKey[1024, 512]
    of k2048:
      rsa2048: RsaSecretKey[2048, 1024]
    of k4096:
      rsa4096: RsaSecretKey[4096, 2048]

template getField(privkey: RsaPrivateKey, field: untyped): untyped =
  case privkey.kind
  of k1024:
    privkey.rsa1024.field
  of k2048:
    privkey.rsa2048.field
  of k4096:
    privkey.rsa4096.field

proc precomputeMontgomery(privkey: var RsaPrivateKey) =
  template precomp(rsaXXXX: untyped) =
    privkey.rsaXXXX.oneMontP = privkey.rsaXXXX.p.montyOne()
    privkey.rsaXXXX.oneMontQ = privkey.rsaXXXX.q.montyOne()
    privkey.rsaXXXX.r3mod_p = privkey.rsaXXXX.p.r3mod()
    privkey.rsaXXXX.r3mod_q = privkey.rsaXXXX.q.r3mod()

    privkey.rsaXXXX.p0ninv = negInvModWord(privkey.rsaXXXX.p)
    privkey.rsaXXXX.q0ninv = negInvModWord(privkey.rsaXXXX.q)

  case privkey.kind
  of k1024: precomp(rsa1024)
  of k2048: precomp(rsa2048)
  of k4096: precomp(rsa4096)

func sign[N, halfN: static int](sig: var openArray[byte], sk: RsaSecretKey[N, halfN], padded: openArray[byte]) =
  type BigIntN = sk.n.typeof()      # TODO: upstream bug, using BigInt[N*2] confuses the compiler
  #type BigIntHalfN = sk.p.typeof()

  var c{.noInit.}: BigIntN
  c.unmarshal(padded, bigEndian)

  #when true:
  # Montgomery constants - can be stuffed in precomputeMontgomery
  let n0ninv = negInvModWord(sk.n)
  let r2ModN = r2Mod(sk.n)
  let oneMontN = montyOne(sk.n)

  var rMont{.noInit.}: BigIntN
  rMont.getMont(c, sk.n, r2ModN, n0ninv, spareBits = 0)
  rMont.powMont(sk.d, sk.n, oneMontN, n0ninv,
                windowSize = 5, spareBits = 0)

  var r{.noInit.}: BigIntN
  r.fromMont(rMont, sk.n, n0ninv, spareBits = 0)

  sig.marshal(r, bigEndian)

  # else: # TODO debug to do
  #   # Chinese Remainder Theorem
  #   #
  #   # m₁ = cᵈᵖ mod p
  #   # m₂ = cᵈᑫ mod q
  #   # h = qInv.(m₁ - m₂) mod p
  #   # m = m₂ + h.q

  #   var m1{.noInit.}, m2{.noInit.}: BigIntHalfN

  #   # Montgomery residue form is aR (mod p)
  #   # redc2xMont(a): computes a/R (mod p)
  #   m1.limbs.redc2xMont(c.limbs, sk.p.limbs, sk.p0ninv, sparebits = 0)
  #   # mulMont(a, b) computes a.b.R⁻¹ (mod p), so mulMont(a/R, R³) = aR (mod p)
  #   m1.mulMont(m1, sk.r3mod_p, sk.p, sk.p0ninv, spareBits = 0)

  #   # Same for q
  #   m2.limbs.redc2xMont(c.limbs, sk.q.limbs, sk.q0ninv, sparebits = 0)
  #   m2.mulMont(m2, sk.r3mod_q, sk.q, sk.q0ninv, spareBits = 0)

  #   # modular exponentiations - TODO: upstream bug, generic instantiation too nested if  we use BigInt[N*2] type
  #   m1.powMont(sk.dp, sk.p, sk.oneMontP, sk.p0ninv,
  #               windowSize = 5, spareBits = 0)
  #   m2.powMont(sk.dq, sk.q, sk.oneMontQ, sk.q0ninv,
  #               windowSize = 5, spareBits = 0)

  #   # Back to canonical repr
  #   var m1c{.noInit.}, m2c{.noInit.}: BigIntHalfN
  #   m1c.fromMont(m1, sk.p, sk.p0ninv, spareBits = 0)
  #   m2c.fromMont(m2, sk.q, sk.q0ninv, spareBits = 0)

  #   # h = qInv.(m₁ - m₂) mod p
  #   # we assume that p > q. Otherwise why precompute qInv? if q < p, m₂ (mod q) implies m₂ (mod p)
  #   var h{.noInit.}: BigIntHalfN
  #   var h2{.noInit.}: BigIntN

  #   let underflowed = sub(m1c, m2c)
  #   discard cadd(m1c, sk.p, underflowed)

  #   h2.prod(sk.qInvModP, m1c)
  #   # Constant-time modular reduction needs n shifts, where n is the difference in bits between h2 and h.
  #   # This is slow and it might be worth it to go through Montgomery domain
  #   h.reduce(h2, sk.p)

  #   # m = m₂ + h.q
  #   var m{.noInit.}, hq{.noInit.}: BigIntN
  #   hq.prod(h, sk.q)
  #   m.copyTruncatedFrom(m2)
  #   m += hq

  #   sig.marshal(m, bigEndian)

proc sign_SHA256*[T: byte|char](privkey: RsaPrivateKey, message: openarray[T]): seq[byte] =
  ## RSASSA-PKCS1-v1_5 using SHA-256
  const oid = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

  var padded: seq[byte]

  case privkey.kind
  of k1024:
    padded.setLen(128)
  of k2048:
    padded.setLen(256)
  of k4096:
    padded.setLen(512)

  padded[1] = 1

  for i in 2 ..< padded.len - 32 - oid.len - 1:
    padded[i] = 0xff

  let oidStart = padded.len - 32 - oid.len
  for i in 0 ..< oid.len:
    padded[oidStart + i] = byte oid[i]

  let pPaddedEnd32 = cast[ptr array[32, byte]](padded[padded.len - 32].addr)

  sha256.hash(pPaddedEnd32[], message)

  case privkey.kind
  of k1024:
    result = newSeq[byte](128)
    result.sign(privkey.rsa1024, padded)
  of k2048:
    result = newSeq[byte](256)
    result.sign(privkey.rsa2048, padded)
  of k4096:
    result = newSeq[byte](512)
    result.sign(privkey.rsa4096, padded)

# Copy-pasted from crunchy for quick-win.
# ---------------------------------------
# TODO: a standalone PEM / PKCS #1 / DER / ASN.1 parser (no alloc, no exceptions, constant-time for fields):
# - https://www.rfc-editor.org/rfc/rfc8017#appendix-C
# - https://www.rfc-editor.org/rfc/rfc7468#section-11
# - https://www.rfc-editor.org/rfc/rfc5208#section-5
# - https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding

import strutils

template raisePrivateKeyError() =
  raise newException(ValueError, "RSA private key data appears invalid")

proc decodeLength(buf: seq[byte], pos: var int): int {.raises: [ValueError].} =
  # https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
  if (buf[pos] and 0b10000000) != 0:
    let numBytes = (buf[pos] and 0b01111111).int
    inc pos
    if pos + numBytes > buf.len or  numBytes > 4:
      raisePrivateKeyError()
    for _ in 0 ..< numBytes:
      result = (result shl 8) or buf[pos].int
      inc pos
  else:
    result = buf[pos].int
    inc pos

proc decodeBigInt*(dst: var BigInt, buf: seq[byte], pos: var int) {.raises: [ValueError].} =
  let len = decodeLength(buf, pos)
  if pos + len > buf.len:
    raisePrivateKeyError()
  dst.unmarshal(buf.toOpenArray(pos, pos + len - 1), bigEndian)
  pos += len

template decodeField(dst: var RsaPrivateKey, field: untyped, buf: seq[byte], pos: var int) =
  case dst.kind
  of k1024:
    dst.rsa1024.field.decodeBigInt(buf, pos)
  of k2048:
    dst.rsa2048.field.decodeBigInt(buf, pos)
  of k4096:
    dst.rsa4096.field.decodeBigInt(buf, pos)

proc decodePrivateKey*(s: string, debugNimBase64: static bool = false): RsaPrivateKey {.raises: [ValueError].} =
  var lines = s.split('\n')

  if lines[lines.high] == "":
    discard lines.pop()

  if lines.len == 0:
    raisePrivateKeyError()

  if lines[0].startsWith('-'):
    # Trim off -----BEGIN RSA PRIVATE KEY-----, -----END RSA PRIVATE KEY-----
    lines = lines[1 ..< ^1]

  when debugNimBase64:
    let buf = cast[seq[byte]](base64.decode(lines.join()))
  else:
    let joined = lines.join()
    var buf = newSeq[byte](joined.len.base64_decodeMaxSize())
    let size = buf.toOpenArray(buf.low, buf.high).base64_decode(joined)
    buf.setLen(size)

  var pos: int

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x30:
    raisePrivateKeyError()
  inc pos

  discard decodeLength(buf, pos)

  if pos + 5 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  if buf[pos] != 0x01:
    raisePrivateKeyError()
  inc pos

  if buf[pos] != 0x00:
    raisePrivateKeyError()
  inc pos

  # This is PKCS#8 format, skip past the header
  if buf[pos] == 0x30:
    inc pos

    discard decodeLength(buf, pos)

    if pos + 2 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x06:
      raisePrivateKeyError()
    inc pos

    # https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier

    let oidLen = decodeLength(buf, pos)

    if pos + oidLen > buf.len:
      raisePrivateKeyError()

    pos += oidLen

    if pos + 4 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x05:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x00:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x04:
      raisePrivateKeyError()
    inc pos

    discard decodeLength(buf, pos)

    if pos + 2 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x30:
      raisePrivateKeyError()
    inc pos

    discard decodeLength(buf, pos)

    if pos + 3 > buf.len:
      raisePrivateKeyError()

    if buf[pos] != 0x02:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x01:
      raisePrivateKeyError()
    inc pos

    if buf[pos] != 0x00:
      raisePrivateKeyError()
    inc pos

  # PKCS#1 private key values start here

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  block:
    let
      tmp = pos
      len = decodeLength(buf, pos)
    pos = tmp
    let size = ((len div 8) * 8) * 8
    if size == 1024:
      result = RsaPrivateKey(kind: k2048)
    elif size == 2048:
      result = RsaPrivateKey(kind: k2048)
    elif size == 4096:
      result = RsaPrivateKey(kind: k4096)
    else:
      raisePrivateKeyError()
    result.decodeField(n, buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  result.decodeField(e, buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  result.decodeField(d, buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  result.decodeField(p, buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  result.decodeField(q, buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  result.decodeField(dp, buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  result.decodeField(dq, buf, pos)

  if pos + 2 > buf.len:
    raisePrivateKeyError()

  if buf[pos] != 0x02:
    raisePrivateKeyError()
  inc pos

  result.decodeField(qInvmodP, buf, pos)

  result.precomputeMontgomery()


proc signSha256Base64*(privateKey: RsaPrivateKey, message: string): string =
  privateKey.sign_SHA256(message).toHex()[2..^1].toUpperAscii()

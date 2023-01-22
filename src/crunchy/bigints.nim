import std/bitops, std/math, std/algorithm

## This is a partial fork of https://github.com/nim-lang/bigints
## The goal here is to do faster RSA signing (powmod) for now.

type
  BigInt* = object
    ## An arbitrary precision integer.
    # Invariants for `a: BigInt`:
    # * if `a` is non-zero: `a.limbs[a.limbs.high] != 0`
    # * if `a` is zero: `a.limbs.len <= 1`
    limbs: seq[uint32]
    isNegative: bool

proc normalize(a: var BigInt) =
  for i in countdown(a.limbs.high, 0):
    if a.limbs[i] > 0'u32:
      a.limbs.setLen(i+1)
      return
  a.limbs.setLen(1)

proc initBigInt*(vals: sink seq[uint32], isNegative = false): BigInt =
  ## Initializes a `BigInt` from a sequence of `uint32` values.
  runnableExamples:
    let a = @[10'u32, 2'u32].initBigInt
    let b = 10 + 2 shl 32
    assert $a == $b
  result.limbs = vals
  result.isNegative = isNegative
  normalize(result)

proc initBigInt*[T: int8|int16|int32](val: T): BigInt =
  if val < 0:
    result.limbs = @[(not val).uint32 + 1] # manual 2's complement (to avoid overflow)
    result.isNegative = true
  else:
    result.limbs = @[val.uint32]
    result.isNegative = false

proc initBigInt*[T: uint8|uint16|uint32](val: T): BigInt =
  result.limbs = @[val.uint32]

proc initBigInt*(val: int64): BigInt =
  var a = val.uint64
  if val < 0:
    a = not a + 1 # 2's complement
    result.isNegative = true
  if a > uint32.high:
    result.limbs = @[(a and uint32.high).uint32, (a shr 32).uint32]
  else:
    result.limbs = @[a.uint32]

proc initBigInt*(val: uint64): BigInt =
  if val > uint32.high:
    result.limbs = @[(val and uint32.high).uint32, (val shr 32).uint32]
  else:
    result.limbs = @[val.uint32]

when sizeof(int) == 4:
  template initBigInt*(val: int): BigInt = initBigInt(val.int32)
  template initBigInt*(val: uint): BigInt = initBigInt(val.uint32)
else:
  template initBigInt*(val: int): BigInt = initBigInt(val.int64)
  template initBigInt*(val: uint): BigInt = initBigInt(val.uint64)

proc initBigInt*(val: BigInt): BigInt =
  result = val

const
  zero = initBigInt(0)
  one = initBigInt(1)
  two = initBigInt(2)

proc isZero(a: BigInt): bool {.inline.} =
  a.limbs.len == 0 or (a.limbs.len == 1 and a.limbs[0] == 0)

proc unsignedCmp(a: BigInt, b: uint32): int64 =
  # ignores the sign of `a`
  # `a` and `b` are assumed to not be zero
  result = int64(a.limbs.len) - 1
  if result != 0: return
  result = int64(a.limbs[0]) - int64(b)

proc unsignedCmp(a: uint32, b: BigInt): int64 = -unsignedCmp(b, a)

proc unsignedCmp(a, b: BigInt): int64 =
  # ignores the signs of `a` and `b`
  # `a` and `b` are assumed to not be zero
  result = int64(a.limbs.len) - int64(b.limbs.len)
  if result != 0: return
  for i in countdown(a.limbs.high, 0):
    result = int64(a.limbs[i]) - int64(b.limbs[i])
    if result != 0:
      return

proc cmp(a, b: BigInt): int64 =
  ## Returns:
  ## * a value less than zero, if `a < b`
  ## * a value greater than zero, if `a > b`
  ## * zero, if `a == b`
  if a.isZero:
    if b.isZero:
      return 0
    elif b.isNegative:
      return 1
    else:
      return -1
  elif a.isNegative:
    if b.isZero or not b.isNegative:
      return -1
    else:
      return unsignedCmp(b, a)
  else: # a > 0
    if b.isZero or b.isNegative:
      return 1
    else:
      return unsignedCmp(a, b)

proc cmp(a: BigInt, b: int32): int64 =
  ## Returns:
  ## * a value less than zero, if `a < b`
  ## * a value greater than zero, if `a > b`
  ## * zero, if `a == b`
  if a.isZero:
    return -b.int64
  elif a.isNegative:
    if b < 0:
      return unsignedCmp((not b).uint32 + 1, a)
    else:
      return -1
  else: # a > 0
    if b <= 0:
      return 1
    else:
      return unsignedCmp(a, b.uint32)

proc cmp(a: int32, b: BigInt): int64 = -cmp(b, a)

proc `==`(a, b: BigInt): bool =
  ## Compares if two `BigInt` numbers are equal.
  runnableExamples:
    let
      a = 5.initBigInt
      b = 3.initBigInt
      c = 2.initBigInt
    assert a == b + c
    assert b != c
  cmp(a, b) == 0

proc `<`(a, b: BigInt): bool =
  runnableExamples:
    let
      a = 5.initBigInt
      b = 3.initBigInt
      c = 2.initBigInt
    assert b < a
    assert b > c
  cmp(a, b) < 0

proc `<=`(a, b: BigInt): bool =
  runnableExamples:
    let
      a = 5.initBigInt
      b = 3.initBigInt
      c = 2.initBigInt
    assert a <= b + c
    assert c <= b
  cmp(a, b) <= 0

proc `==`(a: BigInt, b: int32): bool = cmp(a, b) == 0
proc `<`(a: BigInt, b: int32): bool = cmp(a, b) < 0
proc `<`(a: int32, b: BigInt): bool = cmp(a, b) < 0

template addParts(toAdd) =
  tmp += toAdd
  a.limbs[i] = uint32(tmp and uint32.high)
  tmp = tmp shr 32

proc unsignedAdditionInt(a: var BigInt, b: BigInt, c: uint32) =
  let bl = b.limbs.len
  a.limbs.setLen(bl)

  var tmp: uint64 = uint64(c)
  for i in 0 ..< bl:
    addParts(uint64(b.limbs[i]))
  if tmp > 0'u64:
    a.limbs.add(uint32(tmp))
  a.isNegative = false

proc unsignedMultiplication(a: var BigInt, b, c: BigInt) {.inline.} =
  # always called with bl >= cl
  let
    bl = b.limbs.len
    cl = c.limbs.len
  a.limbs.setLen(bl + cl)
  var tmp = 0'u64

  for i in 0 ..< bl:
    tmp += uint64(b.limbs[i]) * uint64(c.limbs[0])
    a.limbs[i] = uint32(tmp and uint32.high)
    tmp = tmp shr 32

  a.limbs[bl] = uint32(tmp)

  for j in 1 ..< cl:
    tmp = 0'u64
    for i in 0 ..< bl:
      tmp += uint64(a.limbs[j + i]) + uint64(b.limbs[i]) * uint64(c.limbs[j])
      a.limbs[j + i] = uint32(tmp and uint32.high)
      tmp = tmp shr 32
    var pos = j + bl
    while tmp > 0'u64:
      tmp += uint64(a.limbs[pos])
      a.limbs[pos] = uint32(tmp and uint32.high)
      tmp = tmp shr 32
      inc pos
  normalize(a)

proc multiplication(a: var BigInt, b, c: BigInt) =
  # a = b * c
  if b.isZero or c.isZero:
    a = zero
    return
  let
    bl = b.limbs.len
    cl = c.limbs.len

  if cl > bl:
    unsignedMultiplication(a, c, b)
  else:
    unsignedMultiplication(a, b, c)
  a.isNegative = b.isNegative xor c.isNegative

proc `*`(a, b: BigInt): BigInt =
  ## Multiplication for `BigInt`s.
  runnableExamples:
    let
      a = 421.initBigInt
      b = 200.initBigInt
    assert a * b == 84200.initBigInt
  multiplication(result, a, b)

template `*=`(a: var BigInt, b: BigInt) =
  runnableExamples:
    var a = 15.initBigInt
    a *= 10.initBigInt
    assert a == 150.initBigInt
  a = a * b

proc `shr`(x: BigInt, y: Natural): BigInt =
  ## Shifts a `BigInt` to the right (arithmetically).
  runnableExamples:
    let a = 24.initBigInt
    assert a shr 1 == 12.initBigInt
    assert a shr 2 == 6.initBigInt

  var carry = 0'u64
  let a = y div 32
  let b = uint32(y mod 32)
  let mask = (1'u32 shl b) - 1
  result.limbs.setLen(x.limbs.len - a)
  result.isNegative = x.isNegative

  for i in countdown(x.limbs.high, a):
    let acc = (carry shl 32) or x.limbs[i]
    carry = acc and mask
    result.limbs[i - a] = uint32(acc shr b)

  # if result.isNegative:
  #   var underflow = false
  #   if carry > 0:
  #     underflow = true
  #   else:
  #     for i in 0 .. a - 1:
  #       if x.limbs[i] > 0:
  #         underflow = true
  #         break

  #   if underflow:
  #     dec result

  result.normalize()

proc unsignedDivRem(q: var BigInt, r: var uint32, n: BigInt, d: uint32) =
  q.limbs.setLen(n.limbs.len)
  r = 0
  for i in countdown(n.limbs.high, 0):
    let tmp = uint64(n.limbs[i]) + uint64(r) shl 32
    q.limbs[i] = uint32(tmp div d)
    r = uint32(tmp mod d)
  normalize(q)

proc calcSizes(): array[2..36, int] =
  for i in 2..36:
    var x = int64(i)
    while x <= int64(uint32.high) + 1:
      x *= i
      result[i].inc

const
  digits = "0123456789abcdefghijklmnopqrstuvwxyz"
  powers = {2'u8, 4, 8, 16, 32}
  sizes = calcSizes() # `sizes[base]` is the maximum number of digits that fully fit in a `uint32`

proc toString*(a: BigInt, base: range[2..36] = 10): string =
  ## Produces a string representation of a `BigInt` in a specified
  ## `base`.
  ##
  ## Doesn't produce any prefixes (`0x`, `0b`, etc.).
  runnableExamples:
    let a = 55.initBigInt
    assert toString(a) == "55"
    assert toString(a, 2) == "110111"
    assert toString(a, 16) == "37"

  if a.isZero:
    return "0"

  let size = sizes[base]
  if base.uint8 in powers:
    let
      bits = countTrailingZeroBits(base) # bits per digit
      mask = (1'u32 shl bits) - 1
      totalBits = 32 * a.limbs.len - countLeadingZeroBits(a.limbs[a.limbs.high])
    result = newStringOfCap((totalBits + bits - 1) div bits + 1)

    var
      acc = 0'u32
      accBits = 0 # the number of bits needed for acc
    for x in a.limbs:
      acc = acc or (x shl accBits)
      accBits += 32
      while accBits >= bits:
        result.add(digits[acc and mask])
        acc = acc shr bits
        if accBits > 32:
          acc = x shr (32 - (accBits - bits))
        accBits -= bits
    if acc > 0:
      result.add(digits[acc])
  else:
    let
      base = uint32(base)
      d = base ^ size
    var tmp = a

    tmp.isNegative = false
    result = newStringOfCap(size * a.limbs.len + 1) # estimate the length of the result

    while tmp > 0:
      var
        c: uint32
        tmpCopy = tmp
      unsignedDivRem(tmp, c, tmpCopy, d)
      for i in 1..size:
        result.add(digits[c mod base])
        c = c div base

  # normalize
  var i = result.high
  while i > 0 and result[i] == '0':
    dec i
  result.setLen(i+1)

  if a.isNegative:
    result.add('-')

  result.reverse()

proc `$`*(a: BigInt): string =
  ## String representation of a `BigInt` in base 10.
  toString(a, 10)

proc parseDigit(c: char, base: uint32): uint32 {.inline.} =
  result = case c
    of '0'..'9': uint32(ord(c) - ord('0'))
    of 'a'..'z': uint32(ord(c) - ord('a') + 10)
    of 'A'..'Z': uint32(ord(c) - ord('A') + 10)
    else: raise newException(ValueError, "Invalid input: " & c)

  if result >= base:
    raise newException(ValueError, "Invalid input: " & c)

proc filterUnderscores(str: var string) {.inline.} =
  var k = 0 # the amount of underscores
  for i in 0 .. str.high:
    let c = str[i]
    if c == '_':
      inc k
    elif k > 0:
      str[i - k] = c
  str.setLen(str.len - k)

proc initBigInt*(str: string, base: range[2..36] = 10): BigInt =
  ## Create a `BigInt` from a string. For invalid inputs, a `ValueError` exception is raised.
  runnableExamples:
    let
      a = initBigInt("1234")
      b = initBigInt("1234", base = 8)
    assert a == 1234.initBigInt
    assert b == 668.initBigInt

  if str.len == 0:
    raise newException(ValueError, "Empty input")

  let size = sizes[base]
  let base = base.uint32
  var first = 0
  var neg = false

  case str[0]
  of '-':
    if str.len == 1:
      raise newException(ValueError, "Invalid input: " & str)
    first = 1
    neg = true
  of '+':
    if str.len == 1:
      raise newException(ValueError, "Invalid input: " & str)
    first = 1
  else:
    discard
  if str[first] == '_':
    raise newException(ValueError, "A number can not begin with _")
  if str[^1] == '_':
    raise newException(ValueError, "A number can not end with _")

  if base.uint8 in powers:
    # base is a power of two, so each digit corresponds to a block of bits
    let bits = countTrailingZeroBits(base) # bits per digit
    var
      acc = 0'u32
      accBits = 0 # the number of bits needed for acc
    for i in countdown(str.high, first):
      if str[i] != '_':
        let digit = parseDigit(str[i], base)
        acc = acc or (digit shl accBits)
        accBits += bits
        if accBits >= 32:
          result.limbs.add(acc)
          accBits -= 32
          acc = digit shr (bits - accBits)
    if acc > 0:
      result.limbs.add(acc)
    result.normalize()
  else:
    var str = str
    filterUnderscores(str)
    let d = initBigInt(base ^ size)
    for i in countup(first, str.high, size):
      var num = 0'u32 # the accumulator in this block
      if i + size <= str.len:
        # iterator over a block of length `size`, so we can use `d`
        for j in countup(i, i + size - 1):
          if str[j] != '_':
            let digit = parseDigit(str[j], base)
            num = (num * base) + digit
        unsignedAdditionInt(result, result * d, num)
      else:
        # iterator over a block smaller than `size`, so we have to compute `mul`
        var mul = 1'u32 # the multiplication factor for num
        for j in countup(i, min(i + size - 1, str.high)):
          if str[j] != '_':
            let digit = parseDigit(str[j], base)
            num = (num * base) + digit
            mul *= base
        unsignedAdditionInt(result, result * initBigInt(mul), num)

  result.isNegative = neg

################################################################################

proc realUnsignedSubtraction2(a: var BigInt, c: BigInt) {.inline.} =
  # In-place subtraction
  # a > c
  let
    al = a.limbs.len
    cl = c.limbs.len
  var m = min(al, cl)
  a.limbs.setLen(max(al, cl))

  var tmp = 0'i64
  for i in 0 ..< m:
    tmp = int64(uint32.high) + 1 + int64(a.limbs[i]) - int64(c.limbs[i]) - tmp
    a.limbs[i] = uint32(tmp and int64(uint32.high))
    tmp = 1 - (tmp shr 32)
  if al < cl:
    for i in m ..< cl:
      tmp = int64(uint32.high) + 1 - int64(c.limbs[i]) - tmp
      a.limbs[i] = uint32(tmp and int64(uint32.high))
      tmp = 1 - (tmp shr 32)
    a.isNegative = true
  else:
    for i in m ..< al:
      tmp = int64(uint32.high) + 1 + int64(a.limbs[i]) - tmp
      a.limbs[i] = uint32(tmp and int64(uint32.high))
      tmp = 1 - (tmp shr 32)
    a.isNegative = false

  normalize(a)
  assert tmp == 0

proc modulo(a, b: BigInt, memoized: var seq[BigInt]): BigInt =
  # Binary-search-ish modulo
  result = a

  var sl: int
  block:
    var s = b
    while result > s:
      if sl == memoized.len:
        memoized.add(s)
        s *= two
      else:
        s = memoized[sl]
      inc sl

  for i in countdown(sl - 1, 0):
    if result > memoized[i]:
      realUnsignedSubtraction2(result, memoized[i])

proc powmod*(base, exponent, modulus: BigInt): BigInt =
  ## Compute modular exponentation of `base` with power `exponent` modulo `modulus`.
  ## The return value is always in the range `[0, modulus-1]`.
  runnableExamples:
    assert powmod(2.initBigInt, 3.initBigInt, 7.initBigInt) == 1.initBigInt
  if modulus.isZero:
    raise newException(DivByZeroDefect, "modulus must be nonzero")
  elif modulus.isNegative:
    raise newException(ValueError, "modulus must be strictly positive")
  elif modulus == 1:
    return zero
  else:
    var
      base = base
      exponent = exponent
      memoized: seq[BigInt]
    base = modulo(base, modulus, memoized)
    result = one
    while not exponent.isZero:
      if (exponent.limbs[0] and 1) != 0:
        result = modulo((result * base), modulus, memoized)
      base = modulo((base * base), modulus, memoized)
      exponent = exponent shr 1

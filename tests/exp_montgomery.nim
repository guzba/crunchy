# Montgomery reduction is a method for performing modular arithmetic
# efficiently. It was introduced by Peter Montgomery in 1985 and it's
# especially useful in cryptographic computations such as RSA encryption,
# which involves operations on large numbers.

# The problem that Montgomery arithmetic aims to solve is that computations of
# the form A * B mod N can be expensive for large A, B, and N, which are common
# in cryptographic operations like RSA. If you're computing many such products,
# the cost can add up quickly. Montgomery arithmetic can help reduce this cost.

import ../src/crunchy/bigints {.all.}
import pretty
const
  zero = 0.initBigInt
  one = 1.initBigInt
  two = 2.initBigInt
  three = 3.initBigInt

{.push checks:off.}
{.push stackTrace:off.}

# regular Montgomery

# proc chooseMontgomeryR*(N: BigInt): BigInt =
#   # choose R > N and R is a power of 2 and gcd(R, N) = 1
#   # assumes N > 3 and N is not even
#   assert N.isOdd
#   return initBigInt(2).pow(N.totalBits)

# proc toMontgomery*(x, N, R: BigInt): BigInt =
#   (x * R) mod N

# proc fromMontgomery*(x, N, R: BigInt): BigInt =
#   let
#     NPrime = -powmod(N, initBigInt(-1), R)
#     m = ((x mod R) * NPrime) mod R
#     u = (x + m*N) div R
#   if u >= N:
#     return u - N
#   else:
#     return u

# proc montgomeryProduct*(A, B, N, R: BigInt): BigInt =
#   let
#     aMont = toMontgomery(A, N, R)
#     B_mont = toMontgomery(B, N, R)
#     T = aMont * B_mont
#     product_mont = fromMontgomery(T, N, R)
#   # echo aMont, " x ", B_mont, " = ", T
#   return fromMontgomery(product_mont, N, R)

# proc powmodMontgomery*(A, B, N: BigInt): BigInt =
#   var
#     R = chooseMontgomeryR(N)
#     aMont = toMontgomery(A, N, R)
#     xMont = toMontgomery(1.initBigInt, N, R) # Initialize result to 1 (in Montgomery form)
#     b = B

#   while not b.isZero:
#     #echo "xMont ", xMont
#     #echo "aMont ", aMont

#     if (b.limbs[0] and 1) != 0:  # If B is odd
#       #echo "*"
#       xMont = (xMont * aMont).fromMontgomery(N, R)

#     aMont = (aMont * aMont).fromMontgomery(N, R)  # Square aMont

#     b = b shr 1  # Integer division by 2

#     #echo "xMont ", xMont
#     #echo "aMont ", aMont
#     #echo "b ", b

#   return fromMontgomery(xMont, N, R)

# -------------- regular Montgomery --------------

proc chooseMontgomeryR*(N: BigInt): BigInt =
  assert N.isOdd
  assert N > three
  two.pow(N.totalBits)

proc toMontgomery*(x, N, R: BigInt): BigInt =
  (x * R) mod N

proc extendedGCD(a, R: BigInt): tuple[x, y, gcd: BigInt] =
  if a == zero:
    return (zero, one, R)
  else:
    let (x, y, gcd) = extendedGCD(R mod a, a)
    return (y - (R div a) * x, x, gcd)

proc inverseMod(a, R: BigInt): BigInt =
  let (x, _, gcd) = extendedGCD(a, R)
  assert gcd == one
  return x mod R

proc montgomeryReduction*(T, N, R: BigInt): BigInt =
  let NPrime = -inverseMod(N, R)
  let m = ((T mod R) * NPrime) mod R
  var u = (T + m * N) div R
  if u >= N:
    return u - N
  else:
    return u

proc fromMontgomery*(Xm, N, R: BigInt): BigInt =
  montgomeryReduction(Xm, N, R)

proc montgomeryProduct*(Am, Bm, N, R: BigInt): BigInt =
  let Xm = Am * Bm
  return montgomeryReduction(Xm, N, R)

proc montgomeryPowMod*(Am, B, N, R: BigInt): BigInt =

  var AMont = Am
  var BTemp = B
  var xMont = toMontgomery(one, N, R)

  while BTemp > zero:
    if BTemp.isOdd:  # If B is odd
      xMont = montgomeryProduct(xMont, AMont, N, R)
    AMont = montgomeryProduct(AMont, AMont, N, R)  # Square A_mont
    BTemp = BTemp shr 1 # Integer division by 2

  return xMont

# -------------- Montgomery Bits --------------

proc chooseMontgomeryRBits*(N: BigInt): int =
  # choose R > N and R is a power of 2 and gcd(R, N) = 1
  # assumes N > 3 and N is not even
  assert N.isOdd
  assert N > three
  return N.totalBits

proc toMontgomeryBits*(x, N: BigInt, rBits: int): BigInt =
  (x shl rBits) mod N

# proc extendedGCD(a, R: BigInt): tuple[x, y, gcd: BigInt] =
#   if a == zero:
#     return (zero, one, R)
#   else:
#     let (x, y, gcd) = extendedGCD(R mod a, a)
#     return (y - (R div a) * x, x, gcd)

proc inverseModBits(a: BigInt, rBits: int): BigInt =
    let (x, _, gcd) = extendedGCD(a, two.pow(rBits))
    assert gcd == one
    return x.modBits(rBits)

proc montgomeryReductionBits*(x, N: BigInt, rBits: int): BigInt =
  let NPrime = -inverseModBits(N, rBits)
  let m = ((x.modBits(rBits)) * NPrime).modBits(rBits)
  var u = (x + m * N) shr rBits
  if u >= N:
    return u - N
  else:
    return u

proc fromMontgomeryBits*(Xm, N: BigInt, rBits: int): BigInt =
  montgomeryReductionBits(Xm, N, rBits)

proc montgomeryProductBits*(Am, Bm, N: BigInt, rBits: int): BigInt =
  let Xm = Am * Bm
  return montgomeryReductionBits(Xm, N, rBits)

proc montgomeryPowModBits*(Am, B, N: BigInt, rBits: int): BigInt =
  var AMont = Am
  var BTemp = B
  var xMont = toMontgomeryBits(one, N, rBits)

  while BTemp > zero:
    if BTemp.isOdd:  # If B is odd
      xMont = montgomeryProductBits(xMont, AMont, N, rBits)
    AMont = montgomeryProductBits(AMont, AMont, N, rBits)  # Square A_mont
    BTemp = BTemp shr 1 # Integer division by 2

  return xMont

# -------------- Montgomery Words --------------

proc chooseMontgomeryRWords*(N: BigInt): int =
  # Returns R number of 32bit words
  # choose R > N and R is a power of 2 and gcd(R, N) = 1
  # assumes N > 3 and N is not even
  assert N.isOdd
  assert N > three
  N.limbs.len

proc toMontgomeryWords*(x, N: BigInt, rWords: int): BigInt =
  result = BigInt()
  result.isNegative = x.isNegative
  result.limbs.setLen(x.limbs.len + rWords)
  for i, l in x.limbs:
    result.limbs[rWords + i] = l
  return result mod N

{.pop.}
{.pop.}



#func powmodMontgomeryBits*(base, exponent: BigInt, rBits: int): BigInt =

  # var
  #   base = base
  #   exponent = exponent

  # # if exponent < 0:
  # #   base = invmod(base, modulus)
  # #   exponent = -exponent

  # var basePow = base.modBits(rBits)

  # print "base:", $basePow
  # print "exponent:", $basePow
  # print "basePow:", $basePow
  # print rBits, " ", $(1.initBigInt shl (rBits))

  # result = 1.initBigInt
  # while not exponent.isZero:
  #   if (exponent.limbs[0] and 1) != 0:
  #     result = (result * basePow)#.modBits(rBits)
  #   basePow = (basePow * basePow)#.modBits(rBits)
  #   exponent = exponent shr 1

  #   print "exponent:", $exponent
  #   print "result:", $result

  # print "done"


when isMainModule:
  block:
    echo "test montgomery "
    let
      A = 123412317.initBigInt
      B = 12341233.initBigInt
      N = 12317.initBigInt
      R = chooseMontgomeryR(N)


    echo "R: ", R
    echo "slow: ", A * B mod N
    echo "fast: ", montgomeryProduct(A, B, N, R)

    assert A * B mod N == montgomeryProduct(A, B, N, R)

  block:
    echo "test montgomery Bits"
    let
      A = 123412317.initBigInt
      B = 12341233.initBigInt
      N = 12317.initBigInt
      rBits = chooseMontgomeryRBits(N)


    echo "slow:      ", A * B mod N
    echo "fast Bits: ", montgomeryProductBits(A, B, N, rBits)

    assert A * B mod N == montgomeryProductBits(A, B, N, rBits)


  block:
    echo "test montgomery Words"
    let
      A = 123412317.initBigInt
      B = 12341233.initBigInt
      N = 12317.initBigInt
      R = chooseMontgomeryRWords(N)

    echo "slow:      ", A * B mod N
    let
      Am = A.toMontgomeryWords(N, R)
      Bm = B.toMontgomeryWords(N, R)
      res = montgomeryProductWords(Am, Bm, N, R).fromMontgomeryWords(N, R)

    echo "fast Bits: ", res

    assert A * B mod N == res

    echo "slow:      ", A.powmod(B, N)

    let
      res2 = Am.montgomeryPowModWords(B, N, R).fromMontgomeryWords(N, R)

    echo "fast:      ", res2
    assert res2 == A.powmod(B, N)


  block:
    echo "test totalBits"
    assert 0.initBigInt.totalBits == -1
    assert 1.initBigInt.totalBits == 1
    assert 64.initBigInt.totalBits == 7
    assert 65536.initBigInt.totalBits == 17
    assert "1267650600228229401496703205376".initBigInt.totalBits == 101

    echo "test keepBits"
    assert 2.initBigInt.keepBits(0) == 0.initBigInt
    assert 0b1111.initBigInt.keepBits(3) == 0b111.initBigInt
    assert 0b1111_1111_1111.initBigInt.keepBits(10) == 0b11_1111_1111.initBigInt
    assert "1267650600228229401496703205376".initBigInt.keepBits(100) == 0.initBigInt
    assert "1267650600228229401496703205376".initBigInt.keepBits(101) == "1267650600228229401496703205376".initBigInt
    assert "-1267650600228229401496703205376".initBigInt.keepBits(101) == "-1267650600228229401496703205376".initBigInt


  block:
    let
      b = "211234123412231".initBigInt
      e = "12123412343".initBigInt
      m = "1341234121".initBigInt

    echo b.powmod(e, m)
    echo b.powmod_old(e, m)

  #   # let
  #   #   bM = b.toMontgomeryBits(m, rBits)
  #   #   eM = e.toMontgomeryBits(m, rBits)

  #   #   tM = bM.powmodMontgomeryBits(eM, rBits)

  #   #   m1 = tM.fromMontgomeryBits(m, rBits)

  #   #   res = m1 mod m

    let res = b.powmodMontgomery(e, m)
    echo res

  #   assert b.powmod(e, m) == b.powmod_old(e, m)
  #   assert b.powmod_old(e, m) == res

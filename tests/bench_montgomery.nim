import exp_montgomery, benchy, ../src/crunchy/bigints, ../src/crunchy/rsa

let keyText = readFile("tests/data/2048.txt")
let pk2048 = rsa.decodePrivateKey(keyText)

let
  A = pk2048.d #initBigInt(2).pow(i) + initBigInt(7)
  B = pk2048.d #initBigInt(2).pow(i) + initBigInt(13)
  N = pk2048.n #initBigInt(2).pow(i) + initBigInt(17)

  trueRes = (A * B) mod N
  trueRes2 = A.powmod(B, N)

timeIt "regular", 1:
  let res = (A * B) mod N
  let res2 = A.powmod(B, N)
  doAssert res == trueRes
  doAssert res2 == trueRes2

timeIt "Montgomery", 1:
  var
    R = chooseMontgomeryR(N)

  let
    Am = A.toMontgomery(N, R)
    Bm = B.toMontgomery(N, R)

  let
    res = montgomeryProduct(Am, Bm, N, R).fromMontgomery(N, R)
    res2 = Am.montgomeryPowMod(B, N, R).fromMontgomery(N, R)

  doAssert res == trueRes
  doAssert res2 == trueRes2

timeIt "Montgomery Bits", 1:
  var
    R = chooseMontgomeryRBits(N)

  let
    Am = A.toMontgomeryBits(N, R)
    Bm = B.toMontgomeryBits(N, R)

  let
    res = montgomeryProductBits(Am, Bm, N, R).fromMontgomeryBits(N, R)
    res2 = Am.montgomeryPowModBits(B, N, R).fromMontgomeryBits(N, R)

  doAssert res == trueRes
  doAssert res2 == trueRes2

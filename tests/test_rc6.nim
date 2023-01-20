import crunchy/rc6, std/strutils

# block:
#   var key: array[32, uint8]
#   let
#     plaintext = newString(16)
#     encrypted = rc6Encrypt(key, plaintext)

#   doAssert encrypted.toHex() ==
#     "8F5FBD0510D15FA893FA3FDA6E857EC2B8C5819F2CF65FEA4AB06BDDFA378ACD"

  # doAssert rc6Decrypt(key, encrypted) == plaintext

# block:
#   let
#     key = [
#       0x01'u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
#       0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
#       0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
#       0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
#     ]
#     plaintext = "\x02\x13\x24\x35\x46\x57\x68\x79\x8a\x9b\xac\xbd\xce\xdf\xe0\xf1"
#     encrypted = rc6Encrypt(key, plaintext)

#   doAssert encrypted.toHex() ==
#     "C8241816F0D7E48920AD16A1674E5D48ED80D0FB9992FE358718212460E2A166"

  # doAssert rc6Decrypt(key, encrypted) == plaintext

block:
  var key: array[32, uint8]
  for i in 0 ..< 32:
    key[i] = 'a'.uint8
  var iv: array[16, uint8]
  for i in 0 ..< 16:
    iv[i] = 'b'.uint8
  let
    plaintext = "abcdefghijklmnopqrstuvwxyz"
    encrypted = rc6cbcEncrypt(key, iv, plaintext)

  doAssert encrypted.toHex() ==
    "4D7487CB5229E8191DDF8BB0ED6DA65DA4D1880AE8D97F6FAFB1248E70784774"

  doAssert rc6cbcDecrypt(key, iv, encrypted) == plaintext

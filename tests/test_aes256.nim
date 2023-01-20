import crunchy/aes256, std/strutils

block:
  var
    key: array[32, uint8]
    iv: array[12, uint8]
    plaintext = newString(16)

  let (encrypted, tag1) = aes256gcmEncrypt(key, iv, plaintext)

  doAssert encrypted.toHex() == "CEA7403D4D606B6E074EC5D3BAF39D18"

  doAssert tag1 == [
    208'u8, 209, 200, 167, 153, 153, 107, 240,
    38, 91, 152, 181, 212, 138, 185, 25
  ]

  let (decrypted, tag2) = aes256gcmDecrypt(key, iv, encrypted)

  doAssert decrypted == plaintext
  doAssert tag1 == tag2

block:
  let
    key = [
      0xfe'u8, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
      0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    ]
    iv = [
      0xca'u8, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    ]
    plaintext = "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55"

  let (encrypted, tag1) = aes256gcmEncrypt(key, iv, plaintext)

  doAssert encrypted.toHex() ==
    "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD"

  doAssert tag1 == [
    176'u8, 148, 218, 197, 217, 52, 113, 189,
    236, 26, 80, 34, 112, 227, 204, 108
  ]

  let (decrypted, tag2) = aes256gcmDecrypt(key, iv, encrypted)

  doAssert decrypted == plaintext
  doAssert tag1 == tag2

block:
  let
    key = [
      0xfe'u8, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
      0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
      0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    ]
    iv = [
      0xca'u8, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    ]
    plaintext = "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf"

  let (encrypted, tag1) = aes256gcmEncrypt(key, iv, plaintext)

  doAssert encrypted.toHex() ==
    "522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F6628980"

  let (decrypted, tag2) = aes256gcmDecrypt(key, iv, encrypted)

  doAssert decrypted == plaintext
  doAssert tag1 == tag2

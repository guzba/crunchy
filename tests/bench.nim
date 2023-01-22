import benchy, crunchy, crunchy/internal, std/random, crunchy/rc6, crunchy/aes256,
    crunchy/rsa

randomize()

var data = newString(10_000_000)
for c in data.mitems:
  c = rand(0 .. 255).char

timeIt "crc32":
  discard crc32(data)

when allowSimd:
  timeIt "crc32c":
    discard crc32c(data)

timeIt "adler32":
  discard adler32(data)

timeIt "sha256":
  discard sha256(data)

block:
  var
    key: array[32, uint8]
    iv: array[16, uint8]
  timeIt "rc6cbc":
    discard rc6cbcDecrypt(key, iv, rc6cbcEncrypt(key, iv, data))

block:
  var
    key: array[32, uint8]
    iv: array[12, uint8]
  timeIt "aes256gcm":
    let (encrypted, _) = aes256gcmEncrypt(key, iv, data)
    discard aes256gcmDecrypt(key, iv, encrypted)

block:
  let pk = decodePrivateKey(readFile("/Users/me/Documents/GitHub/crunchy/tests/data/2048.txt"))
  timeIt "powmod":
    discard pk.p.powmod(pk.d, pk.n)

import benchy, crunchy, crunchy/internal, std/random, crunchy/rc6

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

var
  key: array[32, uint8]
  iv: array[16, uint8]
timeIt "rc6cbc":
  discard rc6cbcDecrypt(key, iv, rc6cbcEncrypt(key, iv, data))

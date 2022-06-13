import benchy, scrutiny, std/random

randomize()

var data = newString(10_000_000)
for c in data.mitems:
  c = rand(0 .. 255).char

timeIt "crc32":
  discard crc32(data)

timeIt "crc32c":
  discard crc32c(data)

timeIt "adler32":
  discard adler32(data)

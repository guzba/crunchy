import scrutiny/crc32c

const testCases = [
  ("1", 0x90F599E3.uint32),
  ("123456789", 0xE3069283.uint32),
  ("abacus", 0x82418AEB.uint32),
  ("backlog", 0x967C669B.uint32),
  ("campfire", 0xB5B76905.uint32)
]

for (s, v) in testCases:
  doAssert crc32c(s) == v

block:
  let data = readFile("tests/data/zlib_rfc.html")
  doAssert crc32c(data) == 1110169936.uint32

import scrutiny/adler32

const testCases = [
  ("1", 0x00320032.uint32),
  ("123456789", 0x091e01de.uint32),
  ("abacus", 0x08400270.uint32),
  ("backlog", 0x0b1f02d4.uint32),
  ("campfire", 0x0ea10348.uint32)
]

for (s, v) in testCases:
  doAssert adler32(s) == v

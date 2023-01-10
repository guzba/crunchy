import crunchy/adler32

const testCases = [
  ("", 0x00000001'u32),
  ("1", 0x00320032'u32),
  ("123456789", 0x091e01de'u32),
  ("abacus", 0x08400270'u32),
  ("backlog", 0x0b1f02d4'u32),
  ("campfire", 0x0ea10348'u32)
]

for (s, v) in testCases:
  doAssert adler32(s) == v

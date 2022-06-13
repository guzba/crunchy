import scrutiny/crc32

const testCases = [
  ("abacus", 0xc3d7115b.uint32),
  ("backlog", 0x269205.uint32),
  ("campfire", 0x22a515f8.uint32),
  ("delta", 0x9643fed9.uint32),
  ("executable", 0xd68eda01.uint32),
  ("file", 0x8c9f3610.uint32),
  ("greatest", 0xc1abd6cd.uint32),
  ("hello", 0x3610a686.uint32),
  ("inverter", 0xc9e962c9.uint32),
  ("jigsaw", 0xce4e3f69.uint32),
  ("karate", 0x890be0e2.uint32),
  ("landscape", 0xc4e0330b.uint32),
  ("machine", 0x1505df84.uint32),
  ("nanometer", 0xd4e19f39.uint32),
  ("oblivion", 0xdae9de77.uint32),
  ("panama", 0x66b8979c.uint32),
  ("quest", 0x4317f817.uint32),
  ("resource", 0xbc91f416.uint32),
  ("secret", 0x5ca2e8e5.uint32),
  ("test", 0xd87f7e0c.uint32),
  ("ultimate", 0x3fc79b0b.uint32),
  ("vector", 0x1b6e485b.uint32),
  ("walrus", 0xbe769b97.uint32),
  ("xeno", 0xe7a06444.uint32),
  ("yelling", 0xfe3944e5.uint32),
  ("zlib", 0x73887d3a.uint32)
]

for (s, v) in testCases:
  doAssert crc32(s) == v

block:
  let data = "012345678901234567890123"
  doAssert crc32(data) == 560935461

block:
  let data = "The quick brown fox jumps over the lazy dog"
  doAssert crc32(data) == 0x414FA339

block:
  let data = readFile("tests/data/zlib_rfc.html")
  doAssert crc32(data) == 705663465

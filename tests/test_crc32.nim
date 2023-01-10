import crunchy/crc32

const testCases = [
  ("", 0x00000000'u32),
  ("abacus", 0xc3d7115b'u32),
  ("backlog", 0x269205'u32),
  ("campfire", 0x22a515f8'u32),
  ("delta", 0x9643fed9'u32),
  ("executable", 0xd68eda01'u32),
  ("file", 0x8c9f3610'u32),
  ("greatest", 0xc1abd6cd'u32),
  ("hello", 0x3610a686'u32),
  ("inverter", 0xc9e962c9'u32),
  ("jigsaw", 0xce4e3f69'u32),
  ("karate", 0x890be0e2'u32),
  ("landscape", 0xc4e0330b'u32),
  ("machine", 0x1505df84'u32),
  ("nanometer", 0xd4e19f39'u32),
  ("oblivion", 0xdae9de77'u32),
  ("panama", 0x66b8979c'u32),
  ("quest", 0x4317f817'u32),
  ("resource", 0xbc91f416'u32),
  ("secret", 0x5ca2e8e5'u32),
  ("test", 0xd87f7e0c'u32),
  ("ultimate", 0x3fc79b0b'u32),
  ("vector", 0x1b6e485b'u32),
  ("walrus", 0xbe769b97'u32),
  ("xeno", 0xe7a06444'u32),
  ("yelling", 0xfe3944e5'u32),
  ("zlib", 0x73887d3a'u32)
]

for (s, v) in testCases:
  doAssert crc32(s) == v

block:
  let data = "012345678901234567890123"
  doAssert crc32(data) == 560935461'u32

block:
  let data = "The quick brown fox jumps over the lazy dog"
  doAssert crc32(data) == 0x414FA339

block:
  let data = readFile("tests/data/zlib.rfc")
  echo crc32(data)
  doAssert crc32(data) == 705663465'u32

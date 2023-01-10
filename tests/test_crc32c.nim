# import crunchy/internal, crunchy/crc32c

# const testCases = [
#   ("", 0x00000000'u32),
#   ("1", 0x90F599E3'u32),
#   ("123456789", 0xE3069283'u32),
#   ("abacus", 0x82418AEB'u32),
#   ("backlog", 0x967C669B'u32),
#   ("campfire", 0xB5B76905'u32)
# ]

# when allowSimd:

#   for (s, v) in testCases:
#     doAssert crc32c(s) == v

#   block:
#     let data = readFile("tests/data/zlib.rfc")
#     echo crc32c(data)
#     doAssert crc32c(data) == 1110169936'u32

import scrutiny, std/memfiles

block:
  # Just read the file into memory and compute the CRC-32. Easy and perfect
  # for small files or times wen performance isn't important.
  let data = readFile("tests/data/zlib_rfc.html")
  echo crc32(data)

block:
  # Alternatively, memory map the file instead. This avoids copying the file
  # contents and works great even if the file is very large.
  # (Probably overkill if you don't really need to do this!)
  var memFile = memfiles.open("tests/data/zlib_rfc.html")
  echo crc32(memFile.mem, memFile.size)
  memFile.close()

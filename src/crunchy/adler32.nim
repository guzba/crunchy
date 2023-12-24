import internal

when defined(amd64):
  import nimsimd/runtimecheck

when allowSimd:
  import adler32_simd

when defined(release):
  {.push checks: off.}

proc adler32*(src: pointer, len: int): uint32 =
  ## See https://github.com/madler/zlib/blob/master/adler32.c

  when allowSimd:
    when defined(amd64):
      if checkInstructionSets({SSSE3}):
        return adler32_ssse3(src, len)
    elif defined(arm64):
      return adler32_neon(src, len)

  let src = cast[ptr UncheckedArray[uint8]](src)

  const nmax = 5552

  var
    s1 = 1.uint32
    s2 = 0.uint32
    l = len
    pos: int

  template do1(i: int) =
    s1 += src[pos + i]
    s2 += s1

  template do8() =
    do1(0)
    do1(1)
    do1(2)
    do1(3)
    do1(4)
    do1(5)
    do1(6)
    do1(7)

  while l >= nmax:
    l -= nmax
    for i in 0 ..< nmax div 8:
      do8()
      pos += 8

    s1 = s1 mod 65521
    s2 = s2 mod 65521

  while l >= 8:
    l -= 8
    do8()
    pos += 8

  for i in 0 ..< l:
    do1(i)

  s1 = s1 mod 65521
  s2 = s2 mod 65521

  result = (s2 shl 16) or s1

proc adler32*(data: openarray[byte]): uint32 =
  if data.len <= 0:
    adler32(nil, 0)
  else:
    adler32(data[0].unsafeAddr, data.len)

proc adler32*(data: string): uint32 {.inline.} =
  adler32(data.cstring, data.len)

when defined(release):
  {.pop.}

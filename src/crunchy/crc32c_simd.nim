when defined(release):
  {.push checks: off.}

when defined(amd64):
  import nimsimd/sse42

  when defined(gcc) or defined(clang):
    {.localPassC: "-msse4.2".}

  proc crc32c_sse42*(src: pointer, len: int): uint32 =
    let src = cast[ptr UncheckedArray[uint8]](src)

    var pos: int

    # This should be done in blocks, but for now

    result = not result

    # Align to 8 bytes
    while pos < len and (cast[uint64](src[pos].addr) and 7) != 0:
      result = mm_crc32_u8(result, src[pos])
      inc pos

    block:
      var
        crc = result.uint64
        v: uint64
      while pos + 8 <= len:
        copyMem(v.addr, src[pos].addr, 8)
        crc = mm_crc32_u64(crc, v)
        pos += 8
      result = crc.uint32

    for i in pos ..< len:
      result = mm_crc32_u8(result, src[i])

    result = not result

when defined(release):
  {.pop.}

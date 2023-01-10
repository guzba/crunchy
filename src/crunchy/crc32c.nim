import internal

when allowSimd:
  import crc32c_simd

  when defined(amd64):
    proc crc32c*(src: pointer, len: int): uint32 =
      crc32c_sse42(src, len)

    proc crc32c*(data: openarray[byte]): uint32 {.inline.} =
      if data.len <= 0:
        crc32c(nil, 0)
      else:
        crc32c(data[0].unsafeAddr, data.len)

    proc crc32c*(data: string): uint32 {.inline.} =
      crc32c(data.cstring, data.len)

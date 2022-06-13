import internal

when allowSimd:
  import crc32c_simd

  when defined(amd64):
    proc crc32c*(src: pointer, len: int): uint32 =
      crc32c_sse42(src, len)

    proc crc32c*(src: string): uint32 {.inline.} =
      crc32c(src.cstring, src.len)

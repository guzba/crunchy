# Scrutiny

![Github Actions](https://github.com/guzba/nimsimd/workflows/Github%20Actions/badge.svg)

`nimble install scrutiny`

[API reference](https://nimdocs.com/guzba/scrutiny)

## About

Scrutiny provides pure Nim implementations of common data integrity checks (cyclic redundancy checks and checksums). These implementations are tuned for performance, including amd64 and arm64 SIMD where possible.

In addition to pleasant and safe Nim typed APIs, Scrutiny also has optional pointer + len APIs. These enable zero-copy data integrity checks.

Function | Scalar | SIMD: | amd64 | arm64
---       | ---   | ---   | ---   | ---:
CRC-32    | ✅   |       |  ✅   | ⛔
CRC-32C   | ⛔   |       |  ✅   | ⛔
Adler-32  | ✅   |       |  ⛔   | ⛔

Scrutiny is a new repo so keep an eye on releases for more functions and SIMD optimization.

## Examples

Runnable examples using Scrutiny can be found in the [examples/](https://github.com/guzba/scrutiny/blob/master/examples) folder.

Here is a basic example, simply computing the CRC-32 of a string:

```nim
import scrutiny

let data = "The quick brown fox jumps over the lazy dog"
echo crc32(data)
```

Now, lets say you want to compute the CRC-32 of a file. Many approaches are possible, but lets look at these two.

First, the easy way. Just read the file into memory and compute:
```nim
import scrutiny

let data = readFile("tests/data/zlib_rfc.html")
echo crc32(data)
```

Alternatively, to avoid copying the file, memory-map the file and compute instead:
```nim
import scrutiny, std/memfiles

var memFile = memfiles.open("tests/data/zlib_rfc.html")
echo crc32(memFile.mem, memFile.size)
memFile.close()
```

Memory-mapping the file is great if the file is very large or you want to avoid copying a large file's contents. This uses Scrutiny's pointer + len API.

## Testing

`nimble test`

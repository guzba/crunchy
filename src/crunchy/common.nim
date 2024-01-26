import std/strutils

type CrunchyError* = object of CatchableError

proc toHex*(a: openarray[uint8]): string =
  result = newStringOfCap(a.len * 2)
  for i in 0 ..< a.len:
    result.add toHex(a[i], 2)
  for c in result.mitems:
    c = toLowerAscii(c)

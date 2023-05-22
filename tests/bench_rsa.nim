import benchy
import std/strutils
import crunchy/rsa

let keyText = readFile("tests/data/2048.txt")

timeIt "CRT rsa 2048", 1:
  let pk2048 = rsa.decodePrivateKey(keyText)
  discard pk2048.sign("test message\n").toHex().toUpperAscii()

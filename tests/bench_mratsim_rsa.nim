import benchy

import crunchy/mratsim, std/strutils


import crunchy/rsa

let keyText = readFile("tests/data/2048.txt")

timeIt "guzba rsa 2048", 1:
  let pk2048 = rsa.decodePrivateKey(keyText)
  discard pk2048.sign("test message\n").toHex().toUpperAscii()

timeIt "constantine rsa 2048", 1:
  let pk2048 = mratsim.decodePrivateKey(keyText)
  discard pk2048.signSha256Base64("test message\n")

import crunchy/sha256

const sha256Tests = [
  (
    "",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ),
  (
    "abc",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  ),
  (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
  ),
  (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
  ),
  (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
  ),
  (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
  ),
  (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "cdbf867f784a69c7d2e252baa9075c3762843b1beb52c04d4be39e7777d95717",
  ),
  (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu123456789012345678901234567890",
    "a0fefcd69c597d2b9912fd7e3ca2a82e27c92684896a1d501d3b585ddf78c236",
  )
]

for (a, b) in sha256Tests:
  doAssert sha256(a).toHex() == b

const hmacSha256Tests = [
  (
    "abc",
    "def",
    "20ebc0f09344470134f35040f63ea98b1d8e414212949ee5c500429d15eab081"
  ),
  (
    "asdf3q5q23rfasf3a",
    "dfasdfasfd3qr3fqfaefa3fa3rfasadfasfdasdfasdfasdfasfdasd",
    "a1629e21b02776e7eacef6f615165d08894963a12dfbd304a47e7a8aff0a2dc5"
  ),
  (
    "awjieops;oi4etaawjieops;oi4etaawjieops;oi4etaawjieops;oi4etaawjieops;oi4",
    "p890y6t3q9ah2pqh8t6q3pth8qa3whu",
    "a1b7d6b597ae74f950dad4eb4dc1700420281b186abfaa321f728f38d675b099"
  )
]

for (a, b, c) in hmacSha256Tests:
  doAssert hmacSha256(a, b).toHex() == c

const pbkdf2Tests = [
  (
    "password",
    "salt",
    30000,
    "76639c203f99c73c1151d8dee2ca9d5055c932a2b0a4708c10dc21b60c921ca7"
  )
]

for (a, b, c, d) in pbkdf2Tests:
  doAssert pbkdf2(a, b, c).toHex() == d

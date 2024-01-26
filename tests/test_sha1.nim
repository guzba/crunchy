import crunchy/common, crunchy/sha1

const sha1Tests = [
  (
    "",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  ),
  (
    "The quick brown fox jumps over the lazy dog",
    "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
  ),
  (
    "The quick brown fox jumps over the lazy cog",
    "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
  ),
  (
    "abc",
    "a9993e364706816aba3e25717850c26c9cd0d89d",
  ),
  (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "c1c8bbdc22796e28c0e15163d20899b65621d65a",
  ),
  (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "c2db330f6083854c99d4b5bfb6e8f29f201be699",
  ),
  (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "0098ba824b5c16427bd7a1122a5a442a25ec644d",
  ),
  (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "a49b2446a02c645bf419f995b67091253a04a259",
  ),
  (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "0c35f042b13ba2aab1f6f01c63805409017f411a",
  ),
  (
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu123456789012345678901234567890",
    "fa90e54f7610399ed52147631e82f62ce6d0ab83",
  )
]

for (a, b) in sha1Tests:
  doAssert sha1(a).toHex() == b

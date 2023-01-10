const allowSimd* =
  when (NimMajor, NimMinor, NimPatch) >= (1, 2, 0):
    not defined(crunchyNoSimd) and not defined(tcc)
  else:
    false

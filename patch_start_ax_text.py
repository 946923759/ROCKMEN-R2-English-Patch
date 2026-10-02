#!/usr/bin/env python3
"""Patch ROCKMEN R2 start.ax dialogue layout.  Usage: python patch_start_ax.py start.ax [out.ax]"""
import sys, struct

# ---- tweak these ----
ADVANCE   = 16    # px per glyph            (orig 20)
CHAR_CAP  = 100   # glyphs per text box     (orig 65; >100 is pointless, lines only load 100 chunks)
WRAP_X    = 750   # wrap when pen x > this  (orig 750)
LINE_H    = 35    # px between lines        (orig 35)
# ---------------------

# offset of the 16-bit value inside each token, original value
SITES = [
    (0x3C84E, 65,  CHAR_CAP, "repeat 65 (char cap)"),
    (0x3CA02, 20,  ADVANCE,  "var_423 += 20 (glyph set 1-99)"),
    (0x3CAF0, 20,  ADVANCE,  "var_423 += 20 (glyph set 101-200)"),
    (0x3CBDE, 20,  ADVANCE,  "var_423 += 20 (glyph set 201-849)"),
    (0x3CBEC, 750, WRAP_X,   "if var_423 > 750 (auto wrap)"),
    (0x3CC08, 35,  LINE_H,   "var_424 += 35 (auto wrap)"),
    (0x3CC46, 35,  LINE_H,   "var_424 += 35 (code 1002 newline)"),
]

src = sys.argv[1]; dst = sys.argv[2] if len(sys.argv) > 2 else src.replace('.ax', '_patched.ax')
d = bytearray(open(src, 'rb').read())
assert d[:4] == b'HSP3'
for off, old, new, what in SITES:
    cur = struct.unpack_from('<H', d, off)[0]
    if cur not in (old, new):
        sys.exit(f"0x{off:X}: expected {old}, found {cur} - wrong file version?")
    assert 0 <= new <= 0xFFFF
    struct.pack_into('<H', d, off, new)
    print(f"0x{off:06X}  {old:>4} -> {new:<4} {what}")
open(dst, 'wb').write(d)
print("wrote", dst)

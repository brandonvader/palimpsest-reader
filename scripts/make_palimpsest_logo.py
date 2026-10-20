"""Generate src/images/Logo120.h: the Palimpsest boot/sleep mark (120x120, 1bpp, MSB first, 1 = white).

A page outline holding faint, scraped-back lines of old text with bold new text written across them.
Usage: python scripts/make_palimpsest_logo.py [preview.png]
"""
import os
import sys

from PIL import Image, ImageDraw

SIZE = 120
SS = 8  # supersample factor before thresholding


def draw_mark():
    s = SIZE * SS
    img = Image.new("L", (s, s), 255)
    d = ImageDraw.Draw(img)

    def r(v):
        return int(v * SS)

    # Page outline with a folded top-right corner.
    x0, y0, x1, y1, fold = 18, 8, 102, 112, 22
    page = [(x0, y0), (x1 - fold, y0), (x1, y0 + fold), (x1, y1), (x0, y1)]
    d.line([(r(x), r(y)) for x, y in page + [page[0]]], fill=0, width=r(5), joint="curve")
    d.line([(r(x1 - fold), r(y0)), (r(x1 - fold), r(y0 + fold)), (r(x1), r(y0 + fold))], fill=0, width=r(4))

    # Ghost layer: scraped-back old text, drawn as sparse dashes at a slight slant.
    for row, y in enumerate(range(36, 100, 12)):
        xa, xb = 30, 90 - (row % 3) * 8
        x = xa
        while x < xb:
            seg = 3 + (x * 7 + row * 5) % 4
            d.line([(r(x), r(y + 3)), (r(min(x + seg, xb)), r(y + 2))], fill=0, width=r(2))
            x += seg + 3

    # New layer: bold text bars written across, offset from the ghost rows.
    for y, xa, xb in [(44, 28, 84), (62, 34, 92), (80, 28, 70)]:
        d.rounded_rectangle([r(xa), r(y), r(xb), r(y + 7)], radius=r(3), fill=0)

    return img.resize((SIZE, SIZE), Image.LANCZOS)


def to_header(img):
    # The framebuffer is stored rotated: pre-rotate 90 deg CCW so the mark is upright on screen.
    px = img.rotate(90).convert("L").load()
    out = []
    for y in range(SIZE):
        for x in range(0, SIZE, 8):
            b = 0
            for k in range(8):
                if px[x + k, y] >= 128:
                    b |= 1 << (7 - k)
            out.append(b)
    lines = ["#pragma once", "#include <cstdint>", "", f"// Image dimensions: {SIZE}x{SIZE}",
             "static const uint8_t Logo120[] = {"]
    for i in range(0, len(out), 19):
        lines.append("    " + ", ".join(f"0x{v:02x}" for v in out[i:i + 19]) + ",")
    lines[-1] = lines[-1].rstrip(",")
    lines.append("};")
    return "\n".join(lines) + "\n"


def main():
    img = draw_mark()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "src", "images", "Logo120.h"), "w") as f:
        f.write(to_header(img))
    img.point(lambda v: 255 if v >= 128 else 0).convert("1").save(
        os.path.join(root, "src", "images", "Logo120.png"))
    if len(sys.argv) > 1:
        img.point(lambda v: 255 if v >= 128 else 0).resize((360, 360), Image.NEAREST).save(sys.argv[1])


if __name__ == "__main__":
    main()

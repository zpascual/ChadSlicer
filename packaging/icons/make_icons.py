#!/usr/bin/env python3
"""Generate the ChadSlicer application icons from the vector design.

Usage: packaging/icons/make_icons.py <render_svg binary> <resources/icons dir>

Writes the SVG sources and all the raster icons used by the application (PNG sizes,
grayscale and transparent variants, macOS .icns via iconutil, Windows .ico).
The file names stay the ones the application looks for (PrusaSlicer*).
"""
import math, os, shutil, struct, subprocess, sys, tempfile, zlib

BG = '#16181d'
DEFS = '''<linearGradient id="amber" x1="0" y1="105" x2="0" y2="835" gradientUnits="userSpaceOnUse">
<stop offset="0" stop-color="#ffb347"/><stop offset="1" stop-color="#ff6a00"/></linearGradient>
<linearGradient id="lcd" x1="232" y1="0" x2="792" y2="0" gradientUnits="userSpaceOnUse">
<stop offset="0" stop-color="#21d4fd"/><stop offset="1" stop-color="#4f7cff"/></linearGradient>'''

CX, CY, R, STROKE = 512, 470, 290, 150


def design(background=True, small=False):
    """The C cut into print layers above a glowing LCD bar."""
    end = lambda a: (CX + R * math.cos(math.radians(a)), CY + R * math.sin(math.radians(a)))
    (sx, sy), (ex, ey) = end(-40), end(40)
    # Corner of the inner edge of the C ends, the layer gaps are aligned to it, so no slivers remain.
    inner_corner = CY - (R - STROKE / 2) * math.sin(math.radians(40))
    period = 2 * (CY - inner_corner) / (2.5 if small else 5)
    gap = 30 if small else 14
    gaps = []
    k = -20
    while True:
        y = inner_corner + k * period
        k += 1
        if y < 90:
            continue
        if y > 850:
            break
        gaps.append(y)
    gap_color = BG if background else '#000000'
    parts = []
    if background:
        parts.append(f'<rect x="40" y="40" width="944" height="944" rx="210" ry="210" fill="{BG}"/>')
    parts.append(f'<path d="M {sx:.1f} {sy:.1f} A {R} {R} 0 1 0 {ex:.1f} {ey:.1f}" fill="none" '
                 f'stroke="url(#amber)" stroke-width="{STROKE}" stroke-linecap="butt"/>')
    if background:
        parts += [f'<rect x="120" y="{y - gap / 2:.1f}" width="784" height="{gap}" fill="{gap_color}"/>' for y in gaps]
    parts.append(f'<rect x="232" y="862" width="560" height="{56 if small else 36}" rx="18" ry="18" fill="url(#lcd)"/>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">'
            f'<defs>{DEFS}</defs>' + ''.join(parts) + '</svg>\n'), gaps, gap


def read_png(path):
    data = open(path, 'rb').read()
    pos, idat = 8, b''
    while pos < len(data):
        ln, = struct.unpack('>I', data[pos:pos + 4]); typ = data[pos + 4:pos + 8]; body = data[pos + 8:pos + 8 + ln]
        pos += 12 + ln
        if typ == b'IHDR':
            w, h = struct.unpack('>II', body[:8])
        elif typ == b'IDAT':
            idat += body
    raw = zlib.decompress(idat)
    return w, h, [bytearray(raw[y * (4 * w + 1) + 1:(y + 1) * (4 * w + 1)]) for y in range(h)]


def write_png(path, w, h, rows):
    raw = b''.join(b'\x00' + bytes(r) for r in rows)
    chunk = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    open(path, 'wb').write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) +
                           chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def main():
    render, icons = sys.argv[1], sys.argv[2]
    here = os.path.dirname(os.path.abspath(__file__))
    full, _, _ = design()
    small, _, _ = design(small=True)
    open(os.path.join(here, 'chadslicer.svg'), 'w').write(full)
    open(os.path.join(here, 'chadslicer_small.svg'), 'w').write(small)

    # Transparent variant (no tile): C with the layer gaps punched out, used on the wizard background.
    tmp = tempfile.mkdtemp()
    def rendered(svg_text, size, name):
        svg = os.path.join(tmp, name + '.svg')
        png = os.path.join(tmp, f'{name}_{size}.png')
        open(svg, 'w').write(svg_text)
        subprocess.run([render, svg, png, str(size)], check=True)
        return png

    def icon_png(size):
        return rendered(small if size <= 32 else full, size, 'small' if size <= 32 else 'full')

    # The application SVG (vector, rendered by the application itself).
    shutil.copy(os.path.join(here, 'chadslicer.svg'), os.path.join(icons, 'PrusaSlicer.svg'))
    for size, name in [(32, 'PrusaSlicer_32px.png'), (128, 'PrusaSlicer_128px.png'), (192, 'PrusaSlicer_192px.png'),
                       (154, 'PrusaSlicer.png'), (128, 'PrusaSlicer-mac_128px.png')]:
        shutil.copy(icon_png(size), os.path.join(icons, name))

    # Transparent: render the full design, then make the dark tile transparent.
    w, h, rows = read_png(icon_png(192))
    bg = tuple(int(BG[i:i + 2], 16) for i in (1, 3, 5))
    for row in rows:
        for x in range(w):
            r, g, b, a = row[4 * x:4 * x + 4]
            if a and max(abs(r - bg[0]), abs(g - bg[1]), abs(b - bg[2])) < 6:
                row[4 * x + 3] = 0
    write_png(os.path.join(icons, 'PrusaSlicer_192px_transparent.png'), w, h, rows)

    # Grayscale for message dialogs.
    w, h, rows = read_png(icon_png(192))
    for row in rows:
        for x in range(w):
            r, g, b, a = row[4 * x:4 * x + 4]
            v = int(0.299 * r + 0.587 * g + 0.114 * b)
            row[4 * x:4 * x + 3] = bytes((v, v, v))
    write_png(os.path.join(icons, 'PrusaSlicer_192px_grayscale.png'), w, h, rows)

    # macOS icns.
    iconset = os.path.join(tmp, 'PrusaSlicer.iconset')
    os.makedirs(iconset)
    for base in (16, 32, 128, 256, 512):
        shutil.copy(icon_png(base), os.path.join(iconset, f'icon_{base}x{base}.png'))
        shutil.copy(icon_png(2 * base), os.path.join(iconset, f'icon_{base}x{base}@2x.png'))
    subprocess.run(['iconutil', '-c', 'icns', iconset, '-o', os.path.join(icons, 'PrusaSlicer.icns')], check=True)

    # Windows ico with PNG compressed entries (supported since Windows Vista).
    sizes = [16, 32, 48, 64, 128, 256]
    blobs = [open(icon_png(s), 'rb').read() for s in sizes]
    header = struct.pack('<HHH', 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries = b''
    for s, blob in zip(sizes, blobs):
        entries += struct.pack('<BBBBHHII', s % 256, s % 256, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    open(os.path.join(icons, 'PrusaSlicer.ico'), 'wb').write(header + entries + b''.join(blobs))
    shutil.rmtree(tmp)
    print('icons written to', icons)


if __name__ == '__main__':
    main()
